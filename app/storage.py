"""SQLite-backed storage for buoy streams.

All state transitions for a record submission happen in one ``BEGIN
IMMEDIATE`` transaction guarded by a process-wide lock, so concurrent API
workers can never double-seal or observe a momentarily inconsistent
watermark.

Prefix state (``watermark`` / ``tail_digest`` / ``status``) is persisted in
the same transaction as the records that advance it. On startup it is
*rebuilt* from the committed records rather than trusted, so the water line
after a restart is identical to the one implied by durable records.
"""

from __future__ import annotations

import sqlite3
import threading
from dataclasses import dataclass

from .message import ZERO_DIGEST

SCHEMA = """
CREATE TABLE IF NOT EXISTS streams (
    id           TEXT PRIMARY KEY,
    public_key   BLOB NOT NULL,
    status       TEXT NOT NULL DEFAULT 'active',
    watermark    INTEGER NOT NULL DEFAULT 0,
    tail_digest  BLOB NOT NULL DEFAULT (x'0000000000000000000000000000000000000000000000000000000000000000')
);

CREATE TABLE IF NOT EXISTS records (
    stream_id      TEXT NOT NULL,
    seq            INTEGER NOT NULL,
    prev_digest    BLOB NOT NULL,
    payload_digest BLOB NOT NULL,
    signature      BLOB NOT NULL,
    state          TEXT NOT NULL DEFAULT 'pending',
    PRIMARY KEY (stream_id, seq),
    FOREIGN KEY (stream_id) REFERENCES streams(id)
);

CREATE INDEX IF NOT EXISTS records_pending
    ON records(stream_id, seq) WHERE state = 'pending';
"""

MAX_GAP = 32
STATUS_ACTIVE = "active"
STATUS_FORKED = "forked"


@dataclass(frozen=True)
class Verdict:
    stream_id: str
    seq: int
    state: str  # "sealed" | "pending" | "forked"
    status: str  # "active" | "forked"
    watermark: int
    tail_digest: bytes
    duplicate: bool


class Store:
    def __init__(self, path: str):
        self._lock = threading.Lock()
        # Autocommit mode: every transaction is opened explicitly with
        # BEGIN IMMEDIATE. timeout is the busy timeout used by SQLite if a
        # second OS process ever shares this database file.
        self._conn = sqlite3.connect(
            path, timeout=10, isolation_level=None, check_same_thread=False
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.executescript(SCHEMA)
        self.rebuild()

    # -- registration -----------------------------------------------------

    def create_stream(self, stream_id: str, public_key: bytes) -> str:
        """Register a stream. The key can never be replaced afterwards."""
        with self._lock:
            conn = self._conn
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    "SELECT public_key FROM streams WHERE id = ?",
                    (stream_id,),
                ).fetchone()
                if row is not None:
                    if bytes(row["public_key"]) != public_key:
                        raise KeyConflict(stream_id)
                    conn.commit()
                    return "exists"
                conn.execute(
                    "INSERT INTO streams (id, public_key) VALUES (?, ?)",
                    (stream_id, public_key),
                )
                conn.commit()
                return "created"
            except Exception:
                conn.rollback()
                raise

    def get_stream(self, stream_id: str) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM streams WHERE id = ?", (stream_id,)
            ).fetchone()

    # -- record submission ------------------------------------------------

    def submit(
        self,
        stream_id: str,
        seq: int,
        prev_digest: bytes,
        payload_digest: bytes,
        signature: bytes,
        signature_valid: bool,
    ) -> Verdict:
        with self._lock:
            conn = self._conn
            conn.execute("BEGIN IMMEDIATE")
            try:
                stream = conn.execute(
                    "SELECT * FROM streams WHERE id = ?", (stream_id,)
                ).fetchone()
                if stream is None:
                    raise UnknownStream(stream_id)

                existing = conn.execute(
                    "SELECT * FROM records WHERE stream_id = ? AND seq = ?",
                    (stream_id, seq),
                ).fetchone()
                if existing is not None:
                    same = (
                        bytes(existing["prev_digest"]) == prev_digest
                        and bytes(existing["payload_digest"]) == payload_digest
                        and bytes(existing["signature"]) == signature
                    )
                    if not same:
                        # Retransmission carrying different content/signature
                        # (valid or not): two competing histories -> freeze
                        # atomically.
                        if stream["status"] != STATUS_FORKED:
                            self._freeze(conn, stream_id)
                        conn.commit()
                        return Verdict(
                            stream_id, seq, STATUS_FORKED, STATUS_FORKED,
                            stream["watermark"],
                            bytes(stream["tail_digest"]), False,
                        )
                    # Identical retransmission -> the prior verdict stands,
                    # including whether this exact record was ever sealed.
                    conn.commit()
                    return Verdict(
                        stream_id, seq, existing["state"], stream["status"],
                        stream["watermark"], bytes(stream["tail_digest"]),
                        True,
                    )

                if stream["status"] == STATUS_FORKED:
                    conn.commit()
                    return Verdict(
                        stream_id, seq, STATUS_FORKED, STATUS_FORKED,
                        stream["watermark"], bytes(stream["tail_digest"]),
                        False,
                    )

                # A brand-new record that does not carry a valid Ed25519
                # signature over the prescribed message is rejected without
                # mutating stream state: it is no competing history.
                if not signature_valid:
                    raise InvalidSignature(stream_id, seq)

                watermark = stream["watermark"]
                if seq > watermark + MAX_GAP:
                    raise GapTooLarge(stream_id, seq, watermark)
                if seq <= watermark:
                    # Sealed prefix without its row violates invariants.
                    raise RuntimeError(
                        f"sealed record seq={seq} missing for {stream_id}"
                    )

                conn.execute(
                    "INSERT INTO records (stream_id, seq, prev_digest, "
                    "payload_digest, signature, state) "
                    "VALUES (?, ?, ?, ?, ?, 'pending')",
                    (stream_id, seq, prev_digest, payload_digest, signature),
                )

                state = "pending"
                watermark, tail, forked = self._seal_prefix(conn, stream_id)
                if forked:
                    state = STATUS_FORKED
                elif watermark >= seq:
                    state = "sealed"
                conn.commit()
                return Verdict(
                    stream_id, seq, state,
                    STATUS_FORKED if forked else STATUS_ACTIVE,
                    watermark, tail, False,
                )
            except Exception:
                conn.rollback()
                raise

    def _seal_prefix(self, conn: sqlite3.Connection, stream_id: str):
        """Append every now-available next record to the sealed prefix.

        Returns ``(watermark, tail_digest, forked)``. If a candidate record's
        prev_digest does not link to the current tail, the stream is frozen
        inside the same transaction and the prefix stops there.
        """
        stream = conn.execute(
            "SELECT watermark, tail_digest FROM streams WHERE id = ?",
            (stream_id,),
        ).fetchone()
        watermark = stream["watermark"]
        tail = bytes(stream["tail_digest"])
        forked = False
        while True:
            candidate = conn.execute(
                "SELECT * FROM records WHERE stream_id = ? AND seq = ?",
                (stream_id, watermark + 1),
            ).fetchone()
            if candidate is None:
                break
            if bytes(candidate["prev_digest"]) != tail:
                forked = True
                break
            conn.execute(
                "UPDATE records SET state = 'sealed' "
                "WHERE stream_id = ? AND seq = ?",
                (stream_id, watermark + 1),
            )
            tail = bytes(candidate["payload_digest"])
            watermark += 1
        if forked:
            self._freeze(conn, stream_id)
        else:
            conn.execute(
                "UPDATE streams SET watermark = ?, tail_digest = ? "
                "WHERE id = ?",
                (watermark, tail, stream_id),
            )
        return watermark, tail, forked

    @staticmethod
    def _freeze(conn: sqlite3.Connection, stream_id: str) -> None:
        """Freeze a stream and mark every un-sealed record as forked.

        Invariant afterwards: ``state = 'pending'`` only exists on active
        streams, so an identical retransmission replays the exact verdict.
        """
        conn.execute("UPDATE streams SET status = 'forked' WHERE id = ?",
                     (stream_id,))
        conn.execute(
            "UPDATE records SET state = 'forked' "
            "WHERE stream_id = ? AND state = 'pending'",
            (stream_id,),
        )

    # -- recovery ---------------------------------------------------------

    def rebuild(self) -> None:
        """Reconstruct watermark/tail from durable committed records.

        Runs at startup. The committed records form a chain (enforced at seal
        time); we replay it and make the streams table match, so a crash at
        any instant still yields the same contiguous prefix after restart.
        """
        with self._lock:
            conn = self._conn
            conn.execute("BEGIN IMMEDIATE")
            try:
                rows = conn.execute(
                    "SELECT id FROM streams ORDER BY id"
                ).fetchall()
                for (stream_id,) in rows:
                    recs = conn.execute(
                        "SELECT seq, prev_digest, payload_digest FROM records "
                        "WHERE stream_id = ? AND state = 'sealed' ORDER BY seq",
                        (stream_id,),
                    ).fetchall()
                    watermark = 0
                    tail = ZERO_DIGEST
                    for rec in recs:
                        assert rec["seq"] == watermark + 1, (
                            f"sealed prefix gap in {stream_id} at "
                            f"seq {rec['seq']}, watermark {watermark}"
                        )
                        assert bytes(rec["prev_digest"]) == tail, (
                            f"sealed chain broken in {stream_id} at "
                            f"seq {rec['seq']}"
                        )
                        tail = bytes(rec["payload_digest"])
                        watermark += 1
                    conn.execute(
                        "UPDATE streams SET watermark = ?, tail_digest = ? "
                        "WHERE id = ?",
                        (watermark, tail, stream_id),
                    )
                conn.commit()
            except Exception:
                conn.rollback()
                raise

    def close(self) -> None:
        with self._lock:
            self._conn.close()


class UnknownStream(Exception):
    pass


class KeyConflict(Exception):
    pass


class InvalidSignature(Exception):
    pass


class GapTooLarge(Exception):
    def __init__(self, stream_id: str, seq: int, watermark: int):
        self.stream_id = stream_id
        self.seq = seq
        self.watermark = watermark
        super().__init__(
            f"seq {seq} is more than {MAX_GAP} beyond watermark {watermark}"
        )
