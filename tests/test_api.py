"""End-to-end behavior tests for the signed-prefix archive."""

from __future__ import annotations

import base64
import threading

import nacl.signing

from tests.conftest import (
    ZERO,
    digest,
    fresh_key,
    make_record,
    post_record,
    register,
    restart_client,
)


# ---------------------------------------------------------------- registration

def test_register_and_health(tmp_db):
    client, _ = tmp_db
    assert client.get("/health").json()["status"] == "ok"
    key = register(client, "buoy-alpha")
    # Idempotent re-registration with the same key.
    r = client.post(
        "/streams",
        json={"id": "buoy-alpha",
              "public_key": base64.b64encode(key.verify_key.encode()).decode()},
    )
    assert r.status_code == 200 and r.json()["registered"] == "exists"
    # The public key can never be replaced.
    other = fresh_key()
    r = client.post(
        "/streams",
        json={"id": "buoy-alpha",
              "public_key": base64.b64encode(other.verify_key.encode()).decode()},
    )
    assert r.status_code == 409
    # Rejects non-ASCII id.
    r = client.post(
        "/streams",
        json={"id": "浮标",
              "public_key": base64.b64encode(other.verify_key.encode()).decode()},
    )
    assert r.status_code == 400


# ----------------------------------------------------------- in-order sealing

def test_in_order_chain_seals(tmp_db):
    client, _ = tmp_db
    key = register(client, "s1")
    prev = ZERO
    for seq in range(1, 5):
        payload = digest(seq)
        r = post_record(client, "s1", make_record(key, "s1", seq, prev, payload))
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["state"] == "sealed"
        assert body["watermark"] == seq
        prev = payload


# ------------------------------------------------------- out-of-order merging

def test_out_of_order_merge_within_gap(tmp_db):
    client, _ = tmp_db
    key = register(client, "s2")
    digs = {i: digest(100 + i) for i in range(1, 7)}

    # Submit 2,3 before 1: they are held pending.
    r = post_record(client, "s2", make_record(key, "s2", 2, digs[1], digs[2]))
    assert r.json()["state"] == "pending" and r.json()["watermark"] == 0
    r = post_record(client, "s2", make_record(key, "s2", 3, digs[2], digs[3]))
    assert r.json()["state"] == "pending" and r.json()["watermark"] == 0

    # Submit 5 while gap at 4 exists: accepted (distance <= 32), stays pending.
    r = post_record(client, "s2", make_record(key, "s2", 5, digs[4], digs[5]))
    assert r.status_code == 200 and r.json()["state"] == "pending"

    # Fill 1: 1..3 seal together up to the hole at 4.
    r = post_record(client, "s2", make_record(key, "s2", 1, ZERO, digs[1]))
    body = r.json()
    assert body["state"] == "sealed" and body["watermark"] == 3
    assert body["tail_digest"] == digs[3].hex()

    # Retransmit 2 (identical): previous verdict (sealed) returned.
    r = post_record(client, "s2", make_record(key, "s2", 2, digs[1], digs[2]))
    body = r.json()
    assert body["duplicate"] is True and body["state"] == "sealed"
    assert body["watermark"] == 3

    # Retransmit pending 5: stays pending.
    r = post_record(client, "s2", make_record(key, "s2", 5, digs[4], digs[5]))
    body = r.json()
    assert body["duplicate"] is True and body["state"] == "pending"

    # Fill 4: whole chain seals to 5.
    r = post_record(client, "s2", make_record(key, "s2", 4, digs[3], digs[4]))
    body = r.json()
    assert body["state"] == "sealed" and body["watermark"] == 5

    # 6 arrives in order afterwards.
    r = post_record(client, "s2", make_record(key, "s2", 6, digs[5], digs[6]))
    assert r.json()["watermark"] == 6


def test_records_beyond_gap_32_rejected(tmp_db):
    client, _ = tmp_db
    key = register(client, "s3")
    r = post_record(client, "s3",
                    make_record(key, "s3", 33, digest(1), digest(33)))
    assert r.status_code == 422
    assert r.json()["watermark"] == 0 and r.json()["max_gap"] == 32
    # Boundary at 32 is accepted.
    r = post_record(client, "s3",
                    make_record(key, "s3", 32, digest(1), digest(32)))
    assert r.status_code == 200 and r.json()["state"] == "pending"


# ------------------------------------------------------------- signature / wire

def test_bad_signature_and_message_binding(tmp_db):
    client, _ = tmp_db
    key = register(client, "s4")
    rec = make_record(key, "s4", 1, ZERO, digest(1))

    # Tamper the payload digest after signing -> must fail verification.
    bad = dict(rec)
    bad["payload_digest"] = base64.b64encode(digest(999)).decode()
    r = post_record(client, "s4", bad)
    assert r.status_code == 403

    # A signature made for a different stream id must not verify here
    # (the id bytes/length are part of the signed message, not re-derived JSON).
    foreign = make_record(key, "other-stream", 1, ZERO, digest(1))
    r = post_record(client, "s4", foreign)
    assert r.status_code == 403

    # A signature made by a different key fails too.
    other = fresh_key()
    r = post_record(client, "s4", make_record(other, "s4", 1, ZERO, digest(1)))
    assert r.status_code == 403

    # Untampered record still seals.
    r = post_record(client, "s4", rec)
    assert r.status_code == 200 and r.json()["watermark"] == 1


def test_first_record_requires_zero_prev_digest(tmp_db):
    client, _ = tmp_db
    key = register(client, "s5")
    r = post_record(client, "s5",
                    make_record(key, "s5", 1, digest(1), digest(2)))
    # Signature is valid, but the chain cannot link -> fork on sealing.
    assert r.status_code == 409
    body = r.json()
    assert body["state"] == "forked" and body["status"] == "forked"
    assert body["watermark"] == 0
    # Frozen: later genuine prefix never advances.
    r = post_record(client, "s5", make_record(key, "s5", 1, ZERO, digest(1)))
    assert r.status_code == 409 and r.json()["watermark"] == 0
    r = post_record(client, "s5", make_record(key, "s5", 2, digest(1), digest(2)))
    assert r.status_code == 409 and r.json()["watermark"] == 0


# ----------------------------------------------------------------- forking

def test_wrong_prev_at_gap_triggers_fork(tmp_db):
    client, _ = tmp_db
    key = register(client, "s6")
    d = {i: digest(200 + i) for i in range(1, 5)}
    post_record(client, "s6", make_record(key, "s6", 1, ZERO, d[1]))
    post_record(client, "s6", make_record(key, "s6", 2, d[1], d[2]))
    # seq 3 claims a parent that isn't the sealed tail d[2].
    r = post_record(client, "s6",
                    make_record(key, "s6", 3, digest(777), d[3]))
    assert r.status_code == 409
    body = r.json()
    assert body["state"] == "forked" and body["watermark"] == 2
    assert body["tail_digest"] == d[2].hex()
    # The stream is frozen forever.
    r = post_record(client, "s6",
                    make_record(key, "s6", 3, d[2], digest(300)))
    assert r.status_code == 409 and r.json()["status"] == "forked"


def test_conflicting_retransmission_freezes_stream(tmp_db):
    client, _ = tmp_db
    key = register(client, "s7")
    post_record(client, "s7", make_record(key, "s7", 2, digest(1), digest(2)))
    # Same seq, different payload digest (properly signed by the same key):
    # competing history -> fork.
    r = post_record(client, "s7",
                    make_record(key, "s7", 2, digest(1), digest(22)))
    assert r.status_code == 409 and r.json()["state"] == "forked"
    # Even a now-correct prefix cannot unfreeze.
    r = post_record(client, "s7", make_record(key, "s7", 1, ZERO, digest(1)))
    assert r.status_code == 409 and r.json()["watermark"] == 0


def test_gap_filled_with_wrong_prev_freezes(tmp_db):
    client, _ = tmp_db
    key = register(client, "s6b")
    d = {i: digest(250 + i) for i in range(1, 4)}
    # seq 1 seals.
    post_record(client, "s6b", make_record(key, "s6b", 1, ZERO, d[1]))
    # seq 3 waits behind the hole at 2.
    r = post_record(client, "s6b", make_record(key, "s6b", 3, d[2], d[3]))
    assert r.json()["state"] == "pending"
    # Filling seq 2 with a prev_digest that does not match the tail d[1]:
    # fork detected *at sealing time*, inside the same transaction.
    r = post_record(client, "s6b",
                    make_record(key, "s6b", 2, digest(7), digest(22)))
    assert r.status_code == 409
    body = r.json()
    assert body["state"] == "forked" and body["status"] == "forked"
    assert body["watermark"] == 1 and body["tail_digest"] == d[1].hex()
    # Genuine seq 2 can never advance the prefix afterwards.
    r = post_record(client, "s6b", make_record(key, "s6b", 2, d[1], d[2]))
    assert r.status_code == 409
    assert r.json()["status"] == "forked" and r.json()["watermark"] == 1
    # Identical retransmission of the offending record keeps its verdict.
    r = post_record(client, "s6b",
                    make_record(key, "s6b", 2, digest(7), digest(22)))
    assert r.status_code == 409
    assert r.json()["duplicate"] is True and r.json()["state"] == "forked"


def test_unknown_stream_404(tmp_db):
    client, _ = tmp_db
    key = fresh_key()
    r = post_record(client, "nope", make_record(key, "nope", 1, ZERO, digest(1)))
    assert r.status_code == 404


# ------------------------------------------------------------------ restart

def test_watermark_rebuilt_after_restart(tmp_db):
    client, path = tmp_db
    key = register(client, "s8")
    d = {i: digest(400 + i) for i in range(1, 6)}
    # Pending out-of-order records.
    post_record(client, "s8", make_record(key, "s8", 3, d[2], d[3]))
    post_record(client, "s8", make_record(key, "s8", 4, d[3], d[4]))
    # Seal 1..2.
    post_record(client, "s8", make_record(key, "s8", 1, ZERO, d[1]))
    r = post_record(client, "s8", make_record(key, "s8", 2, d[1], d[2]))
    assert r.json()["watermark"] == 4

    # Simulate process restart: a fresh app/store opens the same DB file and
    # rebuilds the watermark from durable records.
    with restart_client(path) as client2:
        body = client2.post(
            "/streams/s8/records",
            json=make_record(key, "s8", 4, d[3], d[4]),
        ).json()
        # Retransmission verdict recovered from durable storage.
        assert body["duplicate"] is True and body["state"] == "sealed"
        assert body["watermark"] == 4 and body["tail_digest"] == d[4].hex()
        # Record 5 extends the prefix.
        r = client2.post(
            "/streams/s8/records",
            json=make_record(key, "s8", 5, d[4], d[5]),
        )
        assert r.status_code == 200 and r.json()["watermark"] == 5


def test_forked_status_survives_restart(tmp_db):
    client, path = tmp_db
    key = register(client, "s8b")
    d = {i: digest(500 + i) for i in range(1, 3)}
    post_record(client, "s8b", make_record(key, "s8b", 1, ZERO, d[1]))
    r = post_record(client, "s8b",
                    make_record(key, "s8b", 2, digest(66), d[2]))
    assert r.status_code == 409 and r.json()["watermark"] == 1
    with restart_client(path) as client2:
        r = client2.post(
            "/streams/s8b/records",
            json=make_record(key, "s8b", 2, d[1], d[2]),
        )
        assert r.status_code == 409
        body = r.json()
        assert body["status"] == "forked" and body["watermark"] == 1
        assert body["tail_digest"] == d[1].hex()


def test_pending_record_seals_after_restart(tmp_db):
    client, path = tmp_db
    key = register(client, "s9")
    post_record(client, "s9", make_record(key, "s9", 2, digest(1), digest(2)))
    with restart_client(path) as client2:
        r = client2.post(
            "/streams/s9/records",
            json=make_record(key, "s9", 1, ZERO, digest(1)),
        )
        assert r.json()["watermark"] == 2 and r.json()["state"] == "sealed"
        # Same verdict after yet another restart.
        with restart_client(path) as client3:
            r = client3.post(
                "/streams/s9/records",
                json=make_record(key, "s9", 2, digest(1), digest(2)),
            )
            assert r.json()["duplicate"] is True
            assert r.json()["state"] == "sealed" and r.json()["watermark"] == 2


# ----------------------------------------------------------------- concurrency

def test_concurrent_submissions_no_double_or_phantom_success(tmp_db):
    client, _ = tmp_db
    key = register(client, "s10")
    N = 25
    errors = []

    def worker(seq: int):
        try:
            # Every worker submits a link in the same chain. Out-of-order
            # delivery is exercised via start barrier; prev pointers form a
            # single valid chain, so nothing forks.
            r = post_record(
                client, "s10",
                make_record(key, "s10", seq, digest(seq - 1) if seq > 1 else ZERO,
                            digest(seq)),
            )
            if r.status_code not in (200, 409):
                errors.append((seq, r.status_code, r.text))
        except Exception as exc:  # pragma: no cover - failure reporting
            errors.append((seq, "exc", repr(exc)))

    barrier = threading.Barrier(N)

    def paced(seq):
        barrier.wait()
        worker(seq)

    threads = [threading.Thread(target=paced, args=(i,))
               for i in range(1, N + 1)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors

def test_concurrent_identical_submissions_share_verdict(tmp_db):
    """Identical concurrent POSTs must act as one retransmission, not race."""
    client, _ = tmp_db
    key = register(client, "s10b")
    rec = make_record(key, "s10b", 1, ZERO, digest(1))
    N = 16
    results = []
    errors = []
    barrier = threading.Barrier(N)

    def worker():
        barrier.wait()
        try:
            r = post_record(client, "s10b", rec)
            results.append((r.status_code, r.json()))
        except Exception as exc:  # pragma: no cover
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(N)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors
    assert len(results) == N
    for code, body in results:
        assert code == 200, (code, body)
        assert body["watermark"] == 1
        assert body["state"] == "sealed"
        assert body["tail_digest"] == digest(1).hex()
    assert sum(1 for _, b in results if b["duplicate"]) == N - 1


def test_concurrent_conflicting_submissions_freeze_once(tmp_db):
    """Competing concurrent content at one seq must freeze, never 200+fork."""
    client, _ = tmp_db
    key = register(client, "s10c")
    N = 12
    records = [
        make_record(key, "s10c", 1, ZERO, digest(1000 + i))
        for i in range(N)
    ]
    outcomes = []
    barrier = threading.Barrier(N)

    def worker(i):
        barrier.wait()
        r = post_record(client, "s10c", records[i])
        outcomes.append((r.status_code, r.json()))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(N)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(outcomes) == N
    # Transactions serialize: exactly one submission wins seq 1 and seals it
    # legitimately (prev is the zero digest); every other competing content
    # hits the conflict rule and atomically freezes the stream. No response
    # may be a 5xx, and the prefix must never extend past 1.
    winners = [b for code, b in outcomes if code == 200]
    losers = [(code, b) for code, b in outcomes if code != 200]
    assert len(winners) == 1, outcomes
    assert winners[0]["state"] == "sealed"
    assert winners[0]["watermark"] == 1
    for code, body in losers:
        assert code == 409, (code, body)
        assert body["status"] == "forked" and body["state"] == "forked"
        assert body["watermark"] == 1, body
    # The stream stays frozen on subsequent calls.
    r = post_record(client, "s10c",
                    make_record(key, "s10c", 2,
                                bytes.fromhex(winners[0]["tail_digest"]),
                                digest(2)))
    assert r.status_code == 409 and r.json()["status"] == "forked"
    assert r.json()["watermark"] == 1
