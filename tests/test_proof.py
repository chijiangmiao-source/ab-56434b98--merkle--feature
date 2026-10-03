"""Behavior tests for the Merkle inclusion-proof read endpoint.

The recomputation helpers below are written directly from the documented
spec (hashlib/struct only, deliberately *not* importing app.merkle) so the
tests independently recompute every leaf, root, and path fold.
"""

from __future__ import annotations

import base64
import hashlib
import math
import struct

from app.merkle import ProofStep, recompute_root
from tests.conftest import (
    ZERO,
    digest,
    make_record,
    post_record,
    register,
    restart_client,
)


# ------------------------------------------------------- independent spec --
# Leaf:  SHA-256( 0x00 || u16be(len(id)) || id || u64be(seq)
#                 || prev[32] || payload[32] || sig[64] )
# Node:  SHA-256( 0x01 || left[32] || right[32] )
# Odd level: trailing node promoted unchanged. Single leaf: root == leaf.

def spec_leaf(sid: str, seq: int, prev: bytes, payload: bytes,
              sig: bytes) -> bytes:
    sid_b = sid.encode("ascii")
    return hashlib.sha256(
        b"\x00"
        + struct.pack(">H", len(sid_b))
        + sid_b
        + struct.pack(">Q", seq)
        + prev
        + payload
        + sig
    ).digest()


def spec_node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def spec_root(leaves: list[bytes]) -> bytes:
    level = list(leaves)
    while len(level) > 1:
        nxt = [spec_node(level[i], level[i + 1])
               for i in range(0, len(level) - 1, 2)]
        if len(level) % 2 == 1:
            nxt.append(level[-1])  # promoted unchanged
        level = nxt
    return level[0]


def spec_fold(leaf: bytes, index: int, count: int,
              path: list[dict]) -> bytes:
    """Fold a JSON proof path (leaf-to-root siblings) back into a root."""
    cur, idx, width, used = leaf, index, count, 0
    while width > 1:
        if width % 2 == 1 and idx == width - 1:
            pass  # promoted level: no sibling
        else:
            step = path[used]
            used += 1
            sib = bytes.fromhex(step["digest"])
            if step["position"] == "left":
                cur = spec_node(sib, cur)
            elif step["position"] == "right":
                cur = spec_node(cur, sib)
            else:  # pragma: no cover - defensive
                raise AssertionError(f"bad position {step['position']!r}")
        idx //= 2
        width = (width + 1) // 2
    assert used == len(path), "path length does not match tree shape"
    return cur


# ------------------------------------------------------------------ helpers

def submit_chain(client, key, sid: str, seqs, payloads, prev: bytes = ZERO):
    """Submit in-order records; return {seq: (prev, payload, signature)}."""
    raw = {}
    for seq in seqs:
        payload = payloads[seq]
        rec = make_record(key, sid, seq, prev, payload)
        r = post_record(client, sid, rec)
        assert r.status_code == 200 and r.json()["state"] == "sealed", r.text
        raw[seq] = (prev, payload, base64.b64decode(rec["signature"]))
        prev = payload
    return raw


def get_proof(client, sid: str, seq: int, watermark):
    return client.get(
        f"/streams/{sid}/records/{seq}/proof",
        params={"watermark": watermark},
    )


def check_proof_body(body, sid, seq, watermark, raw, status="active"):
    """Recompute everything from the response alone and cross-check it."""
    assert body["id"] == sid and body["seq"] == seq
    assert body["state"] == "sealed" and body["status"] == status
    assert body["watermark"] == watermark
    assert body["leaf_index"] == seq - 1
    assert body["leaf_count"] == watermark
    # The record echoed in the response is the submitted one.
    prev, payload, sig = raw[seq]
    rec = body["record"]
    assert base64.b64decode(rec["prev_digest"]) == prev
    assert base64.b64decode(rec["payload_digest"]) == payload
    assert base64.b64decode(rec["signature"]) == sig
    # Leaf recomputed from the response's own fields.
    leaf = spec_leaf(sid, seq, prev, payload, sig)
    assert body["leaf_digest"] == leaf.hex()
    # Path length is bounded by ceil(log2(count)); empty for a lone leaf.
    assert len(body["path"]) <= max(1, math.ceil(math.log2(watermark)))
    # Fold the path (spec implementation) -> must equal the served root.
    assert spec_fold(leaf, seq - 1, watermark, body["path"]).hex() \
        == body["root_digest"]
    # Cross-check the app-side auditor helper agrees.
    steps = [ProofStep(bytes.fromhex(s["digest"]), s["position"])
             for s in body["path"]]
    assert recompute_root(leaf, seq - 1, watermark, steps).hex() \
        == body["root_digest"]
    # Root equals an independently built tree over the known prefix.
    leaves = [spec_leaf(sid, s, *raw[s]) for s in range(1, watermark + 1)]
    assert body["root_digest"] == spec_root(leaves).hex()


# ------------------------------------------------------------------- tests

def test_proof_recomputes_for_every_position_and_watermark(tmp_db):
    client, _ = tmp_db
    key = register(client, "p1")
    n = 8  # exercises even/odd levels and promotions at several widths
    payloads = {i: digest(7000 + i) for i in range(1, n + 1)}
    raw = submit_chain(client, key, "p1", range(1, n + 1), payloads)

    for watermark in range(1, n + 1):
        for seq in range(1, watermark + 1):
            r = get_proof(client, "p1", seq, watermark)
            assert r.status_code == 200, r.text
            body = r.json()
            assert body["current_watermark"] == n
            check_proof_body(body, "p1", seq, watermark, raw)


def test_single_leaf_tree_has_empty_path(tmp_db):
    client, _ = tmp_db
    key = register(client, "p1b")
    raw = submit_chain(client, key, "p1b", [1], {1: digest(7101)})
    r = get_proof(client, "p1b", 1, 1)
    assert r.status_code == 200
    body = r.json()
    assert body["path"] == []
    # Root of a one-leaf tree is the leaf digest itself.
    assert body["root_digest"] == body["leaf_digest"]
    check_proof_body(body, "p1b", 1, 1, raw)


def test_historical_proof_stable_across_appends_retransmits_restart(tmp_db):
    client, path = tmp_db
    key = register(client, "p2")
    payloads = {i: digest(7200 + i) for i in range(1, 8)}
    raw = submit_chain(client, key, "p2", range(1, 5), payloads)

    snap_2_3 = get_proof(client, "p2", 2, 3).json()
    snap_4_4 = get_proof(client, "p2", 4, 4).json()

    # Later records extend the prefix beyond the snapshotted watermarks.
    raw.update(submit_chain(client, key, "p2", range(5, 8), payloads,
                            prev=payloads[4]))
    # Identical retransmissions must not disturb anything either.
    for seq in (2, 3, 6):
        prev, payload, _ = raw[seq]
        r = post_record(client, "p2", make_record(key, "p2", seq, prev,
                                                  payload))
        assert r.json()["duplicate"] is True

    after = get_proof(client, "p2", 2, 3).json()
    assert after["root_digest"] == snap_2_3["root_digest"]
    assert after["path"] == snap_2_3["path"]
    assert after["leaf_digest"] == snap_2_3["leaf_digest"]
    assert after["current_watermark"] == 7
    assert get_proof(client, "p2", 4, 4).json()["root_digest"] \
        == snap_4_4["root_digest"]

    # A restart rebuilds from durable records: same roots, same paths.
    with restart_client(path) as client2:
        again = get_proof(client2, "p2", 2, 3).json()
        assert again["root_digest"] == snap_2_3["root_digest"]
        assert again["path"] == snap_2_3["path"]
        assert get_proof(client2, "p2", 4, 4).json() == \
            get_proof(client, "p2", 4, 4).json()
        # And the recomputation still checks out after the restart.
        check_proof_body(again, "p2", 2, 3, raw)


def test_pending_records_never_enter_proofs(tmp_db):
    client, _ = tmp_db
    key = register(client, "p3")
    d = {i: digest(7300 + i) for i in range(1, 6)}

    # seq 2 pending behind a gap at 1: no proof exists for it at any
    # watermark (current watermark is 0).
    r = post_record(client, "p3", make_record(key, "p3", 2, d[1], d[2]))
    assert r.json()["state"] == "pending"
    assert get_proof(client, "p3", 2, 2).status_code == 422
    assert get_proof(client, "p3", 2, 1).status_code == 422

    # Seal 1..3, then park seq 5 pending behind a gap at 4.
    raw = submit_chain(client, key, "p3", [1], d)
    for seq, prev in ((2, d[1]), (3, d[2])):
        rec = make_record(key, "p3", seq, prev, d[seq])
        assert post_record(client, "p3", rec).json()["state"] == "sealed"
        raw[seq] = (prev, d[seq], base64.b64decode(rec["signature"]))
    r = post_record(client, "p3", make_record(key, "p3", 5, d[4], d[5]))
    assert r.json()["state"] == "pending"

    # The pending record is not provable, whatever the watermark.
    r = get_proof(client, "p3", 5, 3)
    assert r.status_code == 404 and "not sealed" in r.json()["error"]
    assert get_proof(client, "p3", 5, 5).status_code == 422
    # A seq that was never submitted is not provable either.
    assert get_proof(client, "p3", 4, 3).status_code == 404

    # The watermark-3 tree is built from records 1..3 only: the pending
    # record cannot influence the root.
    body = get_proof(client, "p3", 3, 3).json()
    check_proof_body(body, "p3", 3, 3, raw)


def test_frozen_stream_serves_only_the_frozen_prefix(tmp_db):
    client, path = tmp_db
    key = register(client, "p4")
    d = {i: digest(7400 + i) for i in range(1, 6)}
    raw = submit_chain(client, key, "p4", [1, 2, 3], d)
    snapshot = get_proof(client, "p4", 2, 3).json()

    # A pending record sits beyond the gap at 4 when the stream freezes.
    post_record(client, "p4", make_record(key, "p4", 5, d[4], d[5]))
    # Conflicting retransmission of sealed seq 2 freezes the stream at 3.
    r = post_record(client, "p4", make_record(key, "p4", 2, d[1], d[4]))
    assert r.status_code == 409 and r.json()["watermark"] == 3

    # The frozen prefix is still served, bit-for-bit identical.
    body = get_proof(client, "p4", 2, 3).json()
    assert body["status"] == "forked"
    assert body["root_digest"] == snapshot["root_digest"]
    assert body["path"] == snapshot["path"]
    check_proof_body(body, "p4", 2, 3, raw, status="forked")

    # Nothing beyond the frozen watermark: not watermark 4, not the
    # forked-out record 5, not the conflicting content.
    assert get_proof(client, "p4", 2, 4).status_code == 422
    assert get_proof(client, "p4", 5, 3).status_code == 404
    assert get_proof(client, "p4", 4, 3).status_code == 404

    # Same answers after a restart.
    with restart_client(path) as client2:
        body2 = get_proof(client2, "p4", 2, 3).json()
        assert body2["root_digest"] == snapshot["root_digest"]
        assert body2["path"] == snapshot["path"]
        assert get_proof(client2, "p4", 2, 4).status_code == 422


def test_proof_error_boundaries(tmp_db):
    client, _ = tmp_db
    key = register(client, "p5")
    submit_chain(client, key, "p5", [1, 2, 3],
                 {i: digest(7500 + i) for i in range(1, 4)})

    # Unknown stream.
    r = get_proof(client, "nope", 1, 1)
    assert r.status_code == 404 and "unknown stream" in r.json()["error"]

    # Zero / negative / beyond-current watermarks are rejected.
    for bad in (0, -1, 4, 10**9):
        r = get_proof(client, "p5", 1, bad)
        assert r.status_code == 422, (bad, r.status_code)
    r = get_proof(client, "p5", 1, 4)
    assert r.json()["current_watermark"] == 3

    # Sealed record not covered by the requested (smaller) watermark.
    r = get_proof(client, "p5", 3, 2)
    assert r.status_code == 422 and "beyond requested watermark" \
        in r.json()["error"]

    # Malformed path/query parameters.
    assert client.get("/streams/p5/records/0/proof",
                      params={"watermark": 1}).status_code == 422
    assert client.get("/streams/p5/records/1/proof").status_code == 422
    assert client.get("/streams/p5/records/1/proof",
                      params={"watermark": "abc"}).status_code == 422


def test_proof_queries_do_not_mutate_state(tmp_db):
    client, _ = tmp_db
    key = register(client, "p6")
    d = {i: digest(7600 + i) for i in range(1, 6)}
    submit_chain(client, key, "p6", [1, 2, 3], d)
    # Pending record behind the gap at 4.
    post_record(client, "p6", make_record(key, "p6", 5, d[4], d[5]))

    tail_before = post_record(
        client, "p6", make_record(key, "p6", 2, d[1], d[2])
    ).json()["tail_digest"]

    # A barrage of valid and invalid proof queries.
    for seq in (1, 2, 3):
        for wm in (1, 2, 3):
            if seq <= wm:
                assert get_proof(client, "p6", seq, wm).status_code == 200
    assert get_proof(client, "p6", 5, 3).status_code == 404
    assert get_proof(client, "p6", 1, 0).status_code == 422
    assert get_proof(client, "p6", 1, 99).status_code == 422

    # Watermark, tail and retransmission verdicts are exactly as before.
    r = post_record(client, "p6", make_record(key, "p6", 2, d[1], d[2]))
    body = r.json()
    assert body["duplicate"] is True and body["watermark"] == 3
    assert body["tail_digest"] == tail_before
    # The pending record still seals in order when the gap is filled.
    r = post_record(client, "p6", make_record(key, "p6", 4, d[3], d[4]))
    assert r.json()["state"] == "sealed" and r.json()["watermark"] == 5

    # Same for a frozen stream: queries never change the freeze verdict.
    key2 = register(client, "p6f")
    f = {i: digest(7700 + i) for i in range(1, 3)}
    post_record(client, "p6f", make_record(key2, "p6f", 1, ZERO, f[1]))
    r = post_record(client, "p6f",
                    make_record(key2, "p6f", 2, digest(66), f[2]))
    assert r.status_code == 409
    assert get_proof(client, "p6f", 1, 1).status_code == 200
    assert get_proof(client, "p6f", 1, 2).status_code == 422
    r = post_record(client, "p6f", make_record(key2, "p6f", 2, f[1], f[2]))
    body = r.json()
    assert r.status_code == 409 and body["status"] == "forked"
    assert body["watermark"] == 1 and body["tail_digest"] == f[1].hex()
