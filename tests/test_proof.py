"""Offline Merkle proof tests.

Every success case is verified by an *independent* recomputation written from
scratch here (fixed binary leaf encoding, domain tags, odd-node promotion),
so the API cannot pass by echoing its own helpers.
"""

from __future__ import annotations

import base64
import hashlib
import struct

from tests.conftest import (
    ZERO,
    digest,
    make_record,
    post_record,
    register,
    restart_client,
)


# --- independent reference implementation (never imports app.merkle) -------

def ref_leaf(sid: str, seq: int, prev: bytes, payload: bytes,
             sig: bytes) -> bytes:
    sid_b = sid.encode("ascii")
    pre = (
        struct.pack(">H", len(sid_b)) + sid_b
        + struct.pack(">Q", seq) + prev + payload + sig
    )
    return hashlib.sha256(b"\x00" + pre).digest()


def ref_node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def ref_root(leaves: list[bytes]) -> bytes:
    """Independent root with the fixed odd-tail promotion rule."""
    level = list(leaves)
    while len(level) > 1:
        nxt = [ref_node(level[i], level[i + 1])
               for i in range(0, len(level) - 1, 2)]
        if len(level) % 2 == 1:
            nxt.append(level[-1])  # odd tail promoted, not re-hashed
        level = nxt
    return level[0]


def verify_response(sid: str, leaves_by_seq: dict[int, bytes], body: dict):
    """Rebuild the root from the response alone; cross-check all leaves."""
    rec = body["record"]
    node = ref_leaf(
        sid, body["seq"],
        bytes.fromhex(rec["prev_digest"]),
        bytes.fromhex(rec["payload_digest"]),
        bytes.fromhex(rec["signature"]),
    )
    for step in body["proof"]:
        sib = bytes.fromhex(step["digest"])
        if step["position"] == "left":
            node = ref_node(sib, node)
        else:
            assert step["position"] == "right"
            node = ref_node(node, sib)
    assert node == bytes.fromhex(body["root_digest"])
    wm = body["watermark"]
    expected = ref_root([leaves_by_seq[i] for i in range(1, wm + 1)])
    assert bytes.fromhex(body["root_digest"]) == expected


def seal_chain(client, sid, key, lo, hi):
    """Seal seqs lo..hi in order; return {seq: reference leaf digest}."""
    leaves = {}
    for seq in range(lo, hi + 1):
        prev = ZERO if seq == 1 else digest(seq - 1)
        payload = digest(seq)
        signed = make_record(key, sid, seq, prev, payload)
        r = post_record(client, sid, signed)
        assert r.status_code == 200, r.text
        leaves[seq] = ref_leaf(
            sid, seq, prev, payload,
            base64.b64decode(signed["signature"]),
        )
    return leaves


# --------------------------------------------------------------- happy paths

def test_single_leaf_tree_empty_path(tmp_db):
    client, _ = tmp_db
    key = register(client, "p1")
    signed = make_record(key, "p1", 1, ZERO, digest(1))
    post_record(client, "p1", signed)
    r = client.get("/streams/p1/records/1/proof?watermark=1")
    assert r.status_code == 200, r.text
    body = r.json()
    leaf = ref_leaf("p1", 1, ZERO, digest(1),
                    base64.b64decode(signed["signature"]))
    assert body["proof"] == []  # single leaf: root is the leaf itself
    assert bytes.fromhex(body["root_digest"]) == leaf
    verify_response("p1", {1: leaf}, body)


def test_proofs_for_all_tree_shapes(tmp_db):
    """Sizes 1..8 exercise every odd/even layer and promotion pattern."""
    client, _ = tmp_db
    key = register(client, "p2")
    leaves = seal_chain(client, "p2", key, 1, 8)

    payloads = {i: (ZERO if i == 1 else digest(i - 1), digest(i))
                for i in range(1, 9)}
    sigs = {}
    for i in range(1, 9):
        prev, payload = payloads[i]
        sigs[i] = base64.b64decode(
            make_record(key, "p2", i, prev, payload)["signature"])

    for wm in range(1, 9):
        for seq in range(1, wm + 1):
            r = client.get(f"/streams/p2/records/{seq}/proof?watermark={wm}")
            assert r.status_code == 200, (wm, seq, r.text)
            body = r.json()
            assert body["id"] == "p2" and body["seq"] == seq
            assert body["watermark"] == wm
            prev, payload = payloads[seq]
            assert bytes.fromhex(body["record"]["prev_digest"]) == prev
            assert bytes.fromhex(body["record"]["payload_digest"]) == payload
            assert bytes.fromhex(body["record"]["signature"]) == sigs[seq]
            verify_response("p2", leaves, body)


def test_historical_watermark_stable_after_growth_retransmit_restart(tmp_db):
    client, path = tmp_db
    key = register(client, "p3")
    seal_chain(client, "p3", key, 1, 3)

    # Snapshot the historical proof at watermark 2.
    r = client.get("/streams/p3/records/2/proof?watermark=2")
    assert r.status_code == 200
    snapshot = r.json()

    # Later records extend the prefix past it ...
    seal_chain(client, "p3", key, 4, 6)
    # ... an identical retransmission happens ...
    rr = post_record(client, "p3",
                     make_record(key, "p3", 2, digest(1), digest(2)))
    assert rr.json()["duplicate"] is True
    # ... and the service restarts.
    with restart_client(path) as client2:
        r2 = client2.get("/streams/p3/records/2/proof?watermark=2")
        assert r2.status_code == 200
        again = r2.json()
    assert again == snapshot  # identical root and identical sibling path


def test_frozen_stream_served_only_at_frozen_watermark(tmp_db):
    client, _ = tmp_db
    key = register(client, "p4")
    signed1 = make_record(key, "p4", 1, ZERO, digest(1))
    post_record(client, "p4", signed1)
    # seq 3 pending behind the hole at 2.
    post_record(client, "p4", make_record(key, "p4", 3, digest(2), digest(3)))
    # Filling 2 with a bad link freezes the stream at watermark 1.
    r = post_record(client, "p4",
                    make_record(key, "p4", 2, digest(9), digest(22)))
    assert r.status_code == 409 and r.json()["watermark"] == 1

    # The frozen prefix can still be audited.
    r = client.get("/streams/p4/records/1/proof?watermark=1")
    assert r.status_code == 200, r.text
    leaf = ref_leaf("p4", 1, ZERO, digest(1),
                    base64.b64decode(signed1["signature"]))
    assert bytes.fromhex(r.json()["root_digest"]) == leaf

    # But only at the watermark it stopped at: pending records stay out.
    assert client.get(
        "/streams/p4/records/2/proof?watermark=1").status_code == 404
    assert client.get(
        "/streams/p4/records/3/proof?watermark=1").status_code == 404
    assert client.get(
        "/streams/p4/records/1/proof?watermark=2").status_code == 404


def test_pending_records_never_provable(tmp_db):
    client, _ = tmp_db
    key = register(client, "p5")
    # seq 2,3 held pending, watermark 0: nothing sealed, nothing to prove.
    post_record(client, "p5", make_record(key, "p5", 2, digest(1), digest(2)))
    post_record(client, "p5", make_record(key, "p5", 3, digest(2), digest(3)))
    assert client.get(
        "/streams/p5/records/2/proof?watermark=1").status_code == 404
    # Seal 1..3 and ask for 2 at the older prefix of length 1: it was not in
    # that historical prefix.
    post_record(client, "p5", make_record(key, "p5", 1, ZERO, digest(1)))
    r = client.get("/streams/p5/records/2/proof?watermark=1")
    assert r.status_code == 404
    r = client.get("/streams/p5/records/2/proof?watermark=2")
    assert r.status_code == 200


# --------------------------------------------------------------- error cases

def test_proof_unknown_stream_404(tmp_db):
    client, _ = tmp_db
    r = client.get("/streams/ghost/records/1/proof?watermark=1")
    assert r.status_code == 404


def test_proof_bad_watermark_boundaries(tmp_db):
    client, _ = tmp_db
    key = register(client, "p6")
    seal_chain(client, "p6", key, 1, 2)

    # Zero / negative watermark is rejected at parameter validation.
    assert client.get(
        "/streams/p6/records/1/proof?watermark=0").status_code == 422
    assert client.get(
        "/streams/p6/records/1/proof?watermark=-1").status_code == 422
    # Beyond the current sealed prefix is refused (even when the seq exists).
    r = client.get("/streams/p6/records/1/proof?watermark=3")
    assert r.status_code == 404
    assert r.json()["current_watermark"] == 2
    # seq zero or above the requested watermark is not in that prefix.
    assert client.get(
        "/streams/p6/records/0/proof?watermark=1").status_code == 404
    assert client.get(
        "/streams/p6/records/3/proof?watermark=2").status_code == 404
    # Missing the required query parameter.
    assert client.get("/streams/p6/records/1/proof").status_code == 422
    # Garbage value.
    assert client.get(
        "/streams/p6/records/1/proof?watermark=abc").status_code == 422


# ------------------------------------------------------------- non-mutation

def test_proof_reads_do_not_change_state(tmp_db):
    client, _ = tmp_db
    key = register(client, "p7")
    seal_chain(client, "p7", key, 1, 2)

    for _ in range(3):
        r = client.get("/streams/p7/records/1/proof?watermark=2")
        assert r.status_code == 200
    # Watermark and tail unchanged; identical retransmission still returns
    # its prior verdict.
    r = post_record(client, "p7", make_record(key, "p7", 1, ZERO, digest(1)))
    body = r.json()
    assert body["duplicate"] is True and body["state"] == "sealed"
    assert body["watermark"] == 2 and body["tail_digest"] == digest(2).hex()
    # Failed proof attempts (out-of-range watermark) also mutate nothing.
    client.get("/streams/p7/records/1/proof?watermark=99")
    r = post_record(client, "p7",
                    make_record(key, "p7", 2, digest(1), digest(2)))
    assert r.json()["duplicate"] is True and r.json()["watermark"] == 2
