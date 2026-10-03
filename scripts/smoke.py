#!/usr/bin/env python3
"""Live HTTP smoke test against a running app container.

Covers, over real HTTP:
  * health endpoint
  * stream registration + public-key immutability
  * out-of-order merge (records 3,2 then 1) and identical retransmission
  * fork freeze via conflicting retransmission, and frozen permanence
  * Merkle inclusion proofs: independent recomputation, historical
    watermarks, rejection of pending/forked records and bad watermarks
"""

from __future__ import annotations

import base64
import hashlib
import os
import struct
import sys

import nacl.signing
import urllib.error
import urllib.request
import json

from app.message import ZERO_DIGEST, encode_message

BASE = os.environ.get("APP_URL", "http://app:8000").rstrip("/")
failures: list[str] = []


def call(method: str, path: str, body: dict | None = None,
         expect: tuple[int, ...] = (200,)) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        BASE + path, data=data, method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            code = resp.status
            payload = json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as exc:
        code = exc.code
        payload = json.loads(exc.read() or b"{}")
    if code not in expect:
        failures.append(f"{method} {path}: expected {expect}, got {code} "
                        f"{payload}")
    return payload


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def digest(n: int) -> bytes:
    return f"d{n:030d}".encode().ljust(32, b"x")[:32]


def rec(key, sid, seq, prev, payload) -> dict:
    sig = key.sign(encode_message(sid, seq, prev, payload)).signature
    return {"seq": seq, "prev_digest": b64(prev),
            "payload_digest": b64(payload), "signature": b64(sig)}


# Independent auditor-side recomputation, straight from the spec:
# leaf = SHA-256(0x00 || u16be(len(id)) || id || u64be(seq) || prev[32]
#                || payload[32] || sig[64])
# node = SHA-256(0x01 || left || right); odd nodes promoted unchanged.

def spec_leaf(sid: str, seq: int, prev: bytes, payload: bytes,
              sig: bytes) -> bytes:
    sid_b = sid.encode("ascii")
    return hashlib.sha256(
        b"\x00" + struct.pack(">H", len(sid_b)) + sid_b
        + struct.pack(">Q", seq) + prev + payload + sig
    ).digest()


def spec_fold(leaf: bytes, index: int, count: int, path: list) -> bytes:
    cur, idx, width, used = leaf, index, count, 0
    while width > 1:
        if width % 2 == 1 and idx == width - 1:
            pass  # promoted level: no sibling step
        else:
            step = path[used]
            used += 1
            sib = bytes.fromhex(step["digest"])
            if step["position"] == "left":
                cur = hashlib.sha256(b"\x01" + sib + cur).digest()
            else:
                cur = hashlib.sha256(b"\x01" + cur + sib).digest()
        idx //= 2
        width = (width + 1) // 2
    assert used == len(path), "path length does not match tree shape"
    return cur


def check_proof(sid: str, seq: int, watermark: int) -> dict:
    """Fetch a proof and recompute its root from the response alone."""
    body = call("GET",
                f"/streams/{sid}/records/{seq}/proof?watermark={watermark}",
                expect=(200,))
    r = body["record"]
    leaf = spec_leaf(sid, seq,
                     base64.b64decode(r["prev_digest"]),
                     base64.b64decode(r["payload_digest"]),
                     base64.b64decode(r["signature"]))
    if body["leaf_digest"] != leaf.hex():
        failures.append(f"proof {sid}/{seq}@{watermark}: leaf mismatch")
    if body["leaf_index"] != seq - 1 or body["leaf_count"] != watermark:
        failures.append(f"proof {sid}/{seq}@{watermark}: bad index/count")
    root = spec_fold(leaf, body["leaf_index"], body["leaf_count"],
                     body["path"])
    if root.hex() != body["root_digest"]:
        failures.append(f"proof {sid}/{seq}@{watermark}: root mismatch")
    return body


def main() -> int:
    call("GET", "/health", expect=(200,))

    key = nacl.signing.SigningKey.generate()
    sid = "smoke-buoy-001"
    call("POST", "/streams",
         {"id": sid, "public_key": b64(key.verify_key.encode())},
         expect=(200,))
    other = nacl.signing.SigningKey.generate()
    call("POST", "/streams",
         {"id": sid, "public_key": b64(other.verify_key.encode())},
         expect=(409,))

    d = {i: digest(i) for i in range(1, 5)}
    # Out of order: 3, then 2 (pending), then 1 seals through 3.
    r = call("POST", f"/streams/{sid}/records",
             rec(key, sid, 3, d[2], d[3]), expect=(200,))
    assert r["state"] == "pending" and r["watermark"] == 0, r
    r = call("POST", f"/streams/{sid}/records",
             rec(key, sid, 2, d[1], d[2]), expect=(200,))
    assert r["state"] == "pending", r
    r = call("POST", f"/streams/{sid}/records",
             rec(key, sid, 1, ZERO_DIGEST, d[1]), expect=(200,))
    assert r["state"] == "sealed" and r["watermark"] == 3, r

    # Identical retransmission returns the existing verdict.
    r = call("POST", f"/streams/{sid}/records",
             rec(key, sid, 2, d[1], d[2]), expect=(200,))
    assert r["duplicate"] is True and r["state"] == "sealed", r

    # Merkle inclusion proofs over the sealed prefix 1..3.
    proof = check_proof(sid, 2, 3)
    assert proof["status"] == "active" and proof["current_watermark"] == 3
    check_proof(sid, 1, 1)   # single-leaf tree: root == leaf, empty path
    check_proof(sid, 3, 3)   # odd-width level: promotion exercised
    # Historical watermark stays stable after the prefix grows.
    call("POST", f"/streams/{sid}/records",
         rec(key, sid, 4, d[3], d[4]), expect=(200,))
    again = check_proof(sid, 2, 3)
    if again["root_digest"] != proof["root_digest"] or \
            again["path"] != proof["path"]:
        failures.append("historical proof changed after append")
    # Zero / beyond-current watermarks and unsealed seqs are rejected.
    call("GET", f"/streams/{sid}/records/2/proof?watermark=0", expect=(422,))
    call("GET", f"/streams/{sid}/records/2/proof?watermark=5", expect=(422,))
    call("GET", f"/streams/{sid}/records/4/proof?watermark=3", expect=(422,))
    call("GET", f"/streams/{sid}/records/9/proof?watermark=3", expect=(404,))
    call("GET", "/streams/ghost/records/1/proof?watermark=1", expect=(404,))

    # A second stream: conflicting retransmission freezes it.
    fkey = nacl.signing.SigningKey.generate()
    fsid = "smoke-buoy-fork"
    call("POST", "/streams",
         {"id": fsid, "public_key": b64(fkey.verify_key.encode())},
         expect=(200,))
    call("POST", f"/streams/{fsid}/records",
         rec(fkey, fsid, 1, ZERO_DIGEST, digest(70)), expect=(200,))
    r = call("POST", f"/streams/{fsid}/records",
             rec(fkey, fsid, 1, ZERO_DIGEST, digest(71)), expect=(409,))
    assert r["state"] == "forked" and r["status"] == "forked", r
    # Frozen forever.
    r = call("POST", f"/streams/{fsid}/records",
             rec(fkey, fsid, 2, digest(71), digest(72)), expect=(409,))
    assert r["watermark"] == 1 and r["status"] == "forked", r

    # A frozen stream still serves its frozen prefix (watermark 1) but
    # nothing beyond it.
    fproof = check_proof(fsid, 1, 1)
    assert fproof["status"] == "forked", fproof
    call("GET", f"/streams/{fsid}/records/1/proof?watermark=2",
         expect=(422,))

    if failures:
        print("SMOKE FAILURES:")
        for f in failures:
            print(" -", f)
        return 1
    print("HTTP smoke: all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
