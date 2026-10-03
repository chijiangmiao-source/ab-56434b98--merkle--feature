#!/usr/bin/env python3
"""Live HTTP smoke test against a running app container.

Covers, over real HTTP:
  * health endpoint
  * stream registration + public-key immutability
  * out-of-order merge (records 3,2 then 1) and identical retransmission
  * fork freeze via conflicting retransmission, and frozen permanence
  * read-only Merkle archive proof, independently recomputed here
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

    # A third stream: Merkle proof at a *historical* watermark, recomputed
    # independently over raw bytes (no app.merkle import).
    pkey = nacl.signing.SigningKey.generate()
    psid = "smoke-buoy-proof"
    call("POST", "/streams",
         {"id": psid, "public_key": b64(pkey.verify_key.encode())},
         expect=(200,))
    d = {i: digest(i + 200) for i in range(1, 6)}
    leaf_ref = {}
    for i in range(1, 6):
        prev = ZERO_DIGEST if i == 1 else d[i - 1]
        signed = rec(pkey, psid, i, prev, d[i])
        call("POST", f"/streams/{psid}/records", signed, expect=(200,))
        pre = (struct.pack(">H", len(psid.encode())) + psid.encode()
               + struct.pack(">Q", i) + prev + d[i]
               + base64.b64decode(signed["signature"]))
        leaf_ref[i] = hashlib.sha256(b"\x00" + pre).digest()

    # Ask for seq 3 as of the historical prefix of length 3.
    p = call("GET", f"/streams/{psid}/records/3/proof?watermark=3",
             expect=(200,))
    assert p["watermark"] == 3 and p["seq"] == 3, p
    node = leaf_ref[3]
    for step in p["proof"]:  # leaf -> root, using the sibling's position
        sib = bytes.fromhex(step["digest"])
        node = (hashlib.sha256(b"\x01" + sib + node).digest()
                if step["position"] == "left"
                else hashlib.sha256(b"\x01" + node + sib).digest())
    assert node == bytes.fromhex(p["root_digest"]), "proof mismatch"

    # Error boundaries over real HTTP.
    call("GET", f"/streams/{psid}/records/1/proof?watermark=0",
         expect=(422,))
    call("GET", f"/streams/{psid}/records/1/proof?watermark=99",
         expect=(404,))
    call("GET", f"/streams/{psid}/records/5/proof?watermark=3",
         expect=(404,))
    call("GET", "/streams/no-such-buoy/records/1/proof?watermark=1",
         expect=(404,))
    # The read-only proof changed nothing: duplicate verdict still stands.
    r = call("POST", f"/streams/{psid}/records",
             rec(pkey, psid, 3, d[2], d[3]), expect=(200,))
    assert r["duplicate"] is True and r["watermark"] == 5, r

    if failures:
        print("SMOKE FAILURES:")
        for f in failures:
            print(" -", f)
        return 1
    print("HTTP smoke: all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
