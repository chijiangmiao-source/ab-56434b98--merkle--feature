"""Shared pytest fixtures and signing helpers."""

from __future__ import annotations

import base64

import nacl.signing
import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.message import ZERO_DIGEST, encode_message


@pytest.fixture()
def tmp_db(tmp_path):
    path = str(tmp_path / "buoy.db")
    with TestClient(create_app(path)) as client:
        yield client, path


def fresh_key() -> nacl.signing.SigningKey:
    return nacl.signing.SigningKey.generate()


def register(client, sid: str, key: nacl.signing.SigningKey | None = None):
    if key is None:
        key = fresh_key()
    pub = key.verify_key.encode()
    r = client.post(
        "/streams",
        json={"id": sid, "public_key": base64.b64encode(pub).decode()},
    )
    assert r.status_code in (200, 201), r.text
    return key


def make_record(key, sid: str, seq: int, prev: bytes, payload: bytes):
    msg = encode_message(sid, seq, prev, payload)
    sig = key.sign(msg).signature
    return {
        "seq": seq,
        "prev_digest": base64.b64encode(prev).decode(),
        "payload_digest": base64.b64encode(payload).decode(),
        "signature": base64.b64encode(sig).decode(),
    }


def digest(n: int) -> bytes:
    """Deterministic 32-byte digest-ish value."""
    return (f"d{n:030d}").encode().ljust(32, b"x")[:32]


def post_record(client, sid: str, record: dict):
    return client.post(f"/streams/{sid}/records", json=record)


def restart_client(path: str) -> TestClient:
    """Open a fresh app against the same DB file, as a process restart would."""
    return TestClient(create_app(path))


ZERO = ZERO_DIGEST
