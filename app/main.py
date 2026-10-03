"""HTTP API for the buoy signed-prefix archive."""

from __future__ import annotations

import base64
import binascii
import os
from contextlib import asynccontextmanager

import nacl.signing
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .message import encode_message
from .storage import (
    GapTooLarge,
    InvalidSignature,
    KeyConflict,
    Store,
    UnknownStream,
)

MAX_GAP = 32


class RegisterRequest(BaseModel):
    id: str = Field(min_length=1, max_length=256)
    public_key: str  # base64 (standard or urlsafe), 32 raw Ed25519 bytes


class RecordRequest(BaseModel):
    # Sequences are 1-based; the first record links to the all-zero digest.
    seq: int = Field(ge=1, le=(1 << 64) - 1)
    prev_digest: str  # base64, 32 bytes
    payload_digest: str  # base64, 32 bytes
    signature: str  # base64, 64 bytes Ed25519 over the prescribed message


class _BadRequest(Exception):
    def __init__(self, message: str):
        self.message = message


def _b64(data: str, name: str, size: int) -> bytes:
    s = data.strip()
    pad = (-len(s)) % 4
    try:
        raw = base64.b64decode(s + "=" * pad, validate=True)
    except (binascii.Error, ValueError):
        try:
            raw = base64.urlsafe_b64decode(s + "=" * pad, validate=True)
        except (binascii.Error, ValueError):
            raise _BadRequest(f"{name} is not valid base64")
    if len(raw) != size:
        raise _BadRequest(f"{name} must be {size} bytes, got {len(raw)}")
    return raw


def create_app(db_path: str) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # Opening the Store rebuilds the watermark from durable records, so a
        # restart resumes exactly the same contiguous prefix.
        app.state.store = Store(db_path)
        try:
            yield
        finally:
            app.state.store.close()

    api = FastAPI(title="buoy-prefix-archive", lifespan=lifespan)

    @api.exception_handler(_BadRequest)
    async def _bad_request_handler(request: Request, exc: _BadRequest):
        return JSONResponse(status_code=400, content={"error": exc.message})

    @api.get("/health")
    def health():
        return {"status": "ok"}

    @api.post("/streams")
    def create_stream(body: RegisterRequest):
        try:
            body.id.encode("ascii")
        except UnicodeEncodeError:
            raise _BadRequest("id must be ASCII")
        key = _b64(body.public_key, "public_key", 32)
        try:
            outcome = api.state.store.create_stream(body.id, key)
        except KeyConflict:
            return JSONResponse(
                status_code=409,
                content={"error": "stream id already registered with a "
                                  "different public key; key rotation is "
                                  "forbidden"},
            )
        return {"id": body.id, "status": "active", "registered": outcome}

    @api.post("/streams/{stream_id}/records")
    def submit_record(stream_id: str, body: RecordRequest):
        prev = _b64(body.prev_digest, "prev_digest", 32)
        payload = _b64(body.payload_digest, "payload_digest", 32)
        sig = _b64(body.signature, "signature", 64)
        store = api.state.store
        stream = store.get_stream(stream_id)
        if stream is None:
            return JSONResponse(
                status_code=404, content={"error": "unknown stream"}
            )

        # Verify over the exact prescribed binary message
        # (id length+bytes, u64be seq, prev[32], payload[32]) -- never over a
        # JSON re-encoding.
        message = encode_message(stream_id, body.seq, prev, payload)
        verify_key = nacl.signing.VerifyKey(bytes(stream["public_key"]))
        try:
            verify_key.verify(message, sig)
            valid = True
        except nacl.exceptions.BadSignatureError:
            valid = False

        try:
            verdict = store.submit(
                stream_id, body.seq, prev, payload, sig, signature_valid=valid
            )
        except InvalidSignature:
            return JSONResponse(
                status_code=403,
                content={"error": "signature does not verify over the "
                                  "prescribed binary message"},
            )
        except GapTooLarge as exc:
            return JSONResponse(
                status_code=422,
                content={"error": str(exc),
                         "watermark": exc.watermark, "max_gap": MAX_GAP},
            )

        http_status = 409 if verdict.state == "forked" else 200
        return JSONResponse(
            status_code=http_status,
            content={
                "id": verdict.stream_id,
                "seq": verdict.seq,
                "state": verdict.state,
                "status": verdict.status,
                "watermark": verdict.watermark,
                "tail_digest": verdict.tail_digest.hex(),
                "duplicate": verdict.duplicate,
            },
        )

    return api


DB_PATH = os.environ.get("BUOY_DB", "/data/buoy.db")
app = create_app(DB_PATH)
