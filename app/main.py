"""HTTP API for the buoy signed-prefix archive."""

from __future__ import annotations

import base64
import binascii
import os
from contextlib import asynccontextmanager

import nacl.signing
from fastapi import FastAPI, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .message import encode_message
from .storage import (
    GapTooLarge,
    InvalidSignature,
    InvalidWatermark,
    KeyConflict,
    Store,
    UnknownStream,
    UnsealedRecord,
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

    @api.get("/streams/{stream_id}/records/{seq}/proof")
    def get_proof(
        stream_id: str,
        seq: int,
        watermark: int = Query(
            ..., ge=1, le=(1 << 64) - 1,
            description="historical sealed prefix length to prove against",
        ),
    ):
        """Read-only Merkle proof of one sealed record at a past watermark.

        The response is self-contained: the record fields, the prefix root
        digest, and the sibling path (leaf -> root) let an offline reviewer
        re-hash the root without fetching anything else. Pending records are
        never provable; a frozen stream is only served at the watermark it
        stopped at. This call never mutates watermark, freeze verdict or any
        prior retransmission verdict.
        """
        store = api.state.store
        try:
            proof = store.get_proof(stream_id, seq, watermark)
        except UnknownStream:
            return JSONResponse(
                status_code=404, content={"error": "unknown stream"}
            )
        except InvalidWatermark as exc:
            status = 404 if exc.watermark > exc.current else 400
            return JSONResponse(
                status_code=status,
                content={"error": str(exc),
                         "requested_watermark": exc.watermark,
                         "current_watermark": exc.current},
            )
        except UnsealedRecord:
            return JSONResponse(
                status_code=404,
                content={"error": "record is not sealed within the requested "
                                  "prefix",
                         "seq": seq, "watermark": watermark},
            )
        return JSONResponse(
            status_code=200,
            content={
                "id": proof.stream_id,
                "seq": proof.seq,
                "watermark": proof.watermark,
                "record": {
                    "prev_digest": proof.prev_digest.hex(),
                    "payload_digest": proof.payload_digest.hex(),
                    "signature": proof.signature.hex(),
                },
                "root_digest": proof.root.hex(),
                # Sibling digests in leaf->root order. "position" says where
                # the sibling sits relative to the proven node; the reviewer
                # combines it on that side to rebuild the root.
                "proof": [
                    {"digest": step.digest.hex(), "position": step.position}
                    for step in proof.path
                ],
            },
        )

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
