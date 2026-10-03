"""Prescribed binary message format for record signatures.

The signed message is exactly::

    u16be(len(stream_id)) || stream_id ASCII bytes
    || u64be(seq)
    || prev_digest[32]
    || payload_digest[32]

Lengths are big-endian. Verification always runs over these raw bytes, never
over a re-encoding of the JSON request body.
"""

from __future__ import annotations

import struct

ZERO_DIGEST = b"\x00" * 32
U64_MAX = (1 << 64) - 1


def encode_message(
    stream_id: str,
    seq: int,
    prev_digest: bytes,
    payload_digest: bytes,
) -> bytes:
    sid = stream_id.encode("ascii")
    if len(sid) > 0xFFFF:
        raise ValueError("stream id too long")
    if not 0 <= seq <= U64_MAX:
        raise ValueError("seq out of u64 range")
    if len(prev_digest) != 32 or len(payload_digest) != 32:
        raise ValueError("digests must be 32 bytes")
    return (
        struct.pack(">H", len(sid))
        + sid
        + struct.pack(">Q", seq)
        + prev_digest
        + payload_digest
    )
