"""Fixed binary Merkle scheme over sealed prefixes.

A prefix of ``watermark`` sealed records is committed by a Merkle tree whose
leaves are the sealed records in seq order (1..watermark). Every encoding is
a fixed byte sequence -- no JSON re-encoding is involved anywhere.

Leaf pre-image (all integers big-endian)::

    u16be(len(stream_id)) || stream_id ASCII bytes
    || u64be(seq)
    || prev_digest[32]
    || payload_digest[32]
    || signature[64]

Hashing uses domain tags so a leaf hash can never be mistaken for an internal
node hash::

    leaf_hash = sha256(0x00 || leaf_pre_image)
    node_hash = sha256(0x01 || left_hash || right_hash)

Odd-layer rule (fixed): when a level contains an odd number of nodes, its
last node is *promoted unchanged* to the next level (it is not duplicated or
re-hashed). A single-leaf tree has the leaf hash as its root.
"""

from __future__ import annotations

import hashlib
import struct

LEAF_TAG = b"\x00"
NODE_TAG = b"\x01"

U64_MAX = (1 << 64) - 1

# Position of the *sibling* relative to the node being proven.
LEFT = "left"
RIGHT = "right"


def encode_leaf(
    stream_id: str,
    seq: int,
    prev_digest: bytes,
    payload_digest: bytes,
    signature: bytes,
) -> bytes:
    """Encode one leaf's fixed binary pre-image."""
    sid = stream_id.encode("ascii")
    if len(sid) > 0xFFFF:
        raise ValueError("stream id too long")
    if not 1 <= seq <= U64_MAX:
        raise ValueError("seq out of u64 range")
    if len(prev_digest) != 32:
        raise ValueError("prev_digest must be 32 bytes")
    if len(payload_digest) != 32:
        raise ValueError("payload_digest must be 32 bytes")
    if len(signature) != 64:
        raise ValueError("signature must be 64 raw Ed25519 bytes")
    return (
        struct.pack(">H", len(sid))
        + sid
        + struct.pack(">Q", seq)
        + prev_digest
        + payload_digest
        + signature
    )


def leaf_digest(encoded_leaf: bytes) -> bytes:
    return hashlib.sha256(LEAF_TAG + encoded_leaf).digest()


def node_digest(left: bytes, right: bytes) -> bytes:
    if len(left) != 32 or len(right) != 32:
        raise ValueError("node children must be 32-byte digests")
    return hashlib.sha256(NODE_TAG + left + right).digest()


def root_and_path(
    encoded_leaves: list[bytes], index: int
) -> tuple[bytes, list[tuple[bytes, str]]]:
    """Return ``(root, path)`` for leaf ``index`` (0-based).

    ``path`` runs from the leaf toward the root. Each entry is
    ``(sibling_digest, sibling_position)`` where position is ``"left"`` when
    the sibling is the left child (the proven node is the right child) and
    ``"right"`` otherwise. Odd tail nodes produce no path entry for that
    level: they are promoted unchanged, and the index follows them.
    """
    if not encoded_leaves:
        raise ValueError("cannot build a Merkle tree over zero leaves")
    if not 0 <= index < len(encoded_leaves):
        raise IndexError("leaf index out of range")

    level = [leaf_digest(leaf) for leaf in encoded_leaves]
    idx = index
    path: list[tuple[bytes, str]] = []
    while len(level) > 1:
        if idx % 2 == 0:
            # Proven node is the left child; the sibling is on the right
            # unless this is the odd tail node being promoted.
            if idx + 1 < len(level):
                path.append((level[idx + 1], RIGHT))
        else:
            path.append((level[idx - 1], LEFT))
        next_level = [
            node_digest(level[i], level[i + 1])
            for i in range(0, len(level) - 1, 2)
        ]
        if len(level) % 2 == 1:
            # Odd tail node is promoted to the next level unchanged.
            next_level.append(level[-1])
        level = next_level
        idx //= 2
    return level[0], path
