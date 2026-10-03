"""Binary Merkle tree over the sealed record prefix of a stream.

Every encoding rule below is fixed so that an offline auditor can recompute
the exact same digests from a proof response alone -- no JSON re-encoding
and no tree-shape ambiguity anywhere:

Leaf digest (domain tag ``0x00``)::

    SHA-256( 0x00
             || u16be(len(stream_id)) || stream_id ASCII bytes
             || u64be(seq)
             || prev_digest[32]
             || payload_digest[32]
             || signature[64] )

Internal node (domain tag ``0x01``)::

    SHA-256( 0x01 || left[32] || right[32] )

The distinct leaf/node tags make a leaf preimage unusable as an internal
node preimage and vice versa.

Odd-level rule: when a level has an odd number of nodes, the last node is
*promoted unchanged* to the next level -- it is never duplicated and never
re-hashed. A tree with a single leaf has that leaf's digest as its root and
an empty proof path.

Leaves are the sealed records ordered by ``seq`` (1-based), so the record
with ``seq = s`` sits at 0-based leaf index ``s - 1`` and a prefix of
``watermark`` records yields exactly ``watermark`` leaves. Sealed rows are
immutable, therefore a proof for a historical watermark keeps the same root
and path after later appends, retransmissions, or restarts.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

LEAF_TAG = b"\x00"
NODE_TAG = b"\x01"
DIGEST_SIZE = 32

#: Sibling positions used in proof steps: where the sibling sits relative
#: to the running node on the path from leaf to root.
LEFT = "left"
RIGHT = "right"


@dataclass(frozen=True)
class ProofStep:
    """One sibling on the path from a leaf to the root.

    ``position`` tells on which side of the running node the sibling is
    hashed: ``left`` means ``node_digest(sibling, running)``, ``right``
    means ``node_digest(running, sibling)``.
    """

    digest: bytes
    position: str  # LEFT | RIGHT

    def __post_init__(self):
        if len(self.digest) != DIGEST_SIZE:
            raise ValueError("proof step digest must be 32 bytes")
        if self.position not in (LEFT, RIGHT):
            raise ValueError(f"bad sibling position: {self.position!r}")


def encode_leaf(
    stream_id: str,
    seq: int,
    prev_digest: bytes,
    payload_digest: bytes,
    signature: bytes,
) -> bytes:
    """The fixed binary leaf preimage (tagged), never a JSON encoding."""
    sid = stream_id.encode("ascii")
    if len(sid) > 0xFFFF:
        raise ValueError("stream id too long")
    if not 1 <= seq <= (1 << 64) - 1:
        raise ValueError("seq out of u64 range")
    if len(prev_digest) != 32 or len(payload_digest) != 32:
        raise ValueError("digests must be 32 bytes")
    if len(signature) != 64:
        raise ValueError("signature must be 64 bytes")
    return (
        LEAF_TAG
        + struct.pack(">H", len(sid))
        + sid
        + struct.pack(">Q", seq)
        + prev_digest
        + payload_digest
        + signature
    )


def leaf_digest(
    stream_id: str,
    seq: int,
    prev_digest: bytes,
    payload_digest: bytes,
    signature: bytes,
) -> bytes:
    return hashlib.sha256(
        encode_leaf(stream_id, seq, prev_digest, payload_digest, signature)
    ).digest()


def node_digest(left: bytes, right: bytes) -> bytes:
    if len(left) != DIGEST_SIZE or len(right) != DIGEST_SIZE:
        raise ValueError("node children must be 32-byte digests")
    return hashlib.sha256(NODE_TAG + left + right).digest()


def _next_level(level: list[bytes]) -> list[bytes]:
    """Hash pairs left-to-right; promote an odd trailing node unchanged."""
    nxt = [
        node_digest(level[i], level[i + 1])
        for i in range(0, len(level) - 1, 2)
    ]
    if len(level) % 2 == 1:
        nxt.append(level[-1])  # promoted as-is, never duplicated/re-hashed
    return nxt


def merkle_root(leaves: list[bytes]) -> bytes:
    """Root digest of the tree over ``leaves`` (must be non-empty)."""
    if not leaves:
        raise ValueError("an empty prefix has no Merkle root")
    level = list(leaves)
    while len(level) > 1:
        level = _next_level(level)
    return level[0]


def merkle_path(leaves: list[bytes], index: int) -> list[ProofStep]:
    """Sibling steps for leaf ``index``, ordered from leaf to root.

    Levels where the running node is the unpaired odd node contribute no
    step (the node is promoted unchanged); the verifier derives those
    positions from ``index`` and the total leaf count.
    """
    if not 0 <= index < len(leaves):
        raise ValueError(f"leaf index {index} out of range ({len(leaves)})")
    steps: list[ProofStep] = []
    level = list(leaves)
    idx = index
    while len(level) > 1:
        width = len(level)
        if width % 2 == 1 and idx == width - 1:
            pass  # unpaired odd node: promoted, no sibling at this level
        elif idx % 2 == 0:
            steps.append(ProofStep(level[idx + 1], RIGHT))
        else:
            steps.append(ProofStep(level[idx - 1], LEFT))
        level = _next_level(level)
        idx //= 2
    return steps


def recompute_root(
    leaf: bytes,
    leaf_index: int,
    leaf_count: int,
    steps: list[ProofStep],
) -> bytes:
    """Fold a proof path back into the root, leaf-to-root.

    This is the auditor-side computation: given only the leaf digest, its
    0-based index, the total leaf count (== the watermark the proof was
    taken at) and the sibling steps, rebuild the root. Promotion levels are
    recovered from ``leaf_count``/``leaf_index`` alone, so the step list
    must contain exactly the paired-level siblings, in order.
    """
    if len(leaf) != DIGEST_SIZE:
        raise ValueError("leaf digest must be 32 bytes")
    if not 0 <= leaf_index < leaf_count:
        raise ValueError(
            f"leaf index {leaf_index} out of range ({leaf_count})"
        )
    cur = leaf
    idx = leaf_index
    width = leaf_count
    used = 0
    while width > 1:
        if width % 2 == 1 and idx == width - 1:
            pass  # promoted level: no sibling step consumed
        else:
            if used >= len(steps):
                raise ValueError("proof path too short")
            step = steps[used]
            used += 1
            if step.position == LEFT:
                cur = node_digest(step.digest, cur)
            else:
                cur = node_digest(cur, step.digest)
        idx //= 2
        width = (width + 1) // 2
    if used != len(steps):
        raise ValueError("proof path too long")
    return cur
