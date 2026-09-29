"""Binary Merkle tree over ledger event hashes, with inclusion proofs.

Leaves and interior nodes use different prefixes (0x00 / 0x01) so a leaf can
never be confused with an interior node (second-preimage hardening, as in
RFC 6962). An odd node at the end of a level is promoted unchanged.
"""

from __future__ import annotations

import hashlib

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"
EMPTY_ROOT = hashlib.sha256(b"").hexdigest()


def _leaf(h: str) -> bytes:
    return hashlib.sha256(LEAF_PREFIX + bytes.fromhex(h)).digest()


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def _levels(leaf_hashes: list[str]) -> list[list[bytes]]:
    level = [_leaf(h) for h in leaf_hashes]
    levels = [level]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(_node(level[i], level[i + 1]))
            else:
                nxt.append(level[i])
        level = nxt
        levels.append(level)
    return levels


def merkle_root(leaf_hashes: list[str]) -> str:
    if not leaf_hashes:
        return EMPTY_ROOT
    return _levels(leaf_hashes)[-1][0].hex()


def inclusion_proof(leaf_hashes: list[str], index: int) -> list[tuple[str, str]]:
    """Return [(side, sibling_hex), ...] from leaf to root. side is 'L' or 'R'
    (the side the *sibling* sits on)."""
    if not 0 <= index < len(leaf_hashes):
        raise IndexError(index)
    proof: list[tuple[str, str]] = []
    for level in _levels(leaf_hashes)[:-1]:
        sibling = index ^ 1
        if sibling < len(level):
            proof.append(("L" if sibling < index else "R", level[sibling].hex()))
        index //= 2
    return proof


def verify_inclusion(leaf_hash: str, proof: list[tuple[str, str]], root_hex: str) -> bool:
    acc = _leaf(leaf_hash)
    for side, sib_hex in proof:
        sib = bytes.fromhex(sib_hex)
        acc = _node(sib, acc) if side == "L" else _node(acc, sib)
    return acc.hex() == root_hex
