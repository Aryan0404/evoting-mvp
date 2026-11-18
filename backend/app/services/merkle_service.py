# backend/app/services/merkle_service.py
"""
Algorithm 2 — Merkle Bundle Construction
Algorithm 4 — Tamper Localization via Merkle Bisection
──────────────────────────────────────────────────────

Ballots are grouped into bundles of n = 10,000 leaves. Each bundle is hashed
into a binary SHA-256 Merkle tree (depth = ceil(log2(n)) = 14). The single
32-byte root commits to every ballot in the bundle: change one ballot and the
root changes.

Two capabilities built on the tree:
  • Inclusion proof — a voter proves their ballot_hash is in the published
    root using only log2(n) sibling hashes (≈14 hashes, not 10,000).
  • Tamper bisection — if a replica's recomputed root differs from the
    authoritative root, we find exactly which leaves changed in O(log n)
    comparisons instead of scanning all n leaves.

Everything here is pure and deterministic, so the air-gapped replica computes
byte-identical results from the same ballots.
"""

from __future__ import annotations

import hashlib
from typing import List, Tuple

LEFT = "L"
RIGHT = "R"


def _h(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _hash_pair(left: bytes, right: bytes) -> bytes:
    return _h(left + right)


class MerkleTree:
    """
    Binary SHA-256 Merkle tree over a list of leaf hashes (raw 32-byte digests).

    When a layer has an odd number of nodes, the last node is duplicated — the
    standard, widely-audited convention. An empty tree has the all-zero root.
    """

    def __init__(self, leaves: List[bytes]):
        self.leaves: List[bytes] = list(leaves)
        self.layers: List[List[bytes]] = []
        self._build()

    def _build(self) -> None:
        if not self.leaves:
            self.layers = [[b"\x00" * 32]]
            return
        layer = list(self.leaves)
        self.layers = [layer]
        while len(layer) > 1:
            if len(layer) % 2 == 1:
                layer = layer + [layer[-1]]  # duplicate last to make it even
            layer = [
                _hash_pair(layer[i], layer[i + 1])
                for i in range(0, len(layer), 2)
            ]
            self.layers.append(layer)

    @property
    def root(self) -> bytes:
        return self.layers[-1][0]

    def root_hex(self) -> str:
        return self.root.hex()

    @property
    def depth(self) -> int:
        return len(self.layers) - 1

    def inclusion_proof(self, index: int) -> List[Tuple[str, str]]:
        """
        Return the audit path for the leaf at `index`: a list of
        (side, sibling_hex) pairs from leaf level up to the root, where `side`
        tells the verifier whether the sibling sits on the Left or Right.
        """
        if not (0 <= index < len(self.leaves)):
            raise IndexError("leaf index out of range")

        proof: List[Tuple[str, str]] = []
        idx = index
        for level in range(self.depth):
            layer = self.layers[level]
            # mirror the odd-duplication used during build
            if len(layer) % 2 == 1:
                layer = layer + [layer[-1]]
            if idx % 2 == 0:  # node is a left child; sibling is on the right
                sibling = layer[idx + 1]
                proof.append((RIGHT, sibling.hex()))
            else:  # node is a right child; sibling is on the left
                sibling = layer[idx - 1]
                proof.append((LEFT, sibling.hex()))
            idx //= 2
        return proof


def verify_inclusion(
    leaf_hex: str, proof: List[Tuple[str, str]], root_hex: str
) -> bool:
    """
    Recompute the root from a leaf and its audit path; compare to the published
    root. This is what a voter (or auditor) runs to prove their ballot is in.
    """
    acc = bytes.fromhex(leaf_hex)
    for side, sibling_hex in proof:
        sibling = bytes.fromhex(sibling_hex)
        if side == RIGHT:
            acc = _hash_pair(acc, sibling)
        else:
            acc = _hash_pair(sibling, acc)
    return acc.hex() == root_hex


# ── Bundle helpers ─────────────────────────────────────────────────────────


def build_bundle_root(ballot_hashes_hex: List[str]) -> str:
    """Build a bundle's Merkle tree from ballot-hash hex strings; return root hex."""
    leaves = [bytes.fromhex(h) for h in ballot_hashes_hex]
    return MerkleTree(leaves).root_hex()


# ── Algorithm 4 — Tamper Localization via Merkle Bisection ─────────────────


def bisect_trees(primary: "MerkleTree", replica: "MerkleTree") -> Tuple[List[int], int]:
    """
    Algorithm 4 on two already-built trees of the same bundle size.

    Starts at the roots and descends only into children whose stored hashes
    differ, exactly as in the paper: no hashing is redone, so each tampered
    leaf costs at most 2·depth node comparisons — O(m · log n) for m tampered
    leaves. Returns (sorted tampered leaf indices, number of node comparisons).
    """
    if len(primary.leaves) != len(replica.leaves):
        raise ValueError("bundles must contain the same number of leaves")
    if not primary.leaves:
        return [], 0
    top = primary.depth
    comparisons = 1
    if primary.layers[top][0] == replica.layers[top][0]:
        return [], comparisons
    frontier = [0]                      # indices at the current level that differ
    for level in range(top, 0, -1):
        child_p = primary.layers[level - 1]
        child_r = replica.layers[level - 1]
        nxt = []
        for idx in frontier:
            for c in (2 * idx, 2 * idx + 1):
                if c >= len(child_p):  # odd-duplicated node: same as its sibling
                    continue
                comparisons += 1
                if child_p[c] != child_r[c]:
                    nxt.append(c)
        frontier = nxt
    return sorted(frontier), comparisons


def locate_tampered_leaves(
    authoritative: List[str], replica: List[str]
) -> List[int]:
    """
    Convenience wrapper: build both trees once (O(n)) from ballot-hash hex
    lists, then run the O(m · log n) descent of `bisect_trees`.
    """
    if len(authoritative) != len(replica):
        raise ValueError("bundles must contain the same number of leaves")
    if not authoritative:
        return []
    tp = MerkleTree([bytes.fromhex(x) for x in authoritative])
    tr = MerkleTree([bytes.fromhex(x) for x in replica])
    return bisect_trees(tp, tr)[0]
