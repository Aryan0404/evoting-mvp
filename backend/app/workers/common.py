# backend/app/workers/common.py
"""Shared constants and the state commitment used by the primary and the replica."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
from typing import List

from app.services.merkle_service import MerkleTree

BALLOT_TOPIC = os.environ.get("BALLOT_TOPIC", "persistent://public/default/ballots")
# One-way stream from the primary system to the air-gapped replica (the data diode).
DIODE_TOPIC = os.environ.get("DIODE_TOPIC", "persistent://public/default/diode-primary")
BUNDLE_SIZE = int(os.environ.get("BUNDLE_SIZE", "10000"))
CYCLE_SECONDS = float(os.environ.get("INTEGRITY_INTERVAL", "5"))


def pg_dsn(url: str) -> str:
    return url.replace("postgresql+asyncpg://", "postgresql://")


def bundle_roots(leaves: List[bytes], bundle_size: int = BUNDLE_SIZE) -> List[dict]:
    """Split leaves into bundles of `bundle_size`; Merkle root of each (Algorithm 2)."""
    out = []
    for b, start in enumerate(range(0, len(leaves), bundle_size)):
        chunk = leaves[start:start + bundle_size]
        out.append({"b": b, "count": len(chunk), "root": MerkleTree(chunk).root_hex()})
    return out


def state_commitment(leaves: List[bytes], bundle_size: int = BUNDLE_SIZE) -> str:
    """S: the ledger state — SHA-256 over (count, root) of every bundle, in order."""
    h = hashlib.sha256(len(leaves).to_bytes(8, "big"))
    for e in bundle_roots(leaves, bundle_size):
        h.update(e["count"].to_bytes(4, "big"))
        h.update(bytes.fromhex(e["root"]))
    return h.hexdigest()


def nonce_commitment(state_hex: str, nonce_hex: str) -> str:
    """C = H(S ∥ N)  (Algorithm 5)."""
    return hashlib.sha256(bytes.fromhex(state_hex) + bytes.fromhex(nonce_hex)).hexdigest()


SCHEMA = """
CREATE TABLE IF NOT EXISTS vote_ledger (
    seq          BIGSERIAL PRIMARY KEY,
    ballot_hash  TEXT UNIQUE NOT NULL,
    payload      TEXT NOT NULL,
    received_at  DOUBLE PRECISION NOT NULL
)"""


async def connect_db():
    import asyncpg
    dsn = pg_dsn(os.environ["DATABASE_URL"])
    for _ in range(60):
        try:
            return await asyncpg.connect(dsn)
        except Exception as exc:
            logging.getLogger("workers").info("waiting for database: %s", exc)
            await asyncio.sleep(2)
    raise SystemExit("database unreachable")
