# backend/app/services/audit_service.py
"""
Public audit surface (the Bulletin Board).
──────────────────────────────────────────

Read-only views anyone can use to verify the election without trusting the
operator:
  • inclusion    — "is my ballot in the ledger?"  (by ballot_hash receipt)
  • board        — total votes + the current Merkle roots published by the
                   air-gapped replica (the tamper-proof fingerprints)

Everything here only READS state that the ingestion path and the forensic
replica already wrote to Redis; it never mutates the ledger.
"""

from __future__ import annotations

from typing import Any

from app.redis_client import get_redis
from app.services.ledger_service import BUNDLE_SIZE


async def check_inclusion(ballot_hash: str) -> dict[str, Any]:
    """
    Verify a voter's receipt (ballot_hash) is recorded in the ledger, and
    report which bundle seals it and whether that bundle's Merkle root is
    published yet.
    """
    redis = await get_redis()
    seq = await redis.get(f"ballot:{ballot_hash}")
    if seq is None:
        return {"included": False, "ballot_hash": ballot_hash}

    seq = int(seq)
    bundle_id = (seq - 1) // BUNDLE_SIZE
    bundle_root = await redis.get(f"bundle:{bundle_id}:root")
    return {
        "included": True,
        "ballot_hash": ballot_hash,
        "sequence_no": seq,
        "bundle_id": bundle_id,
        "bundle_sealed": bundle_root is not None,
        "bundle_root": bundle_root,
    }


async def get_board() -> dict[str, Any]:
    """
    The public bulletin board: total votes cast, the replica's current root
    over the whole ledger, and the per-bundle Merkle roots it has sealed.
    """
    redis = await get_redis()

    total = await redis.get("ledger:seq")
    total = int(total) if total else 0

    replica_root = await redis.get("replica:root")
    replica_count = await redis.get("replica:count")
    last_check = await redis.get("replica:last_check")

    # Collect every sealed bundle root (bundle:<id>:root). Few keys in practice.
    bundles: list[dict[str, Any]] = []
    cursor = 0
    while True:
        cursor, keys = await redis.scan(cursor, match="bundle:*:root", count=200)
        for k in keys:
            try:
                bid = int(k.split(":")[1])
            except (IndexError, ValueError):
                continue
            bundles.append({"bundle_id": bid, "root": await redis.get(k)})
        if cursor == 0:
            break
    bundles.sort(key=lambda b: b["bundle_id"])

    return {
        "total_votes_cast": total,
        "replica_ballots_verified": int(replica_count) if replica_count else 0,
        "replica_current_root": replica_root,
        "replica_last_check": last_check,
        "bundle_size": BUNDLE_SIZE,
        "sealed_bundles": bundles,
        "integrity": "ok" if (replica_root is not None or total == 0) else "pending",
    }
