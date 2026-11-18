# backend/app/services/audit_service.py
"""
Public audit surface (the Bulletin Board).
──────────────────────────────────────────

Read-only views anyone can use to verify the election without trusting the
operator:
  • inclusion    — "is my ballot in the ledger?"  (by ballot_hash receipt)
  • board        — total votes + the current Merkle roots published by the
                   air-gapped replica (the tamper-proof fingerprints)

  • liveness     — Algorithm 5 verifier: compares the primary's commitment C
                   with the replica's C' for each nonce round
  • alerts       — integrity alerts raised by the replica (with the ledger
                   positions it localised)

The replica's outputs live on the bulletin board, a store separate from the
primary system; everything here only READS.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any

from app.redis_client import get_bulletin, get_redis
from app.services.ledger_service import BUNDLE_SIZE

LIVENESS_TAU = float(os.environ.get("LIVENESS_TAU", "15"))


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
    bundle_root = await (await get_bulletin()).get(f"bundle:{bundle_id}:root")
    return {
        "included": True,
        "ballot_hash": ballot_hash,
        "sequence_no": seq,
        "bundle_id": bundle_id,
        "bundle_sealed": bundle_root is not None,
        "bundle_root": bundle_root,
    }


async def inclusion_proof(ballot_hash: str) -> dict[str, Any]:
    """
    Merkle audit path for a receipt, checkable on the voter's own device.

    The path is built from the primary ledger (PostgreSQL), over exactly the
    first `count` leaves of the bundle that the air-gapped replica has
    published a root for, and the response carries that replica root. The
    device recomputes the root from its own receipt and the path and compares
    it with the replica's root, so a ledger operator who altered or dropped the
    voter's ballot cannot produce a path that matches. Leaves are re-hashed from
    the stored payloads (as the integrity service does), never taken from the
    stored ballot_hash column.
    """
    from sqlalchemy import text

    from app.database import engine
    from app.services.merkle_service import MerkleTree

    async with engine.connect() as conn:
        try:
            seq = (await conn.execute(text("SELECT seq FROM vote_ledger WHERE ballot_hash = :h"),
                                      {"h": ballot_hash})).scalar()
        except Exception:
            return {"included": False, "ballot_hash": ballot_hash, "reason": "LEDGER_NOT_READY"}
        if seq is None:
            return {"included": False, "ballot_hash": ballot_hash, "reason": "NOT_IN_LEDGER_YET"}
        pos = (await conn.execute(text("SELECT count(*) FROM vote_ledger WHERE seq <= :s"), {"s": seq})).scalar()
        b, idx = (pos - 1) // BUNDLE_SIZE, (pos - 1) % BUNDLE_SIZE

        published = await (await get_bulletin()).get(f"replica:bundle:{b}:root")
        if not published:
            return {"included": True, "ballot_hash": ballot_hash, "ledger_position": pos, "bundle_id": b,
                    "verified_by_replica": False, "reason": "REPLICA_NOT_CAUGHT_UP"}
        count_s, replica_root = published.split(":", 1)
        count = int(count_s)
        if idx >= count:
            return {"included": True, "ballot_hash": ballot_hash, "ledger_position": pos, "bundle_id": b,
                    "verified_by_replica": False, "reason": "REPLICA_NOT_CAUGHT_UP"}
        rows = await conn.execute(
            text("SELECT sha256(convert_to(payload, 'UTF8')) FROM vote_ledger "
                 "ORDER BY seq OFFSET :o LIMIT :l"),
            {"o": b * BUNDLE_SIZE, "l": count})
        leaves = [bytes(r[0]) for r in rows]

    tree = MerkleTree(leaves)
    return {
        "included": True,
        "ballot_hash": ballot_hash,
        "ledger_position": pos,
        "bundle_id": b,
        "leaf_index": idx,
        "bundle_count": count,
        "path": [{"side": side, "hash": h} for side, h in tree.inclusion_proof(idx)],
        "replica_root": replica_root,
        "primary_root": tree.root_hex(),
        "verified_by_replica": True,
    }


async def get_board() -> dict[str, Any]:
    """
    The public bulletin board: votes cast, the replica's verified count and
    state commitment, its status, sealed bundle roots, liveness and alerts.
    """
    redis = await get_redis()
    bb = await get_bulletin()
    total = int(await redis.get("ledger:seq") or 0)
    bundles = []
    cursor = 0
    while True:
        cursor, keys = await bb.scan(cursor, match="bundle:*:root", count=200)
        for k in keys:
            try:
                bundles.append({"bundle_id": int(k.split(":")[1]), "root": await bb.get(k)})
            except (IndexError, ValueError):
                continue
        if cursor == 0:
            break
    bundles.sort(key=lambda b: b["bundle_id"])
    alert = await bb.get("alert:active")
    return {
        "total_votes_cast": total,
        "primary_ballots_committed": int(await bb.get("primary:count") or 0),
        "replica_ballots_verified": int(await bb.get("replica:count") or 0),
        "replica_state": await bb.get("replica:state"),
        "replica_status": await bb.get("replica:status"),
        "replica_last_check": await bb.get("replica:last_check"),
        "bundle_size": BUNDLE_SIZE,
        "sealed_bundles": bundles,
        "liveness": await get_liveness(),
        "alert": json.loads(alert) if alert else None,
    }


def classify_round(r: dict, now: float, tau: float = LIVENESS_TAU) -> str:
    """Algorithm 5, lines 6–13, for one nonce round."""
    if not r or "C" not in r:
        return "UNKNOWN"
    if "Cp" in r:
        return "LIVE" if r["Cp"] == r["C"] else "DIVERGED"
    return "STALE" if now - float(r["t_primary"]) > tau else "PENDING"


async def get_liveness(window: int = 6) -> dict[str, Any]:
    """
    Status of the most recent nonce rounds. The replica is reported STALE when
    the newest round older than τ has no matching C', DIVERGED when C' ≠ C.
    """
    bb = await get_bulletin()
    latest = int(await bb.get("liveness:latest") or 0)
    now = time.time()
    rounds = []
    for rnd in range(max(1, latest - window + 1), latest + 1):
        r = await bb.hgetall(f"liveness:round:{rnd}")
        if r:
            rounds.append({"round": rnd, "status": classify_round(r, now),
                           "age_s": round(now - float(r["t_primary"]), 1)})
    decided = [r for r in rounds if r["status"] != "PENDING"]
    current = decided[-1]["status"] if decided else ("PENDING" if rounds else "UNKNOWN")
    return {"status": current, "tau_s": LIVENESS_TAU, "rounds": rounds}


async def get_alerts() -> dict[str, Any]:
    bb = await get_bulletin()
    active = await bb.get("alert:active")
    log = [json.loads(x) for x in await bb.lrange("alerts:log", -20, -1)]
    return {"active": json.loads(active) if active else None, "recent": log}
