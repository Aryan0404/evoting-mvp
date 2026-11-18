# backend/app/routers/election.py
"""
Public election parameters for voter devices.

Everything here is public and comes from the bulletin board: the election
identifier, the trustees' Paillier public key n, the ordered candidate list
(slot i of the one-hot ballot is candidate i), the timestamp window Δ, and the
server clock so a phone with a wrong clock can still stamp packages that pass
the freshness check.
"""

from __future__ import annotations

import json
import time

from fastapi import APIRouter, HTTPException, status

from app.config import get_settings
from app.redis_client import get_bulletin

router = APIRouter()
settings = get_settings()

DEFAULT_CANDIDATES = [
    {"id": "cand_001", "name": "Candidate A", "party": "Party A", "symbol": "A"},
    {"id": "cand_002", "name": "Candidate B", "party": "Party B", "symbol": "B"},
    {"id": "cand_003", "name": "Candidate C", "party": "Party C", "symbol": "C"},
    {"id": "cand_004", "name": "Candidate D", "party": "Party D", "symbol": "D"},
]


@router.get("/election", summary="Public election parameters for voter devices")
async def election_parameters():
    bb = await get_bulletin()
    n_hex = await bb.get("election:public_n")
    if not n_hex:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "NO_ELECTION_KEY",
                    "message": "The trustees' key ceremony has not been run yet."},
        )
    raw = await bb.get("election:candidates")
    candidates = json.loads(raw) if raw else DEFAULT_CANDIDATES
    return {
        "election_id": settings.election_id,
        "public_n": n_hex,
        "key_bits": (int(n_hex, 16).bit_length() + 7) // 8 * 8,
        "threshold": int(await bb.get("election:threshold") or 0),
        "trustees": int(await bb.get("election:trustees") or 0),
        "num_candidates": len(candidates),
        "candidates": [{**c, "position": i + 1} for i, c in enumerate(candidates)],
        "max_skew_seconds": settings.ballot_max_skew_seconds,
        "server_time": time.time(),
    }
