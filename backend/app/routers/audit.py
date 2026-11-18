# backend/app/routers/audit.py

from __future__ import annotations

from fastapi import APIRouter, Path

from app.services.audit_service import check_inclusion, get_alerts, get_board, get_liveness, inclusion_proof

router = APIRouter()


# ── GET /api/v1/audit/receipt/{ballot_hash} ────────────────────────────────


@router.get(
    "/audit/receipt/{ballot_hash}",
    summary="Verify a ballot receipt is included in the ledger",
    description=(
        "Anyone can check that a ballot_hash (the receipt handed back when the "
        "vote was cast) is recorded in the append-only ledger, and see which "
        "Merkle bundle seals it."
    ),
)
async def verify_receipt(
    ballot_hash: str = Path(..., min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$"),
):
    return await check_inclusion(ballot_hash)


# ── GET /api/v1/audit/proof/{ballot_hash} ──────────────────────────────────


@router.get(
    "/audit/proof/{ballot_hash}",
    summary="Merkle inclusion proof for a receipt, against the replica's published root",
    description=(
        "Returns the audit path (about log2(bundle size) sibling hashes) for the "
        "ballot with this receipt, and the root the air-gapped replica published "
        "for that bundle. The voter's device recomputes the root itself."
    ),
)
async def receipt_proof(
    ballot_hash: str = Path(..., min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$"),
):
    return await inclusion_proof(ballot_hash)


# ── GET /api/v1/audit/board ────────────────────────────────────────────────


@router.get(
    "/audit/board",
    summary="Public bulletin board",
    description=(
        "Total votes cast, the air-gapped replica's current Merkle root over "
        "the whole ledger, and every per-bundle root it has sealed. This is the "
        "public, operator-independent proof of integrity."
    ),
)
async def bulletin_board():
    return await get_board()


# ── GET /api/v1/audit/liveness ─────────────────────────────────────────────


@router.get(
    "/audit/liveness",
    summary="Replica liveness (nonce-bound protocol, Algorithm 5)",
    description="LIVE when the replica's commitment C' matches the primary's C for the "
                "latest decided nonce round, STALE when C' is missing after τ seconds, "
                "DIVERGED when C' differs.",
)
async def replica_liveness():
    return await get_liveness()


# ── GET /api/v1/audit/alerts ───────────────────────────────────────────────


@router.get("/audit/alerts", summary="Forensic integrity alerts raised by the replica")
async def integrity_alerts():
    return await get_alerts()
