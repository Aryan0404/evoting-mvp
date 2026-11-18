# backend/app/routers/audit.py

from __future__ import annotations

from fastapi import APIRouter, Path

from app.services.audit_service import check_inclusion, get_board

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
