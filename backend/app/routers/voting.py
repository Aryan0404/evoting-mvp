# backend/app/routers/voting.py

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status

from app.schemas.vote import (
    CastVoteRequest,
    CastVoteResponse,
    TicketError,
    LedgerUnavailableError as LedgerUnavailableSchema,
)
from app.services.ledger_service import (
    ingest_vote,
    TicketInvalidError,
    LedgerUnavailableError,
)

router = APIRouter()


# ── POST /api/v1/vote/cast ─────────────────────────────────────────────────


@router.post(
    "/vote/cast",
    status_code=status.HTTP_201_CREATED,
    response_model=CastVoteResponse,
    responses={
        409: {
            "model": TicketError,
            "description": "Ticket invalid or already used (double-vote blocked)",
        },
        503: {
            "model": LedgerUnavailableSchema,
            "description": "Ledger unavailable — vote not recorded, ticket still valid",
        },
    },
    summary="Cast an encrypted ballot",
    description=(
        "Atomically consumes the voter's one-time ticket and appends the "
        "Paillier-encrypted ballot to the append-only ledger. The request "
        "carries no voter identity — only the ticket and the ciphertext — so "
        "the ballot cannot be linked back to a person."
    ),
)
async def cast_vote(body: CastVoteRequest) -> CastVoteResponse:
    """
    Vote Casting Flow (Algorithm 1 — Atomic Vote Ingestion)
    ───────────────────────────────────────────────────────
    1. Atomically consume the one-time ticket (Redis GETDEL). If it is missing
       or already used, the vote is rejected with 409 — this is the double-vote
       defence.
    2. Seal the ballot (anonymous) and append it to the Pulsar ledger.
    3. Return the receipt: ballot_id, ballot_hash, sequence_no.
    """
    try:
        receipt = await ingest_vote(
            uti=body.uti,
            ciphertext=body.ciphertext,
            zkp_proof=body.zkp_proof,
            num_candidates=body.num_candidates,
        )
    except TicketInvalidError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": "TICKET_INVALID_OR_USED",
                "message": "This ticket is invalid or has already been used to cast a vote.",
            },
        )
    except LedgerUnavailableError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "LEDGER_UNAVAILABLE",
                "message": (
                    "The vote ledger is temporarily unavailable. Your vote was "
                    "NOT recorded and your ticket is still valid — please retry."
                ),
            },
        )

    return CastVoteResponse(
        ballot_id=receipt["ballot_id"],
        ballot_hash=receipt["ballot_hash"],
        sequence_no=receipt["sequence_no"],
        ledger_message_id=receipt["ledger_message_id"],
        cast_at=receipt["cast_at"],
    )
