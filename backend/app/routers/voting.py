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
    StaleTimestampError,
    InvalidProofError,
    InvalidSignatureError,
    LockdownError,
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
    Checks timestamp freshness (400), ticket validity (409), the ballot-validity
    ZKP (422) and the device signature (422) before atomically consuming the
    ticket with Redis GETDEL and appending the anonymous ballot to the Pulsar
    ledger. Returns the receipt: ballot_id, ballot_hash, sequence_no.
    """
    try:
        receipt = await ingest_vote(
            uti=body.uti,
            ciphertext=body.ciphertext,
            zkp_proof=body.zkp_proof,
            num_candidates=body.num_candidates,
            ts=body.ts,
            signature=body.signature,
        )
    except StaleTimestampError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "STALE_TIMESTAMP",
                    "message": "Ballot timestamp is outside the permitted skew."},
        )
    except InvalidProofError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "INVALID_PROOF",
                    "message": "The ballot-validity proof does not verify."},
        )
    except InvalidSignatureError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "INVALID_SIGNATURE",
                    "message": "The device signature does not verify for this ticket."},
        )
    except LockdownError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "FORENSIC_LOCKDOWN",
                    "message": "Ingestion is halted while a forensic integrity alert is investigated."},
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
