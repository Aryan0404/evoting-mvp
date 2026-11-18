# backend/app/schemas/vote.py

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field


# ── Vote Casting ───────────────────────────────────────────────────────────


class CastVoteRequest(BaseModel):
    """
    POST /api/v1/vote/cast — request body.

    BALLOT SECRECY CONTRACT
    ───────────────────────
    The voter does NOT send their voter_id or aadhaar_id here. They send only:
      • uti        — the one-time ticket issued at the end of registration
      • ciphertext — the Paillier-encrypted ballot (server never sees the choice)

    The ticket proves the voter is eligible AND has not already voted, WITHOUT
    linking the sealed ballot back to a person. This decoupling is what gives
    the system ballot secrecy while still preventing double voting.
    """

    uti: str = Field(
        ...,
        min_length=64,
        max_length=64,
        pattern=r"^[0-9a-f]{64}$",
        description="64-char hex one-time ticket (UTI) issued at registration",
    )
    ciphertext: str = Field(
        ...,
        min_length=1,
        max_length=8192,
        description="Base64 Paillier-encrypted ballot. Opaque to the server.",
    )
    zkp_proof: Optional[str] = Field(
        default=None,
        max_length=8192,
        description=(
            "Base64 zero-knowledge proof that the ciphertext is a well-formed "
            "ballot (exactly one candidate selected). Optional in the MVP."
        ),
    )
    num_candidates: int = Field(
        default=2,
        ge=2,
        le=1000,
        description="Number of candidates in this election (for tally bookkeeping)",
    )


class CastVoteResponse(BaseModel):
    """POST /api/v1/vote/cast — 201 response. This is the voter's receipt."""

    ballot_id: uuid.UUID = Field(description="Server-assigned ballot identifier")
    ballot_hash: str = Field(
        min_length=64,
        max_length=64,
        description=(
            "SHA-256 of the sealed ballot. This is your receipt — keep it to "
            "later verify your vote is included in the public ledger."
        ),
    )
    sequence_no: int = Field(
        description="Position of this ballot in the append-only ledger"
    )
    ledger_message_id: str = Field(
        description="Pulsar message id confirming the durable, append-only write"
    )
    cast_at: datetime
    message: str = "Vote recorded. Keep your ballot_hash to verify inclusion."


# ── Error responses ────────────────────────────────────────────────────────


class TicketError(BaseModel):
    """POST /api/v1/vote/cast — 409 response."""

    error: Literal["TICKET_INVALID_OR_USED"] = "TICKET_INVALID_OR_USED"
    message: str = (
        "This ticket is invalid or has already been used to cast a vote."
    )


class LedgerUnavailableError(BaseModel):
    """POST /api/v1/vote/cast — 503 response."""

    error: Literal["LEDGER_UNAVAILABLE"] = "LEDGER_UNAVAILABLE"
    message: str = (
        "The vote ledger is temporarily unavailable. Your vote was NOT "
        "recorded and your ticket is still valid — please retry."
    )
