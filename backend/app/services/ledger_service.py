# backend/app/services/ledger_service.py
"""
Algorithm 1 — Atomic Vote Ingestion.
────────────────────────────────────

This is the heart of the voting path. A vote is accepted only if a valid,
unused one-time ticket is presented, and that ticket is burned in the SAME
atomic step so a replayed or concurrent duplicate can never slip through.

The atomic primitive is Redis GETDEL: it reads a key and deletes it in one
indivisible operation. If two requests race with the same ticket, exactly one
receives the value and the other receives nil — so exactly one vote is
recorded. No locks, no consensus round, O(1).
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from app import pulsar_client
from app.config import get_settings
from app.redis_client import get_redis

settings = get_settings()
logger = logging.getLogger(__name__)

# ballot_ticket:{uti} -> "1"   (written at registration, consumed here)
BALLOT_TICKET_PREFIX = "ballot_ticket"
# monotonic counter giving each accepted ballot a human-readable position
LEDGER_SEQ_KEY = "ledger:seq"
# ballots per Merkle bundle (paper: n = 10,000, tree depth 14)
BUNDLE_SIZE = 10_000


class TicketInvalidError(Exception):
    """The ticket is missing or has already been used."""


class LedgerUnavailableError(Exception):
    """The durable ledger append failed; the vote must be refused."""


def _ticket_key(uti: str) -> str:
    return f"{BALLOT_TICKET_PREFIX}:{uti}"


def canonical_ballot_bytes(ballot: dict[str, Any]) -> bytes:
    """
    Deterministic JSON encoding of a ballot so its SHA-256 is reproducible by
    anyone — including the independent air-gapped replica. Sorted keys, no
    whitespace. The replica reads the same payload and recomputes the same leaf.
    """
    return json.dumps(ballot, sort_keys=True, separators=(",", ":")).encode()


async def consume_ticket(uti: str) -> bool:
    """
    Atomically consume a one-time ticket with Redis GETDEL.

    Returns True if the ticket was valid and is now burned, False if it was
    absent (invalid or already used). Keyed by the ticket's own secret value,
    so only a holder of the real ticket can ever burn it — an attacker who
    knows a victim's voter_id cannot grief them.
    """
    redis = await get_redis()
    consumed = await redis.getdel(_ticket_key(uti))
    return consumed is not None


async def ingest_vote(
    uti: str,
    ciphertext: str,
    zkp_proof: Optional[str],
    num_candidates: int,
) -> dict[str, Any]:
    """
    Full atomic vote ingestion pipeline.

    1. Atomically consume the one-time ticket (GETDEL). Reject if already used.
    2. Build the ANONYMOUS sealed ballot — no voter identity is attached.
       A nullifier (hash of the ticket) lets downstream stages prove the same
       ticket is never counted twice, without revealing who voted.
    3. Compute the ballot hash (SHA-256 of the canonical bytes) — this is both
       the voter's receipt and the Merkle leaf.
    4. Append the ballot to the Pulsar append-only ledger (durable).
    5. Only AFTER a confirmed append, assign a ledger sequence number and record
       the inclusion index. Assigning the number last means a failed append
       leaves no gap in the ledger.

    On ledger failure the ticket is re-issued so the voter is never
    disenfranchised by a transient infrastructure problem.
    """
    # ── 1. Atomic one-time ticket ─────────────────────────────────────────
    if not await consume_ticket(uti):
        raise TicketInvalidError()

    redis = await get_redis()

    # ── 2. Build the anonymous sealed ballot (the Pulsar payload) ─────────
    ballot_id = uuid.uuid4()
    cast_at = datetime.now(tz=timezone.utc)
    ballot_core = {
        "ballot_id": str(ballot_id),
        "ciphertext": ciphertext,
        "zkp_proof": zkp_proof,
        "num_candidates": num_candidates,
        "cast_at": cast_at.isoformat(),
        "nullifier": hashlib.sha256(uti.encode()).hexdigest(),
    }
    payload = canonical_ballot_bytes(ballot_core)

    # ── 3. Ballot hash = receipt = Merkle leaf (deterministic from payload) ─
    ballot_hash = hashlib.sha256(payload).hexdigest()

    # ── 4. Durable append to the append-only ledger ───────────────────────
    try:
        message_id = await pulsar_client.publish_ballot(
            payload, partition_key=ballot_hash
        )
    except Exception as exc:
        logger.error("Ledger append failed for ballot %s: %s", ballot_id, exc)
        # Re-issue the ticket so the voter can retry — never lose a vote.
        await redis.set(
            _ticket_key(uti), "1", ex=settings.uti_ttl_seconds
        )
        raise LedgerUnavailableError() from exc

    # ── 5. Assign sequence number + record inclusion index (post-append) ──
    sequence_no = await redis.incr(LEDGER_SEQ_KEY)
    # ballot_hash -> sequence_no, so an auditor can later prove inclusion.
    await redis.set(
        f"ballot:{ballot_hash}", sequence_no, ex=settings.uti_ttl_seconds
    )

    logger.info(
        "Ballot %s appended (seq=%s, bundle=%s)",
        ballot_id,
        sequence_no,
        (sequence_no - 1) // BUNDLE_SIZE,
    )
    return {
        "ballot_id": ballot_id,
        "ballot_hash": ballot_hash,
        "sequence_no": sequence_no,
        "ledger_message_id": message_id,
        "cast_at": cast_at,
    }
