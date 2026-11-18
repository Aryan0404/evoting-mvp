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


class StaleTimestampError(Exception):
    """|now − ts| exceeds the permitted skew Δ (Algorithm 1, step 1)."""


class InvalidProofError(Exception):
    """The ballot-validity zero-knowledge proof does not verify (step 3)."""


class InvalidSignatureError(Exception):
    """The device signature does not verify against the ticket's key (step 4)."""


class LockdownError(Exception):
    """The forensic replica raised an integrity alert; ingestion is halted."""


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


_LOCKDOWN_CACHE = {"t": 0.0, "active": False}


async def _lockdown_active() -> bool:
    """Read the forensic-lockdown flag from the bulletin board (cached 0.5 s)."""
    import time as _t
    now = _t.monotonic()
    if now - _LOCKDOWN_CACHE["t"] > 0.5:
        try:
            from app.redis_client import get_bulletin
            bb = await get_bulletin()
            _LOCKDOWN_CACHE["active"] = bool(await bb.exists("alert:active"))
        except Exception:
            pass                       # bulletin unreachable: keep last known state
        _LOCKDOWN_CACHE["t"] = now
    return _LOCKDOWN_CACHE["active"]


def _verify_proof_sync(pp, ciphertext: str, zkp_proof: str, num_candidates: int, context: str) -> bool:
    from app.services import ballot_proof
    try:
        cts, proof = ballot_proof.decode(ciphertext, zkp_proof)
    except Exception:
        return False
    if len(cts) != num_candidates:
        return False
    return ballot_proof.verify_ballot(pp, cts, proof, context)


async def ingest_vote(
    uti: str,
    ciphertext: str,
    zkp_proof: Optional[str],
    num_candidates: int,
    ts: Optional[float] = None,
    signature: Optional[str] = None,
) -> dict[str, Any]:
    """
    Algorithm 1 — Atomic Vote Ingestion, in the order the manuscript specifies.

    1. Timestamp freshness: reject if |now − ts| > Δ.
    2. Ticket check: the ticket must exist and be unused (Redis GET). Its value
       is the device public key registered at enrolment.
    3. VerifyZKP: the ballot-validity proof must verify for this ballot,
       bound to the election and to this ticket's nullifier.
    4. VerifySig: the device signature over the package must verify against
       the ticket's registered key.
       (Plus: refuse new ballots while a forensic lockdown is active.)
    5. Atomic commit: GETDEL consumes the ticket — exactly one concurrent
       request can win it — then the ballot is appended to the ledger. If the
       append fails, the ticket is re-issued with the same key, so an
       infrastructure fault never disenfranchises a voter.
    6. Sequence number and receipt (VID) are assigned only after the append.

    Checks 1–4 run before the ticket is consumed, so a malformed or forged
    package can never burn a legitimate voter's ticket.
    """
    import asyncio
    import time as _t

    from app.services import device_sig
    from app.services.election_keys import get_public_params

    redis = await get_redis()
    nullifier = hashlib.sha256(uti.encode()).hexdigest()

    # ── 1. Timestamp freshness ────────────────────────────────────────────
    now = _t.time()
    if ts is None or abs(now - ts) > settings.ballot_max_skew_seconds:
        raise StaleTimestampError()

    # ── 2. Ticket must exist and be unused ────────────────────────────────
    device_pk = await redis.get(_ticket_key(uti))
    if device_pk is None:
        raise TicketInvalidError()

    # ── 3. Ballot-validity zero-knowledge proof ───────────────────────────
    if settings.verify_ballot_proofs:
        pp = await get_public_params()
        if pp is None or not zkp_proof:
            raise InvalidProofError()
        context = f"{settings.election_id}|{nullifier}"
        loop = asyncio.get_running_loop()
        ok = await loop.run_in_executor(
            None, _verify_proof_sync, pp, ciphertext, zkp_proof, num_candidates, context)
        if not ok:
            raise InvalidProofError()

    # ── 4. Device signature ───────────────────────────────────────────────
    if settings.verify_device_signatures:
        msg = device_sig.package_bytes(settings.election_id, uti, num_candidates,
                                       ciphertext, zkp_proof or "", ts)
        if device_pk == "1" or not signature or not device_sig.verify(device_pk, signature, msg):
            raise InvalidSignatureError()

    if await _lockdown_active():
        raise LockdownError()

    # ── 5. Atomic commit: consume the ticket exactly once ─────────────────
    if not await consume_ticket(uti):
        raise TicketInvalidError()       # a concurrent duplicate won the ticket

    ballot_id = uuid.uuid4()
    cast_at = datetime.now(tz=timezone.utc)
    ballot_core = {
        "ballot_id": str(ballot_id),
        "ciphertext": ciphertext,
        "zkp_proof": zkp_proof,
        "num_candidates": num_candidates,
        "ts": ts,
        "cast_at": cast_at.isoformat(),
        "nullifier": nullifier,
    }
    payload = canonical_ballot_bytes(ballot_core)
    ballot_hash = hashlib.sha256(payload).hexdigest()   # receipt = VID = Merkle leaf

    try:
        message_id = await pulsar_client.publish_ballot(payload, partition_key=ballot_hash)
    except Exception as exc:
        logger.error("Ledger append failed for ballot %s: %s", ballot_id, exc)
        await redis.set(_ticket_key(uti), device_pk, ex=settings.uti_ttl_seconds)
        raise LedgerUnavailableError() from exc

    # ── 6. Sequence number + inclusion index (post-append) ────────────────
    sequence_no = await redis.incr(LEDGER_SEQ_KEY)
    await redis.set(f"ballot:{ballot_hash}", sequence_no, ex=settings.uti_ttl_seconds)
    logger.info("Ballot %s appended (seq=%s, bundle=%s)", ballot_id, sequence_no,
                (sequence_no - 1) // BUNDLE_SIZE)

    return {
        "ballot_id": ballot_id,
        "ballot_hash": ballot_hash,
        "sequence_no": sequence_no,
        "ledger_message_id": message_id,
        "cast_at": cast_at,
    }
