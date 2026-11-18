# backend/app/pulsar_client.py
"""
Pulsar / BookKeeper client — the append-only vote ledger.
─────────────────────────────────────────────────────────

Every accepted ballot is written here as one immutable message. Apache Pulsar
(backed by BookKeeper) gives us an *append-only* log: messages can be added and
read in order, but never edited or deleted in place. That is exactly the
property an election ledger needs.

Why Pulsar and not a blockchain:
  • No global consensus round per vote → thousands of writes/second, not ~2–3.
  • Durability comes from BookKeeper's write quorum (several bookies must
    acknowledge each entry), not from miners. See WRITE QUORUM note below.

The official pulsar-client is a *synchronous* C++-backed library. Calling it
directly would block FastAPI's async event loop, so every blocking call is
pushed onto a thread pool with run_in_executor.

The import of `pulsar` is lazy (inside functions) so this module stays
importable — and the registration/liveness flow keeps working — even in an
environment where the Pulsar client or broker is not present.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

from app.config import get_settings

settings = get_settings()
logger = logging.getLogger(__name__)

# One topic holds the entire ordered ballot ledger.
BALLOT_TOPIC = "persistent://public/default/ballots"

# ── WRITE QUORUM (BookKeeper persistence policy) ───────────────────────────
# Documented here for the paper's methodology section. On a real multi-bookie
# cluster these are set at the namespace level via the Pulsar admin API:
#     Ensemble (E)      = 3   # entry is striped across 3 bookies
#     Write Quorum (Qw) = 2   # each entry written to 2 bookies
#     Ack Quorum (Qa)   = 2   # 2 acks required before the write is confirmed
# With E=3, Qw=2, Qa=2 the ledger tolerates the loss of one bookie with zero
# data loss and no write stall. Pulsar *standalone* runs a single bookie, so
# these values only take effect on the clustered deployment used for the
# scalability and fault-tolerance experiments.
BK_ENSEMBLE = 3
BK_WRITE_QUORUM = 2
BK_ACK_QUORUM = 2

_client = None
_producer = None
_lock = asyncio.Lock()


def _connect_sync():
    """
    Create a Pulsar client and producer. BLOCKING — must run in a thread.
    """
    import pulsar

    client = pulsar.Client(
        settings.pulsar_url,
        operation_timeout_seconds=15,
    )
    producer = client.create_producer(
        BALLOT_TOPIC,
        # Batching many ballots into one network/disk op is the main throughput
        # lever at high vote rates.
        batching_enabled=True,
        batching_max_publish_delay_ms=10,
        batching_max_messages=1000,
        # Never drop a vote because a local queue filled — apply backpressure.
        block_if_queue_full=True,
        max_pending_messages=10000,
        # Shrink the on-disk ledger; SHA-256 hashes and ciphertext compress well.
        compression_type=pulsar.CompressionType.LZ4,
    )
    return client, producer


async def get_producer():
    """Return the shared ledger producer, connecting lazily on first use."""
    global _client, _producer
    if _producer is not None:
        return _producer
    async with _lock:
        if _producer is None:
            loop = asyncio.get_event_loop()
            _client, _producer = await loop.run_in_executor(None, _connect_sync)
            logger.info("Pulsar producer connected → %s", BALLOT_TOPIC)
    return _producer


async def publish_ballot(payload: bytes, partition_key: Optional[str] = None) -> str:
    """
    Append one sealed ballot to the append-only ledger. Returns the Pulsar
    message id (as a string) once the write is durably acknowledged.

    Uses Pulsar's ASYNC send: the write is handed to the client's I/O layer and
    this coroutine awaits a Future that the Pulsar callback resolves. Thousands
    of writes can be in flight at once (the producer batches them), instead of
    each one blocking a scarce thread-pool worker until the broker acks.

    Still raises on failure so the caller can REFUSE the vote rather than let it
    be silently lost. A vote the ledger did not confirm is not a cast vote.
    """
    import pulsar

    producer = await get_producer()
    loop = asyncio.get_event_loop()
    fut: asyncio.Future = loop.create_future()

    def _on_done(res, msg_id):
        # Runs on a Pulsar client thread — hop back onto the event loop.
        if res == pulsar.Result.Ok:
            loop.call_soon_threadsafe(fut.set_result, str(msg_id))
        else:
            loop.call_soon_threadsafe(
                fut.set_exception, RuntimeError(f"pulsar send failed: {res}")
            )

    producer.send_async(payload, _on_done, partition_key=partition_key or "")
    return await fut


def _subscribe_sync(subscription_name: str, from_earliest: bool = True):
    """
    Create a consumer for the ballot ledger. BLOCKING — run in a thread.
    Used by the air-gapped forensic replica to re-read every ballot in order.
    """
    import pulsar

    client = pulsar.Client(settings.pulsar_url, operation_timeout_seconds=15)
    consumer = client.subscribe(
        BALLOT_TOPIC,
        subscription_name,
        consumer_type=pulsar.ConsumerType.Exclusive,
        initial_position=(
            pulsar.InitialPosition.Earliest
            if from_earliest
            else pulsar.InitialPosition.Latest
        ),
    )
    return client, consumer


async def close_pulsar():
    """Gracefully close the producer and client on shutdown."""
    global _client, _producer
    loop = asyncio.get_event_loop()
    if _producer is not None:
        await loop.run_in_executor(None, _producer.close)
        _producer = None
    if _client is not None:
        await loop.run_in_executor(None, _client.close)
        _client = None
    logger.info("Pulsar producer closed.")
