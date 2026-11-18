# backend/app/workers/ledger_worker.py
"""
Ledger worker — materialises the primary vote ledger in PostgreSQL.
───────────────────────────────────────────────────────────────────────────────

Consumes the ballot topic through its own durable subscription and appends
every ballot, in ledger order, to the `vote_ledger` table: the store the
primary system serves and tallies from. Ballots are de-duplicated by their
SHA-256 hash (the same key the replica uses), so redelivery after a crash can
never shift positions between the primary ledger and the replica.

This table is mutable by anyone with database access — which is exactly the
insider threat the forensic replica exists to detect.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import time

from app.workers.common import BALLOT_TOPIC, SCHEMA, connect_db

logging.basicConfig(level=logging.INFO, format="%(asctime)s ledger-worker %(levelname)s %(message)s")
log = logging.getLogger("ledger-worker")

async def main() -> None:
    import pulsar

    conn = await connect_db()
    await conn.execute(SCHEMA)
    client = pulsar.Client(os.environ.get("PULSAR_URL", "pulsar://pulsar:6650"), operation_timeout_seconds=30)
    consumer = client.subscribe(BALLOT_TOPIC, subscription_name="ledger-worker",
                                consumer_type=pulsar.ConsumerType.Exclusive,
                                initial_position=pulsar.InitialPosition.Earliest)
    loop = asyncio.get_running_loop()
    log.info("ledger worker started: %s -> vote_ledger", BALLOT_TOPIC)

    def receive_batch():
        msgs = []
        deadline = None
        while len(msgs) < 500:
            wait = 500 if not msgs else max(1, int((deadline - time.monotonic()) * 1000))
            try:
                msgs.append(consumer.receive(timeout_millis=wait))
            except Exception:
                break
            if deadline is None:
                deadline = time.monotonic() + 0.05
            elif time.monotonic() >= deadline:
                break
        return msgs

    while True:
        msgs = await loop.run_in_executor(None, receive_batch)
        if not msgs:
            continue
        now = time.time()
        rows = [(hashlib.sha256(m.data()).hexdigest(), m.data().decode(), now) for m in msgs]
        await conn.executemany(
            "INSERT INTO vote_ledger (ballot_hash, payload, received_at) VALUES ($1, $2, $3) "
            "ON CONFLICT (ballot_hash) DO NOTHING", rows)
        for m in msgs:
            consumer.acknowledge(m)


if __name__ == "__main__":
    asyncio.run(main())
