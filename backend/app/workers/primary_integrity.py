# backend/app/workers/primary_integrity.py
"""
Primary integrity service — bundle roots and liveness nonces (Algorithms 2, 5).
───────────────────────────────────────────────────────────────────────────────

Every cycle (default 5 s):

  1. Re-hashes every ballot straight from the primary vote ledger
     (PostgreSQL computes SHA-256 over each stored payload), so any change an
     insider makes to a stored ballot changes the leaves and the roots.
  2. Builds the Merkle root of every bundle of n ballots (Algorithm 2).
  3. Samples a fresh nonce N, computes the state commitment S over all
     bundles and C = H(S ∥ N) (Algorithm 5).
  4. Sends {bundle roots, N, number of ballots covered} to the air-gapped
     replica over the one-way diode stream. Leaf hashes are included for any
     bundle whose root changed since the previous cycle, so the replica can
     localise a divergence by bisection (Algorithm 4) without ever asking.
  5. Publishes (N, C) and its bundle roots on the public bulletin board.

Nothing ever flows back from the replica to this service.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
import time

import redis.asyncio as aioredis

from app.workers.common import (BUNDLE_SIZE, CYCLE_SECONDS, DIODE_TOPIC, SCHEMA, bundle_roots,
                                connect_db, nonce_commitment, state_commitment)

logging.basicConfig(level=logging.INFO, format="%(asctime)s primary-integrity %(levelname)s %(message)s")
log = logging.getLogger("primary-integrity")

ROUND_TTL = 3600


async def main() -> None:
    import pulsar

    conn = await connect_db()
    await conn.execute(SCHEMA)
    bb = aioredis.from_url(os.environ.get("BULLETIN_URL", "redis://bulletin:6379/0"), decode_responses=True)
    client = pulsar.Client(os.environ.get("PULSAR_URL", "pulsar://pulsar:6650"), operation_timeout_seconds=30)
    producer = client.create_producer(DIODE_TOPIC, batching_enabled=False)
    rnd = int(await bb.get("liveness:latest") or 0)
    last = {}
    log.info("primary integrity service started: cycle %.1fs, bundle %d", CYCLE_SECONDS, BUNDLE_SIZE)

    while True:
        t0 = time.time()
        try:
            rows = await conn.fetch("SELECT sha256(convert_to(payload, 'UTF8')) AS h FROM vote_ledger ORDER BY seq")
            leaves = [bytes(r["h"]) for r in rows]
            bundles = bundle_roots(leaves)
            for e in bundles:
                key = (e["count"], e["root"])
                if last.get(e["b"]) != key:
                    s = e["b"] * BUNDLE_SIZE
                    e["leaves"] = b"".join(leaves[s:s + e["count"]]).hex()
                    last[e["b"]] = key
            S = state_commitment(leaves)
            N = secrets.token_hex(32)
            C = nonce_commitment(S, N)
            rnd += 1
            msg = {"type": "cycle", "round": rnd, "t_primary": t0, "upto": len(leaves), "N": N, "bundles": bundles}
            await asyncio.get_running_loop().run_in_executor(None, producer.send, json.dumps(msg).encode())
            pipe = bb.pipeline(transaction=False)
            pipe.hset(f"liveness:round:{rnd}", mapping={"N": N, "C": C, "upto": len(leaves), "t_primary": t0})
            pipe.expire(f"liveness:round:{rnd}", ROUND_TTL)
            pipe.set("liveness:latest", rnd)
            pipe.set("primary:count", len(leaves))
            pipe.set("primary:state", S)
            pipe.delete("primary:bundles")
            if bundles:
                pipe.hset("primary:bundles", mapping={str(e["b"]): f'{e["count"]}:{e["root"]}' for e in bundles})
            await pipe.execute()
        except Exception as exc:
            log.error("cycle failed: %s", exc)
        await asyncio.sleep(max(0.0, CYCLE_SECONDS - (time.time() - t0)))


if __name__ == "__main__":
    asyncio.run(main())
