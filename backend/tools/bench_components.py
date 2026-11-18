#!/usr/bin/env python3
# backend/tools/bench_components.py
"""
Component-level diagnostic: measure each piece of the vote path in isolation,
so we know which one is the bottleneck instead of guessing.

Run inside the backend container:
    docker compose exec backend python tools/bench_components.py

It times, separately:
  1. Redis one-time-ticket ops (GETDEL) — the atomic-ingestion primitive.
  2. Pulsar async publish — the durable append-only ledger write.
  3. SHA-256 ballot hashing — the CPU work per vote.

Whichever is slowest is the ceiling the full system runs into.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import secrets
import time

import redis.asyncio as aioredis


async def bench_redis(n: int = 20000) -> None:
    url = os.environ.get("REDIS_URL", "redis://redis:6379/0")
    r = aioredis.from_url(url, decode_responses=True)

    keys = [f"bench_ticket:{secrets.token_hex(16)}" for _ in range(n)]
    pipe = r.pipeline(transaction=False)
    for k in keys:
        pipe.set(k, "1")
    await pipe.execute()

    t0 = time.perf_counter()
    # GETDEL each key (the real atomic-ingestion op), pipelined in chunks
    CHUNK = 500
    for i in range(0, n, CHUNK):
        pipe = r.pipeline(transaction=False)
        for k in keys[i:i + CHUNK]:
            pipe.getdel(k)
        await pipe.execute()
    dt = time.perf_counter() - t0
    await r.aclose()
    print(f"[Redis ]  {n:,} GETDEL ops in {dt:.2f}s  ->  {n/dt:,.0f} ops/sec")


def bench_hash(n: int = 100000) -> None:
    payload = secrets.token_bytes(400)
    t0 = time.perf_counter()
    for _ in range(n):
        hashlib.sha256(payload).hexdigest()
    dt = time.perf_counter() - t0
    print(f"[SHA256]  {n:,} ballot hashes in {dt:.2f}s  ->  {n/dt:,.0f} hashes/sec")


async def bench_pulsar(n: int = 20000) -> None:
    try:
        import pulsar
    except Exception as e:
        print(f"[Pulsar]  pulsar-client not available: {e}")
        return

    url = os.environ.get("PULSAR_URL", "pulsar://pulsar:6650")
    client = pulsar.Client(url, operation_timeout_seconds=30)
    producer = client.create_producer(
        "persistent://public/default/bench",
        batching_enabled=True,
        batching_max_publish_delay_ms=10,
        batching_max_messages=1000,
        block_if_queue_full=True,
        max_pending_messages=50000,
    )

    loop = asyncio.get_event_loop()
    done = 0
    fail = 0
    fut_all = loop.create_future()

    def on_done(res, msg_id):
        nonlocal done, fail
        if res == pulsar.Result.Ok:
            done += 1
        else:
            fail += 1
        if done + fail == n and not fut_all.done():
            loop.call_soon_threadsafe(fut_all.set_result, True)

    payload = secrets.token_bytes(400)
    t0 = time.perf_counter()
    for _ in range(n):
        producer.send_async(payload, on_done)
    await fut_all
    dt = time.perf_counter() - t0

    producer.close()
    client.close()
    print(f"[Pulsar]  {n:,} async publishes in {dt:.2f}s  ->  {n/dt:,.0f} writes/sec "
          f"(failed={fail})")


async def main() -> None:
    print("=== Component ceilings on THIS machine (no API in the path) ===")
    bench_hash()
    await bench_redis()
    await bench_pulsar()
    print("The slowest line is the ceiling the whole system is pinned to.")


if __name__ == "__main__":
    asyncio.run(main())
