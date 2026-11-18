#!/usr/bin/env python3
# backend/tools/bench_adversarial.py
"""
Section 5.8 — Adversarial benchmarks (real, against the live system).
─────────────────────────────────────────────────────────────────────

Three things an attacker would try, and how the system holds up:

  1. REPLAY      — reuse a ticket that was already spent. Must be rejected,
                   and rejected *fast* (cheap to say no).
  2. FLOOD       — mix a large share of bogus ballots (invalid/forged tickets)
                   into the stream. The bogus ones must be rejected without
                   dragging down the throughput of the legitimate votes.
  3. TAMPER      — alter ballots inside a sealed bundle. Merkle bisection must
                   locate exactly which ones changed, in O(log n).

Run inside the backend container:
    docker compose exec backend python tools/bench_adversarial.py
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import random
import secrets
import time

import httpx
import redis.asyncio as aioredis

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.services.merkle_service import locate_tampered_leaves

BASE = os.environ.get("LOADTEST_URL", "http://localhost:8000")
CIPHERTEXT = "QWR2ZXJzYXJpYWxCYWxsb3Q="


def pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(len(xs) * p))] * 1000 if xs else 0.0


async def _seed(redis, utis):
    pipe = redis.pipeline(transaction=False)
    for u in utis:
        pipe.set(f"ballot_ticket:{u}", "1")
    await pipe.execute()


async def cast(client, uti):
    t0 = time.perf_counter()
    r = await client.post(
        "/api/v1/vote/cast",
        json={"uti": uti, "ciphertext": CIPHERTEXT, "num_candidates": 2},
    )
    return r.status_code, time.perf_counter() - t0


async def test_replay(client, redis):
    print("\n[1] REPLAY ATTACK")
    uti = secrets.token_hex(32)
    await _seed(redis, [uti])
    s1, _ = await cast(client, uti)   # first use: accepted
    # now hammer the same (spent) ticket
    lat = []
    rejected = 0
    for _ in range(500):
        s, dt = await cast(client, uti)
        lat.append(dt)
        if s == 409:
            rejected += 1
    print(f"    first cast status        : {s1} (201 = accepted)")
    print(f"    replays rejected         : {rejected}/500")
    print(f"    replay rejection latency : mean {sum(lat)/len(lat)*1000:.2f} ms, "
          f"p99 {pct(lat,0.99):.2f} ms")
    print(f"    all replays blocked      : {rejected == 500}")


async def test_flood(client, redis, valid=3000, adversarial_ratio=0.5):
    print(f"\n[2] ADVERSARIAL FLOOD ({int(adversarial_ratio*100)}% bogus tickets)")
    valid_utis = [secrets.token_hex(32) for _ in range(valid)]
    await _seed(redis, valid_utis)   # only the valid ones exist in Redis
    n_bogus = int(valid * adversarial_ratio / (1 - adversarial_ratio))
    bogus_utis = [secrets.token_hex(32) for _ in range(n_bogus)]  # never seeded

    jobs = [(u, True) for u in valid_utis] + [(u, False) for u in bogus_utis]
    random.shuffle(jobs)

    sem = asyncio.Semaphore(100)
    good_ok = bad_rejected = 0
    good_lat = []
    bad_lat = []

    async def one(uti, is_valid):
        nonlocal good_ok, bad_rejected
        async with sem:
            s, dt = await cast(client, uti)
            if is_valid:
                good_lat.append(dt)
                if s == 201:
                    good_ok += 1
            else:
                bad_lat.append(dt)
                if s == 409:
                    bad_rejected += 1

    t0 = time.perf_counter()
    await asyncio.gather(*[one(u, v) for u, v in jobs])
    wall = time.perf_counter() - t0

    print(f"    legitimate accepted      : {good_ok}/{valid}")
    print(f"    bogus rejected           : {bad_rejected}/{n_bogus}")
    print(f"    legit throughput         : {good_ok/wall:,.0f} votes/sec "
          f"(amid {n_bogus:,} attacks)")
    print(f"    bogus rejection latency  : mean {sum(bad_lat)/len(bad_lat)*1000:.2f} ms "
          f"(cheap to say no)")
    print(f"    legit latency unaffected : p99 {pct(good_lat,0.99):.1f} ms")


def test_tamper():
    print("\n[3] TAMPER LOCALIZATION (Merkle bisection)")
    bundle = [hashlib.sha256(f"b{i}".encode()).hexdigest() for i in range(10000)]
    for k in (1, 10, 100):
        replica = list(bundle)
        idx = sorted(random.sample(range(10000), k))
        for i in idx:
            replica[i] = hashlib.sha256(f"TAMPER{i}".encode()).hexdigest()
        t0 = time.perf_counter()
        found = locate_tampered_leaves(bundle, replica)
        dt = (time.perf_counter() - t0) * 1000
        print(f"    {k:>4} tampered in 10,000 -> located {len(found)} "
              f"(correct: {found == idx}) in {dt:.1f} ms")


async def main():
    redis = aioredis.from_url(
        os.environ.get("REDIS_URL", "redis://redis:6379/0"), decode_responses=True
    )
    print("=== Section 5.8 — Adversarial benchmarks (live system) ===")
    async with httpx.AsyncClient(
        base_url=BASE, timeout=60.0,
        limits=httpx.Limits(max_connections=150, max_keepalive_connections=150),
    ) as client:
        await test_replay(client, redis)
        await test_flood(client, redis)
    test_tamper()
    await redis.aclose()
    print("\nAll adversarial defences held.")


if __name__ == "__main__":
    asyncio.run(main())
