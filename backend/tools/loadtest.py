#!/usr/bin/env python3
# backend/tools/loadtest.py
"""
Real load test for the vote-ingestion path (Section 5.4 / 5.2).
───────────────────────────────────────────────────────────────

Fires many real votes at the running backend and measures actual throughput
and latency — the honest replacement for the simulated scalability numbers.

Runs INSIDE the backend container (redis/httpx already installed, service
names resolve):

    docker compose exec backend python tools/loadtest.py
    docker compose exec backend python tools/loadtest.py --votes 20000 --concurrency 200
    docker compose exec backend python tools/loadtest.py --sweep
    docker compose exec backend python tools/loadtest.py --procs 6 --concurrency 100

Why --procs matters: a single async process (one core) cannot saturate a
multi-worker API — it becomes the bottleneck itself. --procs N spreads the
load generation across N OS processes (cores) so we measure the *system's*
ceiling, not the tester's. Default: one process.

Single-machine caveat: generator, API, Redis and Pulsar all share one laptop,
so this is a realistic single-node figure, not a multi-node cluster ceiling.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import secrets
import time
from concurrent.futures import ProcessPoolExecutor

import httpx
import redis.asyncio as aioredis

CIPHERTEXT = "QmFsbG90Q2lwaGVydGV4dFBsYWNlaG9sZGVyMDE="  # opaque to the server


def pct(sorted_vals, p):
    if not sorted_vals:
        return 0.0
    i = min(len(sorted_vals) - 1, int(len(sorted_vals) * p))
    return sorted_vals[i]


async def seed_tickets(redis, utis):
    pipe = redis.pipeline(transaction=False)
    for u in utis:
        pipe.set(f"ballot_ticket:{u}", "1")
    await pipe.execute()


async def run(votes, concurrency, candidates, base_url, verbose=True):
    redis_url = os.environ.get("REDIS_URL", "redis://redis:6379/0")
    redis = aioredis.from_url(redis_url, decode_responses=True)

    utis = [secrets.token_hex(32) for _ in range(votes)]
    if verbose:
        print(f"Seeding {votes:,} tickets into Redis ...")
    await seed_tickets(redis, utis)

    sem = asyncio.Semaphore(concurrency)
    latencies = []
    ok = 0
    failed = 0

    limits = httpx.Limits(
        max_connections=concurrency + 50,
        max_keepalive_connections=concurrency + 50,
    )
    async with httpx.AsyncClient(base_url=base_url, timeout=60.0, limits=limits) as client:
        async def cast(uti):
            nonlocal ok, failed
            body = {"uti": uti, "ciphertext": CIPHERTEXT, "num_candidates": candidates}
            async with sem:
                t0 = time.perf_counter()
                try:
                    r = await client.post("/api/v1/vote/cast", json=body)
                    latencies.append(time.perf_counter() - t0)
                    if r.status_code == 201:
                        ok += 1
                    else:
                        failed += 1
                except Exception:
                    failed += 1

        if verbose:
            print(f"Casting {votes:,} votes at concurrency {concurrency} ...")
        t_start = time.perf_counter()
        await asyncio.gather(*[cast(u) for u in utis])
        wall = time.perf_counter() - t_start

    await redis.aclose()

    latencies.sort()
    tps = ok / wall if wall else 0.0
    if verbose:
        print("\n================ RESULTS ================")
        print(f"votes attempted     : {votes:,}")
        print(f"accepted (201)      : {ok:,}")
        print(f"failed/rejected     : {failed:,}")
        print(f"wall time           : {wall:.2f} s")
        print(f"THROUGHPUT          : {tps:,.0f} votes/sec")
        print(f"latency p50         : {pct(latencies, 0.50)*1000:.1f} ms")
        print(f"latency p95         : {pct(latencies, 0.95)*1000:.1f} ms")
        print(f"latency p99         : {pct(latencies, 0.99)*1000:.1f} ms")
        print("=========================================")
    return {
        "concurrency": concurrency, "votes": votes, "accepted": ok,
        "failed": failed, "wall": round(wall, 2), "tps": round(tps, 1),
        "p50_ms": round(pct(latencies, 0.50) * 1000, 1),
        "p99_ms": round(pct(latencies, 0.99) * 1000, 1),
        "latencies": latencies,
    }


def _worker(args):
    votes, concurrency, candidates, url = args
    return asyncio.run(run(votes, concurrency, candidates, url, verbose=False))


def run_multiproc(total_votes, concurrency, candidates, url, procs):
    """Drive load from `procs` OS processes in parallel; aggregate the result."""
    per = max(1, total_votes // procs)
    print(f"Driving load from {procs} processes "
          f"({per:,} votes each, concurrency {concurrency} each) ...")
    t0 = time.perf_counter()
    with ProcessPoolExecutor(max_workers=procs) as ex:
        results = list(ex.map(_worker, [(per, concurrency, candidates, url)] * procs))
    wall = time.perf_counter() - t0

    accepted = sum(r["accepted"] for r in results)
    failed = sum(r["failed"] for r in results)
    all_lat = sorted(l for r in results for l in r["latencies"])
    agg_tps = accepted / wall if wall else 0.0
    print("\n============ AGGREGATE RESULTS ============")
    print(f"processes           : {procs}")
    print(f"total accepted      : {accepted:,}")
    print(f"total failed        : {failed:,}")
    print(f"wall time           : {wall:.2f} s")
    print(f"AGGREGATE THROUGHPUT: {agg_tps:,.0f} votes/sec")
    print(f"latency p50         : {pct(all_lat, 0.50)*1000:.1f} ms")
    print(f"latency p99         : {pct(all_lat, 0.99)*1000:.1f} ms")
    print("===========================================")
    print("Compare: Razaque blockchain baseline ~2-3 votes/sec.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--votes", type=int, default=5000)
    ap.add_argument("--concurrency", type=int, default=100)
    ap.add_argument("--candidates", type=int, default=2)
    ap.add_argument("--url", default="http://localhost:8000")
    ap.add_argument("--procs", type=int, default=1,
                    help="parallel load-generator processes (default 1)")
    ap.add_argument("--sweep", action="store_true",
                    help="run a concurrency sweep and print a scalability curve")
    args = ap.parse_args()

    if args.sweep:
        levels = [50, 100, 200, 400, 800]
        rows = []
        for c in levels:
            rows.append(asyncio.run(run(args.votes, c, args.candidates, args.url)))
        print("\n============ SCALABILITY CURVE ============")
        print(f"{'concurrency':>12} {'tps':>10} {'p50 ms':>9} {'p99 ms':>9} {'failed':>8}")
        for r in rows:
            print(f"{r['concurrency']:>12} {r['tps']:>10,.0f} "
                  f"{r['p50_ms']:>9} {r['p99_ms']:>9} {r['failed']:>8}")
        print("==========================================")
    elif args.procs > 1:
        run_multiproc(args.votes, args.concurrency, args.candidates, args.url, args.procs)
    else:
        asyncio.run(run(args.votes, args.concurrency, args.candidates, args.url))


if __name__ == "__main__":
    main()
