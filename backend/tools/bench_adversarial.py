#!/usr/bin/env python3
# backend/tools/bench_adversarial.py
"""
Section 5.10 — Adversarial tests against the live system (all measured).
───────────────────────────────────────────────────────────────────────────────

  1. REPLAY       one valid ballot is accepted, then the identical package is
                  re-submitted 1,000 times. Every replay must be rejected (409).
  2. FORGERIES    100 submissions of each forgery type, each built from an
                  otherwise valid package:
                    unknown ticket · proof made for another ticket ·
                    tampered proof · signature by the wrong device key ·
                    stale timestamp
                  Every one must be rejected, and the voter's real ticket must
                  remain usable afterwards.
  3. DOUBLE VOTE  50 simultaneous submissions of one ticket: exactly one wins.

Mixed adversarial load (10% / 50% invalid traffic against a fixed legitimate
rate) is measured by `tools.bench_load mix`; offline Merkle bisection by
`tools.run_all_benchmarks_real`; live tamper detection by `tools.bench_integrity`.

Run inside the backend container:  python -m tools.bench_adversarial
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import sys
import time

import httpx
import redis.asyncio as aioredis

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tools import ballot_factory as bf   # noqa: E402

BASE = os.environ.get("LOADTEST_URL", "http://localhost:8000")
REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
BULLETIN_URL = os.environ.get("BULLETIN_URL", "redis://bulletin:6379/0")
OUT_DIR = os.environ.get("RESULTS_DIR", "/app/paper/results/docker")


def pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(len(xs) * p))] * 1000 if xs else None


async def cast(client, body):
    t0 = time.perf_counter()
    r = await client.post("/api/v1/vote/cast", json=body)
    return r.status_code, time.perf_counter() - t0


async def main():
    r = aioredis.from_url(REDIS_URL, decode_responses=True)
    bb = aioredis.from_url(BULLETIN_URL, decode_responses=True)
    pkgs = bf.make_packages(await bf.election_n_hex(bb), 700, k=2)
    await bf.seed_tickets(r, pkgs)
    report = {}
    print("=== Section 5.10 — Adversarial tests (live system, full Algorithm 1) ===")
    async with httpx.AsyncClient(base_url=BASE, timeout=30.0,
                                 limits=httpx.Limits(max_connections=100, max_keepalive_connections=100)) as c:
        # 1. replay
        p = pkgs[0]
        body = p.body()
        first, _ = await cast(c, body)
        lat, rej = [], 0
        for _ in range(1000):
            s, dt = await cast(c, body)
            lat.append(dt)
            rej += s == 409
        report["replay"] = {"first_status": first, "attempts": 1000, "rejected": rej,
                            "mean_ms": sum(lat) / len(lat) * 1000, "p50_ms": pct(lat, .5), "p99_ms": pct(lat, .99)}
        print(f"\n[1] REPLAY: first cast {first}; replays rejected {rej}/1000; "
              f"latency mean {report['replay']['mean_ms']:.2f} ms, p99 {report['replay']['p99_ms']:.2f} ms")

        # 2. forgeries (100 each), victims' real tickets must survive
        print("\n[2] FORGERIES (100 of each type)")
        victims = pkgs[1:101]
        donors = pkgs[101:201]
        types = {
            "unknown_ticket": lambda v, d: {**v.body(), "uti": secrets.token_hex(32)},
            "proof_for_other_ticket": lambda v, d: {**d.body(), "uti": v.uti},
            "tampered_proof": lambda v, d: v.body(tamper="proof"),
            "wrong_device_key": lambda v, d: v.body(tamper="signature"),
            "stale_timestamp": lambda v, d: v.body(tamper="timestamp"),
        }
        report["forgeries"] = {}
        for name, build in types.items():
            lat, codes = [], []
            for v, d in zip(victims, donors):
                s, dt = await cast(c, build(v, d))
                lat.append(dt)
                codes.append(s)
            rejected = sum(s in (400, 409, 422) for s in codes)
            report["forgeries"][name] = {"sent": 100, "rejected": rejected,
                                         "status_counts": {str(s): codes.count(s) for s in set(codes)},
                                         "mean_ms": sum(lat) / len(lat) * 1000, "p99_ms": pct(lat, .99)}
            print(f"    {name:<24} rejected {rejected}/100   mean {sum(lat)/len(lat)*1000:6.2f} ms   "
                  f"codes {report['forgeries'][name]['status_counts']}")
        ok = 0
        for v in victims:
            s, _ = await cast(c, v.body())
            ok += s == 201
        report["victims_could_still_vote"] = ok
        print(f"    real tickets still usable after all forgeries: {ok}/100")

        # 3. concurrent double vote
        p = pkgs[300]
        body = p.body()
        results = await asyncio.gather(*[cast(c, dict(body)) for _ in range(50)])
        wins = sum(s == 201 for s, _ in results)
        report["double_vote"] = {"concurrent": 50, "accepted": wins,
                                 "rejected_409": sum(s == 409 for s, _ in results)}
        print(f"\n[3] DOUBLE VOTE: 50 simultaneous submissions of one ticket -> {wins} accepted, "
              f"{report['double_vote']['rejected_409']} rejected")

    allok = (report["replay"]["rejected"] == 1000 and report["replay"]["first_status"] == 201
             and all(v["rejected"] == 100 for v in report["forgeries"].values())
             and report["victims_could_still_vote"] == 100 and report["double_vote"]["accepted"] == 1)
    report["all_defences_held"] = allok
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(os.path.join(OUT_DIR, "adversarial.json"), "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n{'All adversarial defences held.' if allok else 'CHECK: a defence did not hold — see adversarial.json'}")
    await r.aclose()
    await bb.aclose()


if __name__ == "__main__":
    asyncio.run(main())
