#!/usr/bin/env python3
# backend/tools/bench_load.py
"""
Load engine for Sections 5.3, 5.6 and 5.10 — every vote fully valid.
───────────────────────────────────────────────────────────────────────────────

Each request is a complete Algorithm 1 package (one-hot Paillier ballot,
ballot-validity proof bound to its own ticket, fresh timestamp, ECDSA P-256
device signature), so the server performs the full ingestion checks.

Modes
  closed   N votes at fixed concurrency C — throughput ceiling.
  open     a fixed arrival rate R for D seconds (open loop: arrivals do not
           wait for responses), so latency reflects the offered load instead
           of queueing behind a fixed concurrency.
  sweep    open-loop runs at increasing rates — Section 5.6 scalability
           under increasing load (achieved throughput and latency vs load).
  mix      open-loop legitimate votes at rate R plus a fraction of invalid
           submissions (unknown ticket, replay, bad proof, bad signature,
           stale timestamp) — Section 5.10 adversarial load impact, compared
           against an attack-free baseline at the same legitimate rate.

Run inside the backend container, e.g.
  python -m tools.bench_load closed --votes 20000 --concurrency 100
  python -m tools.bench_load sweep --rates 50 100 150 200 250 300 --duration 30
  python -m tools.bench_load mix --rate 100 --duration 30 --invalid 0.1 0.5
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import random
import secrets
import sys
import time

import aiohttp
import redis.asyncio as aioredis

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tools import ballot_factory as bf   # noqa: E402

BASE = os.environ.get("LOADTEST_URL", "http://localhost:8000")
REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
BULLETIN_URL = os.environ.get("BULLETIN_URL", "redis://bulletin:6379/0")
OUT_DIR = os.environ.get("RESULTS_DIR", "/app/paper/results/docker")


def pct(xs, p):
    if not xs:
        return None
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(len(xs) * p))]


def summarise(lat, statuses, wall, accepted):
    return {
        "attempted": len(statuses), "accepted": accepted,
        "rejected_or_failed": len(statuses) - accepted,
        "status_counts": {str(k): statuses.count(k) for k in sorted(set(statuses))},
        "wall_s": round(wall, 2), "throughput_per_s": round(accepted / wall, 1) if wall else 0,
        "p50_ms": round(pct(lat, .5) * 1000, 1) if lat else None,
        "p95_ms": round(pct(lat, .95) * 1000, 1) if lat else None,
        "p99_ms": round(pct(lat, .99) * 1000, 1) if lat else None,
        "max_ms": round(max(lat) * 1000, 1) if lat else None,
        "errors": dict(ERROR_CODES),
    }


async def prepare(count, k):
    r = aioredis.from_url(REDIS_URL, decode_responses=True)
    bb = aioredis.from_url(BULLETIN_URL, decode_responses=True)
    n_hex = await bf.election_n_hex(bb)
    pkgs = bf.make_packages(n_hex, count, k=k)
    await bf.seed_tickets(r, pkgs)
    await r.aclose()
    await bb.aclose()
    return pkgs


def client(conns):
    """aiohttp, not httpx: httpx's connection pool assigns queued requests to
    connections by scanning both lists, which becomes quadratic with thousands
    of in-flight requests and stalled the 400 votes/s sweep on the client side.
    Every request has a 30 s total timeout and counts as status 0 if it fails."""
    return aiohttp.ClientSession(
        base_url=BASE,
        connector=aiohttp.TCPConnector(limit=conns, limit_per_host=conns),
        timeout=aiohttp.ClientTimeout(total=30.0),
    )


ERROR_CODES: dict = {}
TIMELINE: list = []      # (seconds since start, latency s, status) for legitimate votes   # "503 FORENSIC_LOCKDOWN" -> count, so every failure is explained


async def post(c, body):
    t0 = time.perf_counter()
    try:
        async with c.post("/api/v1/vote/cast", json=body) as resp:
            raw = await resp.read()
            code = resp.status
        if code != 201:
            try:
                d = json.loads(raw)
                d = d.get("detail", d)
                reason = d.get("error") if isinstance(d, dict) else str(d)[:40]
            except Exception:
                reason = raw[:40].decode(errors="replace") or "-"
            key = f"{code} {reason}"
            ERROR_CODES[key] = ERROR_CODES.get(key, 0) + 1
    except Exception as e:
        code = 0
        key = f"0 {type(e).__name__}"
        ERROR_CODES[key] = ERROR_CODES.get(key, 0) + 1
    return code, time.perf_counter() - t0


# ── closed loop ─────────────────────────────────────────────────────────────
async def closed(votes, concurrency, k):
    ERROR_CODES.clear()
    pkgs = await prepare(votes, k)
    sem = asyncio.Semaphore(concurrency)
    lat, st = [], []
    async with client(concurrency + 20) as c:
        async def one(p):
            async with sem:
                code, dt = await post(c, p.body())
                st.append(code)
                if code == 201:
                    lat.append(dt)
        t0 = time.perf_counter()
        await asyncio.gather(*[one(p) for p in pkgs])
        wall = time.perf_counter() - t0
    return summarise(lat, st, wall, st.count(201))


# ── open loop ───────────────────────────────────────────────────────────────
async def open_loop(rate, duration, k, invalid_frac=0.0, pkgs=None):
    ERROR_CODES.clear()
    TIMELINE.clear()
    n_legit = int(rate * duration)
    pkgs = pkgs or await prepare(n_legit + 50, k)
    legit, spare = pkgs[:n_legit], pkgs[n_legit:]
    replay_src = spare[0] if spare else None
    kinds = ["unknown_ticket", "replay", "bad_proof", "bad_signature", "stale_timestamp"]
    n_bad = int(n_legit * invalid_frac / (1 - invalid_frac)) if invalid_frac else 0
    events = [("legit", p) for p in legit] + [(kinds[i % len(kinds)], None) for i in range(n_bad)]
    random.shuffle(events)
    gap = duration / max(1, len(events))
    res = {"legit": ([], []), **{kk: ([], []) for kk in kinds}}

    async with client(2000) as c:
        if replay_src is not None and n_bad:
            await post(c, replay_src.body())                    # spend it once
        tasks = []

        async def fire(kind, p):
            if kind == "legit":
                body = p.body()
            elif kind == "unknown_ticket":
                q = random.choice(legit)
                body = q.body()
                body["uti"] = secrets.token_hex(32)
            elif kind == "replay":
                body = replay_src.body()
            else:
                q = random.choice(spare[1:] or legit)
                body = q.body(tamper={"bad_proof": "proof", "bad_signature": "signature",
                                      "stale_timestamp": "timestamp"}[kind])
            t_send = time.perf_counter() - t0
            code, dt = await post(c, body)
            res[kind][0].append(dt)
            res[kind][1].append(code)
            if kind == "legit":
                TIMELINE.append((t_send, dt, code))

        t0 = time.perf_counter()
        for j, (kind, p) in enumerate(events):
            delay = t0 + j * gap - time.perf_counter()
            if delay > 0:
                await asyncio.sleep(delay)
            tasks.append(asyncio.create_task(fire(kind, p)))
        await asyncio.gather(*tasks)
        wall = time.perf_counter() - t0

    lat, st = res["legit"]
    ok_lat = [l for l, s in zip(lat, st) if s == 201]
    out = {"offered_rate": rate, "duration_s": duration, "invalid_fraction": invalid_frac,
           "legit": summarise(ok_lat, st, wall, st.count(201))}
    if n_bad:
        out["invalid"] = {kk: {"sent": len(res[kk][1]),
                               "rejected": sum(1 for s in res[kk][1] if s in (400, 409, 422)),
                               "status_counts": {str(s): res[kk][1].count(s) for s in set(res[kk][1])},
                               "mean_ms": round(sum(res[kk][0]) / len(res[kk][0]) * 1000, 2) if res[kk][0] else None}
                          for kk in kinds}
    return out


def save(name, data):
    os.makedirs(OUT_DIR, exist_ok=True)
    path = os.path.join(OUT_DIR, name)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    return path


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="mode", required=True)
    a = sub.add_parser("closed"); a.add_argument("--votes", type=int, default=20000); a.add_argument("--concurrency", type=int, default=100)
    b = sub.add_parser("open"); b.add_argument("--rate", type=float, default=100); b.add_argument("--duration", type=float, default=60)
    s = sub.add_parser("sweep"); s.add_argument("--rates", type=float, nargs="+", default=[50, 100, 150, 200, 250, 300, 400]); s.add_argument("--duration", type=float, default=30)
    m = sub.add_parser("mix"); m.add_argument("--rate", type=float, default=100); m.add_argument("--duration", type=float, default=30); m.add_argument("--invalid", type=float, nargs="+", default=[0.1, 0.5])
    for p in (a, b, s, m):
        p.add_argument("--candidates", type=int, default=2)
        p.add_argument("--tag", default="")
    args = ap.parse_args()
    k = args.candidates
    tag = f"_{args.tag}" if args.tag else ""

    if args.mode == "closed":
        r = asyncio.run(closed(args.votes, args.concurrency, k))
        print(f"\nCLOSED LOOP  {args.votes:,} votes @ concurrency {args.concurrency}:  "
              f"{r['accepted']:,} accepted, {r['throughput_per_s']} votes/s, "
              f"p50 {r['p50_ms']} ms, p95 {r['p95_ms']} ms, p99 {r['p99_ms']} ms  {r['status_counts']}")
        if r["errors"]:
            print("  failures by reason:", r["errors"])
        print("saved", save(f"load_closed{tag}.json", {"votes": args.votes, "concurrency": args.concurrency, **r}))
    elif args.mode == "open":
        r = asyncio.run(open_loop(args.rate, args.duration, k))
        L = r["legit"]
        print(f"\nOPEN LOOP  {args.rate}/s for {args.duration}s:  {L['accepted']:,}/{L['attempted']:,} accepted, "
              f"{L['throughput_per_s']} votes/s, p50 {L['p50_ms']} ms, p95 {L['p95_ms']} ms, p99 {L['p99_ms']} ms")
        if L["errors"]:
            print("  failures by reason:", L["errors"])
        if args.duration >= 120 and TIMELINE:
            print("  latency of accepted votes by 30 s window (the ledger grows as the run goes on):")
            for w in range(0, int(args.duration), 30):
                xs = sorted(dt for t, dt, code in TIMELINE if w <= t < w + 30 and code == 201)
                if xs:
                    print(f"    {w:>4}-{w+30:<4}s  n={len(xs):>5}  p50 {pct(xs,.5)*1000:7.1f} ms  "
                          f"p95 {pct(xs,.95)*1000:8.1f} ms  p99 {pct(xs,.99)*1000:8.1f} ms")
            r["timeline"] = TIMELINE[:]
        print("saved", save(f"load_open{tag}.json", r))
    elif args.mode == "sweep":
        rows = []
        for rate in args.rates:
            print(f"  offered {rate:>5.0f}/s ...", flush=True)
            rows.append(asyncio.run(open_loop(rate, args.duration, k)))
        print("\n" + "=" * 82)
        print("  SECTION 5.6 — THROUGHPUT AND LATENCY UNDER INCREASING LOAD (open loop, full Algorithm 1)")
        print("=" * 82)
        print(f"  {'Offered/s':>10} {'Achieved/s':>11} {'Accepted':>10} {'Shed 503':>9} {'Other':>6} {'p50 ms':>9} {'p95 ms':>9} {'p99 ms':>9}")
        for r in rows:
            L = r["legit"]
            shed = L["status_counts"].get("503", 0)
            print(f"  {r['offered_rate']:>10.0f} {L['throughput_per_s']:>11.1f} {L['accepted']:>10,} {shed:>9,} {L['rejected_or_failed'] - shed:>6,}"
                  f" {str(L['p50_ms']):>9} {str(L['p95_ms']):>9} {str(L['p99_ms']):>9}")
        print("=" * 82)
        print("saved", save(f"load_sweep{tag}.json", {"duration_s": args.duration, "rows": rows}))
    elif args.mode == "mix":
        rows = [asyncio.run(open_loop(args.rate, args.duration, k, 0.0))]
        for f in args.invalid:
            print(f"  invalid fraction {f:.0%} ...", flush=True)
            rows.append(asyncio.run(open_loop(args.rate, args.duration, k, f)))
        base = rows[0]["legit"]["throughput_per_s"]
        print("\n" + "=" * 92)
        print(f"  SECTION 5.10 — ADVERSARIAL LOAD  (legitimate votes offered at {args.rate}/s)")
        print("=" * 92)
        print(f"  {'Invalid share':>13} {'Legit accepted/s':>17} {'Drop vs baseline':>17} {'Legit p50 ms':>13} {'Legit p99 ms':>13} {'Invalid rejected':>17}")
        for r in rows:
            L = r["legit"]
            inv = r.get("invalid", {})
            sent = sum(v["sent"] for v in inv.values())
            rej = sum(v["rejected"] for v in inv.values())
            drop = (1 - L["throughput_per_s"] / base) * 100 if base else 0
            print(f"  {r['invalid_fraction']:>12.0%} {L['throughput_per_s']:>17.1f} {drop:>16.1f}% {str(L['p50_ms']):>13} {str(L['p99_ms']):>13} {f'{rej}/{sent}' if sent else '—':>17}")
        for r in rows[1:]:
            print(f"  rejection by type at {r['invalid_fraction']:.0%}: " +
                  ", ".join(f"{kk} {v['rejected']}/{v['sent']} ({v['mean_ms']} ms)" for kk, v in r["invalid"].items()))
        print("=" * 92)
        print("saved", save(f"load_mix{tag}.json", {"rate": args.rate, "duration_s": args.duration, "rows": rows}))


if __name__ == "__main__":
    main()
