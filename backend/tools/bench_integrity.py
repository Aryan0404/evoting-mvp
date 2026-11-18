#!/usr/bin/env python3
# backend/tools/bench_integrity.py
"""
Sections 5.5 / 5.10 — live tamper detection, localisation and liveness.
───────────────────────────────────────────────────────────────────────────────

  fill      cast N valid votes (open loop) so the ledger holds several bundles.

  tamper    act as a malicious insider with database access: overwrite m stored
            ballots in the primary vote ledger (PostgreSQL) with copies of other
            ballots, for m ∈ {1, 10, 100, 1000}, several trials each. For every
            trial it measures
              • detection latency  — commit of the tampering → alert on the
                                     public bulletin board;
              • localisation       — the ledger positions named by the replica's
                                     Merkle bisection vs the positions altered;
              • lockdown           — a valid vote submitted after the alert must
                                     be refused (503 FORENSIC_LOCKDOWN);
            then restores the original ballots, clears the alert and waits for
            the replica to report PASS again (no residual false alarm).

  monitor   sample the liveness verdict (Algorithm 5) and replica status every
            0.25 s for S seconds into a CSV; the driving script pauses and
            resumes the replica and records the times in ft-style events.

  analyse-liveness   compute, from the monitor CSV and the events file, how long
            after the pause the replica was reported STALE and how long after
            the resume it was LIVE again.

Run inside the backend container, e.g.
  python -m tools.bench_integrity fill --votes 25000 --rate 200
  python -m tools.bench_integrity tamper --sizes 1 10 100 1000 --trials 5
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import os
import random
import statistics
import sys
import time

import asyncpg
import httpx
import redis.asyncio as aioredis

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.services.audit_service import classify_round        # noqa: E402
from app.workers.common import CYCLE_SECONDS, pg_dsn          # noqa: E402
from tools import ballot_factory as bf                        # noqa: E402
from tools.bench_load import open_loop                        # noqa: E402

BASE = os.environ.get("LOADTEST_URL", "http://localhost:8000")
REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
BULLETIN_URL = os.environ.get("BULLETIN_URL", "redis://bulletin:6379/0")
OUT_DIR = os.environ.get("RESULTS_DIR", "/app/paper/results/docker")


async def wait_status(bb, want="PASS", timeout=120, settle_count=None):
    t0 = time.time()
    while time.time() - t0 < timeout:
        st = await bb.get("replica:status")
        pc = int(await bb.get("primary:count") or 0)
        rc = int(await bb.get("replica:count") or 0)
        if st == want and (settle_count is None or (pc >= settle_count and rc >= settle_count)):
            return time.time() - t0
        await asyncio.sleep(0.25)
    return None


async def fill(args):
    r = await open_loop(args.rate, args.votes / args.rate, args.candidates)
    L = r["legit"]
    print(f"Filled ledger: {L['accepted']:,}/{L['attempted']:,} votes accepted at {L['throughput_per_s']}/s")
    bb = aioredis.from_url(BULLETIN_URL, decode_responses=True)
    redis = aioredis.from_url(REDIS_URL, decode_responses=True)
    total = int(await redis.get("ledger:seq") or 0)
    waited = await wait_status(bb, "PASS", timeout=300, settle_count=total)
    print(f"Replica and primary agree on all {total:,} ballots (PASS) after {waited:.1f}s" if waited is not None
          else "WARNING: replica did not reach PASS")


async def tamper(args):
    conn = await asyncpg.connect(pg_dsn(os.environ["DATABASE_URL"]))
    bb = aioredis.from_url(BULLETIN_URL, decode_responses=True)
    redis = aioredis.from_url(REDIS_URL, decode_responses=True)
    n_rows = await conn.fetchval("SELECT COUNT(*) FROM vote_ledger")
    if n_rows < max(args.sizes) * 2:
        raise SystemExit(f"ledger holds only {n_rows} ballots — run `fill` first")
    await bb.delete("alert:active")
    if await wait_status(bb, "PASS", timeout=120, settle_count=n_rows) is None:
        raise SystemExit("replica not in PASS state before tampering")
    probes = bf.make_packages(await bf.election_n_hex(bb), len(args.sizes) * args.trials + 5, k=2)
    await bf.seed_tickets(redis, probes)
    probe_i = 0
    rows = []
    async with httpx.AsyncClient(base_url=BASE, timeout=30.0) as client:
        for m in args.sizes:
            for trial in range(args.trials):
                seqs = sorted(random.sample(range(1, n_rows + 1), m))
                donors = [random.randint(1, n_rows) for _ in seqs]
                orig = {r["seq"]: r["payload"] for r in await conn.fetch(
                    "SELECT seq, payload FROM vote_ledger WHERE seq = ANY($1::bigint[])", seqs)}
                donor_payload = {r["seq"]: r["payload"] for r in await conn.fetch(
                    "SELECT seq, payload FROM vote_ledger WHERE seq = ANY($1::bigint[])", donors)}
                updates = []
                for s, d in zip(seqs, donors):
                    newp = donor_payload[d] if d != s else orig[s].replace('"ts":', '"ts": ', 1)
                    if newp == orig[s]:
                        newp = orig[s].replace('"ts":', '"ts": ', 1)
                    updates.append((newp, s))
                await conn.executemany("UPDATE vote_ledger SET payload = $1 WHERE seq = $2", updates)
                t_tamper = time.time()

                alert = None
                while time.time() - t_tamper < 60:
                    a = await bb.get("alert:active")
                    if a:
                        cand = json.loads(a)
                        # Only an alert raised AFTER this tampering counts. A
                        # replica cycle that was already running when the previous
                        # trial was restored can publish one late, and it must not
                        # be mistaken for this trial's detection.
                        if cand.get("detected_at", 0) >= t_tamper:
                            alert = cand
                            if all(b.get("located") for b in alert["bundles"]):
                                break
                    await asyncio.sleep(0.05)
                t_detect = (alert["detected_at"] - t_tamper) if alert else None
                located = sorted({s for b in (alert or {}).get("bundles", []) if b.get("located")
                                  for s in b["located"]["ledger_seq"]})
                comps = sum(b["located"]["comparisons"] for b in (alert or {}).get("bundles", []) if b.get("located"))

                p = probes[probe_i]
                probe_i += 1
                resp = await client.post("/api/v1/vote/cast", json=p.body())
                lockdown = resp.status_code == 503 and "FORENSIC_LOCKDOWN" in resp.text

                await conn.executemany("UPDATE vote_ledger SET payload = $1 WHERE seq = $2",
                                       [(orig[s], s) for s in seqs])
                await bb.delete("alert:active")
                t_clear0 = time.time()
                cleared = await wait_status(bb, "PASS", timeout=60)
                # a comparison that was in flight during the restore may re-raise
                # the alert just after the delete: wait one more cycle, then clear
                await asyncio.sleep(CYCLE_SECONDS + 1)
                late = await bb.get("alert:active")
                still_alert = bool(late) and json.loads(late).get("detected_at", 0) > t_clear0 + CYCLE_SECONDS
                await bb.delete("alert:active")
                rows.append({"tampered": m, "trial": trial + 1, "detect_s": t_detect,
                             "located_exact": located == seqs, "located": len(located),
                             "bisection_comparisons": comps, "lockdown_enforced": lockdown,
                             "back_to_pass_s": cleared, "false_alarm_after_restore": still_alert})
                print(f"  m={m:>5} trial {trial+1}: detected in {t_detect:.2f}s, located {len(located)}/{m} "
                      f"(exact: {located == seqs}), {comps} comparisons, lockdown: {lockdown}, "
                      f"PASS again after restore: {cleared is not None}" if t_detect is not None
                      else f"  m={m:>5} trial {trial+1}: NOT DETECTED within 60 s")

    summary = []
    for m in args.sizes:
        rs = [r for r in rows if r["tampered"] == m]
        ds = [r["detect_s"] for r in rs if r["detect_s"] is not None]
        summary.append({"tampered": m, "trials": len(rs), "detected": len(ds),
                        "detect_mean_s": statistics.mean(ds) if ds else None,
                        "detect_sd_s": statistics.stdev(ds) if len(ds) > 1 else 0,
                        "detect_min_s": min(ds) if ds else None, "detect_max_s": max(ds) if ds else None,
                        "located_exact": sum(r["located_exact"] for r in rs),
                        "lockdown_enforced": sum(r["lockdown_enforced"] for r in rs),
                        "mean_comparisons": statistics.mean(r["bisection_comparisons"] for r in rs),
                        "false_alarms_after_restore": sum(r["false_alarm_after_restore"] for r in rs)})
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(os.path.join(OUT_DIR, "integrity_tamper.json"), "w") as f:
        json.dump({"ledger_ballots": n_rows, "rows": rows, "summary": summary}, f, indent=2)
    print("\n" + "=" * 100)
    print(f"  SECTION 5.5 — LIVE TAMPER DETECTION  (insider edits the primary ledger; {n_rows:,} ballots, "
          f"bundles of {os.environ.get('BUNDLE_SIZE', '10000')})")
    print("=" * 100)
    print(f"  {'Tampered':>9} {'Detected':>9} {'Latency mean ± SD (s)':>23} {'Min–max (s)':>14} "
          f"{'Located exactly':>16} {'Lockdown':>9} {'Comparisons':>12}")
    for s in summary:
        lat = (f"{s['detect_mean_s']:.2f} ± {s['detect_sd_s']:.2f}" if s["detect_mean_s"] is not None else "—")
        rng = (f"{s['detect_min_s']:.2f}–{s['detect_max_s']:.2f}" if s["detect_min_s"] is not None else "—")
        det = f"{s['detected']}/{s['trials']}"
        loc = f"{s['located_exact']}/{s['trials']}"
        lck = f"{s['lockdown_enforced']}/{s['trials']}"
        print(f"  {s['tampered']:>9} {det:>9} {lat:>23} {rng:>14} {loc:>16} {lck:>9} {s['mean_comparisons']:>12.0f}")
    print("=" * 100)
    await conn.close()


async def monitor(args):
    bb = aioredis.from_url(BULLETIN_URL, decode_responses=True)
    path = os.path.join(OUT_DIR, args.out)
    os.makedirs(OUT_DIR, exist_ok=True)
    t_end = time.time() + args.seconds
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["epoch", "liveness", "latest_round", "replica_status", "replica_count", "primary_count"])
        while time.time() < t_end:
            latest = int(await bb.get("liveness:latest") or 0)
            now = time.time()
            status = "UNKNOWN"
            for rnd in range(latest, max(0, latest - 8), -1):
                st = classify_round(await bb.hgetall(f"liveness:round:{rnd}"), now)
                if st != "PENDING":
                    status = st
                    break
            w.writerow([f"{now:.3f}", status, latest, await bb.get("replica:status"),
                        await bb.get("replica:count"), await bb.get("primary:count")])
            f.flush()
            await asyncio.sleep(0.25)
    print(f"liveness samples written to {path}")


def analyse_liveness(args):
    rows = list(csv.DictReader(open(os.path.join(OUT_DIR, args.csv))))
    ev = {}
    for line in open(os.path.join(OUT_DIR, args.events)):
        t, label = line.strip().split(maxsplit=1)
        ev[label.split()[0]] = float(t)
    pause, resume = ev["pause_replica"], ev["resume_replica"]
    first_stale = next((float(r["epoch"]) for r in rows if float(r["epoch"]) >= pause and r["liveness"] == "STALE"), None)
    live_again = next((float(r["epoch"]) for r in rows if float(r["epoch"]) >= resume and r["liveness"] == "LIVE"), None)
    before = [r["liveness"] for r in rows if float(r["epoch"]) < pause]
    out = {"tau_s": float(os.environ.get("LIVENESS_TAU", "15")),
           "cycle_s": float(os.environ.get("INTEGRITY_INTERVAL", "5")),
           "paused_for_s": resume - pause,
           "live_before_pause_share": before.count("LIVE") / len(before) if before else None,
           "stale_reported_after_pause_s": (first_stale - pause) if first_stale else None,
           "live_again_after_resume_s": (live_again - resume) if live_again else None,
           "diverged_samples": sum(r["liveness"] == "DIVERGED" for r in rows)}
    with open(os.path.join(OUT_DIR, "integrity_liveness.json"), "w") as f:
        json.dump(out, f, indent=2)
    print("\n" + "=" * 72)
    print("  SECTION 5.5 — NONCE-BOUND LIVENESS (Algorithm 5)")
    print("=" * 72)
    print(f"  cycle {out['cycle_s']:.0f} s, timeout τ = {out['tau_s']:.0f} s, replica paused for {out['paused_for_s']:.1f} s")
    print(f"  LIVE before the pause                : {out['live_before_pause_share']:.0%} of samples" if out['live_before_pause_share'] is not None else "")
    print(f"  reported STALE after the pause       : {out['stale_reported_after_pause_s']:.1f} s" if out['stale_reported_after_pause_s'] is not None else "  reported STALE after the pause       : never")
    print(f"  LIVE again after the replica resumed : {out['live_again_after_resume_s']:.1f} s" if out['live_again_after_resume_s'] is not None else "  LIVE again after resume              : never")
    print(f"  DIVERGED samples (should be 0)       : {out['diverged_samples']}")
    print("=" * 72)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="mode", required=True)
    f = sub.add_parser("fill"); f.add_argument("--votes", type=int, default=25000); f.add_argument("--rate", type=float, default=200); f.add_argument("--candidates", type=int, default=2)
    t = sub.add_parser("tamper"); t.add_argument("--sizes", type=int, nargs="+", default=[1, 10, 100, 1000]); t.add_argument("--trials", type=int, default=5)
    m = sub.add_parser("monitor"); m.add_argument("--seconds", type=float, default=90); m.add_argument("--out", default="integrity_liveness.csv")
    a = sub.add_parser("analyse-liveness"); a.add_argument("--csv", default="integrity_liveness.csv"); a.add_argument("--events", default="integrity_events.txt")
    args = ap.parse_args()
    if args.mode == "fill":
        asyncio.run(fill(args))
    elif args.mode == "tamper":
        asyncio.run(tamper(args))
    elif args.mode == "monitor":
        asyncio.run(monitor(args))
    else:
        analyse_liveness(args)


if __name__ == "__main__":
    main()
