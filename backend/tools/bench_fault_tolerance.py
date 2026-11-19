#!/usr/bin/env python3
# backend/tools/bench_fault_tolerance.py
"""
Section 5.5 — Fault tolerance under a live election (real, not simulated).
───────────────────────────────────────────────────────────────────────────────

Driven by ./run_paper_experiments.sh fault, which runs the ledger as a 4-bookie
BookKeeper cluster (Ensemble 3, Write quorum 2, Ack quorum 2) and injects
faults on a schedule while this tool keeps voting:

    t = KILL_BOOKIE_AT    one storage node (bookie) is SIGKILLed
    t = KILL_REPLICA_AT   the air-gapped forensic replica is SIGKILLed
    t = RESTART_REPLICA   the replica is restarted and must catch up

Two modes:

  --run      seed one-time tickets, cast votes at a steady rate for D seconds
             (a voter's app retries a refused vote with back-off, exactly as
             the ticket re-issue path in ledger_service intends), and sample
             the ledger counter and replica counter twice a second.

  --verify   with the storage node STILL DOWN: read every ballot of this run
             back out of the ledger, compare against the server's accepted
             count and against the replica's database, and recompute the
             Merkle root on both sides. Prints the summary used in the paper.

Outputs (in --out-dir): ft_votes.csv, ft_samples.csv, ft_timeline.csv,
ft_summary.json.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import hashlib
import json
import os
import secrets
import sqlite3
import statistics
import sys
import time
from datetime import datetime

import aiohttp
import redis.asyncio as aioredis

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.services.merkle_service import MerkleTree  # noqa: E402
from tools import ballot_factory as bf              # noqa: E402

BULLETIN_URL = os.environ.get("BULLETIN_URL", "redis://bulletin:6379/0")

BASE = os.environ.get("LOADTEST_URL", "http://localhost:8000")
REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
PULSAR_URL = os.environ.get("PULSAR_URL", "pulsar://pulsar:6650")
TOPIC = "persistent://public/default/ballots"
REPLICA_DB = os.environ.get("REPLICA_DB", "/app/replica_data/replica.db")
MAX_ATTEMPTS = 12           # a voter's app gives up after this many tries (~60 s)
BACKOFF = [0.25, 0.5, 1, 1, 2, 3, 5, 5, 8, 10, 12, 12]


def pct(xs, p):
    if not xs:
        return None
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(len(xs) * p))]


# ─────────────────────────────────────────────────────────────────────────────
#  RUN
# ─────────────────────────────────────────────────────────────────────────────
async def run(args):
    os.makedirs(args.out_dir, exist_ok=True)
    r = aioredis.from_url(REDIS_URL, decode_responses=True)
    n = int(args.rate * args.duration)

    bb = aioredis.from_url(BULLETIN_URL, decode_responses=True)
    pkgs = bf.make_packages(await bf.election_n_hex(bb), n, k=2)
    await bf.seed_tickets(r, pkgs)

    # ledger:seq lives in the collectors' store; replica:count is published by
    # the replica on the public bulletin board.
    seq0 = int(await r.get("ledger:seq") or 0)
    rep0 = int(await bb.get("replica:count") or 0)
    start = time.time()
    meta = {"run_start_epoch": start, "seq0": seq0, "rep0": rep0,
            "rate": args.rate, "duration": args.duration, "votes_planned": n}
    with open(os.path.join(args.out_dir, "ft_meta.json"), "w") as f:
        json.dump(meta, f, indent=2)
    print(f"Seeded {n:,} tickets. Voting at {args.rate}/s for {args.duration}s ...", flush=True)

    results = [None] * n
    samples = []
    sending = True

    async def sampler():
        while sending or time.time() - start < args.duration + args.grace:
            seq = int(await r.get("ledger:seq") or 0)
            rep = int(await bb.get("replica:count") or 0)
            samples.append((time.time(), seq - seq0, rep - rep0))
            await asyncio.sleep(0.5)

    # aiohttp: httpx's pool stalls with thousands of requests queued, which is
    # exactly what happens while storage is below quorum and votes are retrying.
    async with aiohttp.ClientSession(
            base_url=BASE,
            connector=aiohttp.TCPConnector(limit=400, limit_per_host=400),
            timeout=aiohttp.ClientTimeout(total=45.0)) as client:

        async def vote(i):
            first_send = time.time()
            statuses = []
            for attempt in range(MAX_ATTEMPTS):
                try:
                    async with client.post("/api/v1/vote/cast", json=pkgs[i].body()) as resp:
                        await resp.read()
                        code = resp.status
                except Exception:
                    code = 0            # timeout / connection error
                statuses.append(code)
                if code == 201:
                    break
                if code == 409:
                    # ticket already burned: only possible if an earlier attempt
                    # was actually recorded but its reply was lost
                    break
                await asyncio.sleep(BACKOFF[attempt])
            final = statuses[-1]
            if final == 201:
                outcome = "accepted"
            elif final == 409 and any(s == 0 for s in statuses[:-1]):
                outcome = "accepted_reply_lost"
            else:
                outcome = "failed"
            results[i] = (i, first_send, outcome, len(statuses),
                          time.time() - first_send, "|".join(map(str, statuses)))

        samp = asyncio.create_task(sampler())
        tasks = []
        for i in range(n):
            delay = start + i / args.rate - time.time()
            if delay > 0:
                await asyncio.sleep(delay)
            tasks.append(asyncio.create_task(vote(i)))
        await asyncio.gather(*tasks)
        sending = False
        await samp

    with open(os.path.join(args.out_dir, "ft_votes.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["idx", "send_epoch", "outcome", "attempts", "latency_s", "statuses"])
        w.writerows(results)
    with open(os.path.join(args.out_dir, "ft_samples.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["epoch", "ledger_delta", "replica_delta"])
        w.writerows(samples)

    acc = sum(1 for x in results if x[2] != "failed")
    print(f"Voting finished: {acc:,}/{n:,} accepted.", flush=True)
    await r.aclose()
    await bb.aclose()


# ─────────────────────────────────────────────────────────────────────────────
#  VERIFY
# ─────────────────────────────────────────────────────────────────────────────
def read_ledger(run_start: float):
    """Read every ballot of this run back out of Pulsar (storage node still down)."""
    import pulsar
    client = pulsar.Client(PULSAR_URL, operation_timeout_seconds=30)
    reader = client.create_reader(TOPIC, pulsar.MessageId.earliest)
    hashes, total_msgs = [], 0
    t0 = time.time()
    while reader.has_message_available():
        msg = reader.read_next(timeout_millis=10000)
        data = msg.data()
        try:
            cast = datetime.fromisoformat(json.loads(data)["cast_at"]).timestamp()
        except Exception:
            continue
        if cast >= run_start - 1:
            total_msgs += 1
            hashes.append(hashlib.sha256(data).hexdigest())
    read_s = time.time() - t0
    reader.close()
    client.close()
    return hashes, total_msgs, read_s


def read_replica(run_start: float):
    conn = sqlite3.connect(f"file:{REPLICA_DB}?mode=ro", uri=True)
    rows = conn.execute(
        "SELECT ballot_hash FROM ballots WHERE received_at >= ? ORDER BY seq",
        (run_start - 1,)).fetchall()
    conn.close()
    return [x[0] for x in rows]


def load_events(path):
    ev = []
    if os.path.exists(path):
        for line in open(path):
            parts = line.strip().split(maxsplit=1)
            if len(parts) == 2:
                ev.append((float(parts[0]), parts[1]))
    return ev


async def verify(args):
    meta = json.load(open(os.path.join(args.out_dir, "ft_meta.json")))
    start, seq0 = meta["run_start_epoch"], meta["seq0"]
    r = aioredis.from_url(REDIS_URL, decode_responses=True)

    votes = list(csv.DictReader(open(os.path.join(args.out_dir, "ft_votes.csv"))))
    samples = [(float(a), int(b), int(c)) for a, b, c in
               list(csv.reader(open(os.path.join(args.out_dir, "ft_samples.csv"))))[1:]]
    events = load_events(os.path.join(args.out_dir, "ft_events.txt"))
    ev = {label.split()[0]: t for t, label in events}

    server_accepted = int(await r.get("ledger:seq") or 0) - seq0

    # integrity alerts and liveness verdicts during the run (bulletin board)
    from app.services.audit_service import classify_round
    bbd = aioredis.from_url(BULLETIN_URL, decode_responses=True)
    run_end = start + meta["duration"] + args.grace
    alerts = [json.loads(a) for a in await bbd.lrange("alerts:log", 0, -1)]
    false_alarms = sum(1 for a in alerts if start <= a.get("detected_at", 0) <= run_end + 60)
    verdicts = {"LIVE": 0, "STALE": 0, "DIVERGED": 0, "PENDING": 0, "UNKNOWN": 0}
    latest = int(await bbd.get("liveness:latest") or 0)
    now_v = time.time()
    for rnd in range(1, latest + 1):
        rr = await bbd.hgetall(f"liveness:round:{rnd}")
        if rr and start <= float(rr.get("t_primary", 0)) <= run_end:
            verdicts[classify_round(rr, now_v)] += 1
    await bbd.aclose()

    # wait for the replica to finish catching up (it publishes every 5 s)
    print("Waiting for the replica to catch up ...", flush=True)
    last, stable_since = -1, time.time()
    while time.time() - stable_since < 15:
        rep_rows = len(read_replica(start))
        if rep_rows >= server_accepted:
            break
        if rep_rows != last:
            last, stable_since = rep_rows, time.time()
        await asyncio.sleep(1)

    print("Reading every ballot of this run back from the ledger ...", flush=True)
    ledger_hashes, ledger_msgs, read_s = read_ledger(start)
    replica_hashes = read_replica(start)
    ledger_set, replica_set = set(ledger_hashes), set(replica_hashes)

    # Merkle roots over this run's ballots, in ledger order on both sides
    ledger_unique_ordered = list(dict.fromkeys(ledger_hashes))
    root_ledger = MerkleTree([bytes.fromhex(h) for h in ledger_unique_ordered]).root_hex() if ledger_unique_ordered else None
    root_replica = MerkleTree([bytes.fromhex(h) for h in replica_hashes]).root_hex() if replica_hashes else None

    # client-side view
    outcomes = [v["outcome"] for v in votes]
    acc_client = sum(o != "failed" for o in outcomes)
    failed = outcomes.count("failed")
    retried = sum(1 for v in votes if v["outcome"] != "failed" and int(v["attempts"]) > 1)
    reply_lost = outcomes.count("accepted_reply_lost")
    lat = [float(v["latency_s"]) for v in votes if v["outcome"] != "failed"]

    kill_b = ev.get("kill_bookie")
    kill_r = ev.get("kill_replica")
    rest_r = ev.get("restart_replica")

    def window_lat(t_from, t_to):
        xs = [float(v["latency_s"]) for v in votes
              if v["outcome"] != "failed" and t_from <= float(v["send_epoch"]) < t_to]
        return (pct(xs, 0.5), pct(xs, 0.99), len(xs))

    # longest stretch with no vote accepted, measured on completion times
    done_times = sorted(float(v["send_epoch"]) + float(v["latency_s"])
                        for v in votes if v["outcome"] != "failed")
    longest_gap = max((b - a for a, b in zip(done_times, done_times[1:])), default=0.0)

    # replica catch-up after restart: lag back to its pre-fault level
    catch_up = None
    if rest_r and kill_b:
        pre = [led - rep for t, led, rep in samples if t < kill_b]
        pre_max = max(pre) if pre else 0
        for t, led, rep in samples:
            if t > rest_r and (led - rep) <= max(pre_max, args.rate * 6):
                catch_up = t - rest_r
                break

    # per-second timeline (by send second)
    buckets = {}
    for v in votes:
        s = int(float(v["send_epoch"]) - start)
        b = buckets.setdefault(s, {"sent": 0, "ok_first": 0, "ok_retry": 0, "failed": 0, "lat": []})
        b["sent"] += 1
        if v["outcome"] == "failed":
            b["failed"] += 1
        elif int(v["attempts"]) == 1:
            b["ok_first"] += 1
        else:
            b["ok_retry"] += 1
        if v["outcome"] != "failed":
            b["lat"].append(float(v["latency_s"]))
    with open(os.path.join(args.out_dir, "ft_timeline.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["second", "sent", "accepted_first_try", "accepted_after_retry",
                    "failed", "p50_latency_ms", "p99_latency_ms"])
        for s in sorted(buckets):
            b = buckets[s]
            p50 = pct(b["lat"], 0.5)
            p99 = pct(b["lat"], 0.99)
            w.writerow([s, b["sent"], b["ok_first"], b["ok_retry"], b["failed"],
                        round(p50 * 1000, 1) if p50 is not None else "",
                        round(p99 * 1000, 1) if p99 is not None else ""])

    kill_q = ev.get("kill_quorum")
    rest_q = ev.get("restore_quorum")
    quorum = None
    if kill_q and rest_q:
        in_out = [v for v in votes if kill_q <= float(v["send_epoch"]) < rest_q]
        ok_out = [v for v in in_out if v["outcome"] != "failed"]
        first_after = min((float(v["send_epoch"]) + float(v["latency_s"]) for v in votes
                           if v["outcome"] != "failed" and float(v["send_epoch"]) + float(v["latency_s"]) >= rest_q),
                          default=None)
        accepted_during = sum(1 for t in done_times if kill_q + 2 < t < rest_q)
        lat_out = sorted(float(v["latency_s"]) for v in ok_out)
        quorum = {"outage_s": round(rest_q - kill_q, 1),
                  "votes_cast_during_outage": len(in_out),
                  "eventually_accepted": len(ok_out),
                  "needed_retry": sum(1 for v in ok_out if int(v["attempts"]) > 1),
                  "accepted_while_quorum_lost": accepted_during,
                  "max_latency_s": round(lat_out[-1], 2) if lat_out else None,
                  "p50_latency_s": round(lat_out[len(lat_out) // 2], 2) if lat_out else None,
                  "first_acceptance_after_restore_s": round(first_after - rest_q, 2) if first_after else None}

    before = window_lat(start, kill_b) if kill_b else (None, None, 0)
    during = window_lat(kill_b, kill_b + 10) if kill_b else (None, None, 0)
    after = window_lat(kill_b + 10, start + meta["duration"]) if kill_b else (None, None, 0)

    summary = {
        "votes_attempted": len(votes),
        "accepted_client_view": acc_client,
        "accepted_after_retry": retried,
        "accepted_reply_lost": reply_lost,
        "failed_after_all_retries": failed,
        "server_accepted_ledger_seq_delta": server_accepted,
        "ledger_messages_read_back": ledger_msgs,
        "ledger_unique_ballots": len(ledger_set),
        "ledger_read_back_seconds": round(read_s, 2),
        "replica_ballots_this_run": len(replica_set),
        "lost_votes_server_vs_ledger": server_accepted - len(ledger_set),
        "ledger_duplicates": ledger_msgs - len(ledger_set),
        "replica_matches_ledger_exactly": ledger_set == replica_set,
        "merkle_root_ledger": root_ledger,
        "merkle_root_replica": root_replica,
        "merkle_roots_equal": root_ledger == root_replica and root_ledger is not None,
        "longest_gap_without_acceptance_s": round(longest_gap, 3),
        "latency_p50_p99_ms_before_fault": [round(x * 1000, 1) if x else None for x in before[:2]],
        "latency_p50_p99_ms_first_10s_after_fault": [round(x * 1000, 1) if x else None for x in during[:2]],
        "latency_p50_p99_ms_after_recovery": [round(x * 1000, 1) if x else None for x in after[:2]],
        "max_latency_ms": round(max(lat) * 1000, 1) if lat else None,
        "replica_downtime_s": round(rest_r - kill_r, 1) if (kill_r and rest_r) else None,
        "replica_catch_up_s_after_restart": round(catch_up, 1) if catch_up is not None else None,
        "events": [{"t_rel_s": round(t - start, 2), "event": label} for t, label in events],
        "quorum_loss": quorum,
        "integrity_alerts_during_faults": false_alarms,
        "liveness_rounds": verdicts,
    }
    with open(os.path.join(args.out_dir, "ft_summary.json"), "w") as f:
        json.dump(summary, f, indent=2)

    ok = (summary["lost_votes_server_vs_ledger"] == 0
          and summary["replica_matches_ledger_exactly"]
          and summary["merkle_roots_equal"]
          and false_alarms == 0)

    def fmt(v):
        return "—" if v is None else v

    print("\n" + "=" * 70)
    print("  SECTION 5.7 — FAULT TOLERANCE (4 bookies, E=3 / Qw=2 / Qa=2)")
    print("=" * 70)
    for e in summary["events"]:
        print(f"  t = {e['t_rel_s']:>6.1f} s   {e['event']}")
    print("  " + "-" * 66)
    rows = [
        ("Votes attempted", summary["votes_attempted"]),
        ("Accepted (client view)", summary["accepted_client_view"]),
        ("  of which needed a retry", retried),
        ("  of which reply lost, then confirmed", reply_lost),
        ("Failed after all retries", failed),
        ("Accepted by server (ledger seq Δ)", server_accepted),
        ("Ballots read back from ledger (node down)", len(ledger_set)),
        ("Ballots verified by replica", len(replica_set)),
        ("LOST VOTES", summary["lost_votes_server_vs_ledger"]),
        ("Duplicate ledger entries", summary["ledger_duplicates"]),
        ("Replica == ledger (same ballots)", summary["replica_matches_ledger_exactly"]),
        ("Merkle roots equal (ledger vs replica)", summary["merkle_roots_equal"]),
        ("Longest pause with no vote accepted", f"{summary['longest_gap_without_acceptance_s']} s"),
        ("Latency p50/p99 before fault", f"{fmt(summary['latency_p50_p99_ms_before_fault'][0])} / {fmt(summary['latency_p50_p99_ms_before_fault'][1])} ms"),
        ("Latency p50/p99 first 10 s after fault", f"{fmt(summary['latency_p50_p99_ms_first_10s_after_fault'][0])} / {fmt(summary['latency_p50_p99_ms_first_10s_after_fault'][1])} ms"),
        ("Latency p50/p99 after recovery", f"{fmt(summary['latency_p50_p99_ms_after_recovery'][0])} / {fmt(summary['latency_p50_p99_ms_after_recovery'][1])} ms"),
        ("Replica downtime", f"{fmt(summary['replica_downtime_s'])} s"),
        ("Replica back in sync after restart", f"{fmt(summary['replica_catch_up_s_after_restart'])} s"),
        ("Integrity alerts during faults (false +)", false_alarms),
    ]
    if quorum:
        rows += [
            ("QUORUM LOSS: storage below ensemble for", f"{quorum['outage_s']} s"),
            ("  votes cast during the outage", quorum["votes_cast_during_outage"]),
            ("  eventually accepted (voter app retries)", quorum["eventually_accepted"]),
            ("  accepted while quorum was lost", quorum["accepted_while_quorum_lost"]),
            ("  first acceptance after restore", f"{fmt(quorum['first_acceptance_after_restore_s'])} s"),
            ("  max latency of an outage vote", f"{fmt(quorum['max_latency_s'])} s"),
        ]
    rows.append(("Liveness rounds LIVE / STALE / DIVERGED",
                 f"{verdicts['LIVE']} / {verdicts['STALE']} / {verdicts['DIVERGED']}"))
    for k, v in rows:
        print(f"  {k:<44}{str(v):>22}")
    print("  " + "-" * 66)
    print(f"  RESULT: {'PASS — no vote lost, replica identical' if ok else 'CHECK — see ft_summary.json'}")
    print("=" * 70)
    await r.aclose()
    sys.exit(0 if ok else 2)


def main():
    ap = argparse.ArgumentParser()
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--run", action="store_true")
    mode.add_argument("--verify", action="store_true")
    ap.add_argument("--rate", type=float, default=100)
    ap.add_argument("--duration", type=float, default=120)
    ap.add_argument("--grace", type=float, default=20)
    ap.add_argument("--out-dir", default="/app/paper/results/docker")
    args = ap.parse_args()
    asyncio.run(run(args) if args.run else verify(args))


if __name__ == "__main__":
    main()
