#!/usr/bin/env python3
# backend/tools/bench_ledger_stress.py
"""
Section 5.12 — Sustained stress on the replicated ledger (measured, not mocked).
───────────────────────────────────────────────────────────────────────────────

Drives the real Pulsar/BookKeeper cluster (4 bookies, E=3, Qw=2, Qa=2) as fast
as it will acknowledge, for a sustained period, with producer back-pressure
(the client never drops a write; it blocks when 20,000 are in flight).

Payload sizes:
  tiny   400-byte messages — the component ceiling reported earlier;
  k2     real ballot records with a 2-candidate ballot and its validity proof;
  k5     real ballot records with a 5-candidate ballot and its validity proof.
Real records are produced exactly as the ingestion path writes them
(canonical JSON with ciphertexts, proof, timestamps, nullifier).

Reports per-second acknowledged throughput (mean, min, max), failures, and
acknowledgement latency (p50 / p99, sampled every 50th write).

Run:  python -m tools.bench_ledger_stress --sizes tiny k2 k5 --seconds 30
      python -m tools.bench_ledger_stress --sizes k2 --seconds 120 --tag sustained
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import statistics
import sys
import threading
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.services import ballot_proof as bp            # noqa: E402
from app.services.ledger_service import canonical_ballot_bytes  # noqa: E402
from tools import ballot_factory as bf                 # noqa: E402

OUT_DIR = os.environ.get("RESULTS_DIR", "/app/paper/results/docker")


def make_payloads(size, n_hex, count=200):
    if size == "tiny":
        return [secrets.token_bytes(400) for _ in range(count)]
    k = 2 if size == "k2" else 5
    pp = bp.PublicParams.from_n(int(n_hex, 16))
    tpls = bf.make_templates(n_hex, k, 8)
    out = []
    for j in range(count):
        uti = secrets.token_hex(32)
        null = hashlib.sha256(uti.encode()).hexdigest()
        ct, pr = bf.instantiate(pp, tpls[j % len(tpls)], f"{bf.ELECTION_ID}|{null}")
        out.append(canonical_ballot_bytes({"ballot_id": str(uuid.uuid4()), "ciphertext": ct, "zkp_proof": pr,
                                           "num_candidates": k, "ts": time.time(), "cast_at": "2026-11-18T00:00:00+00:00",
                                           "nullifier": null}))
    return out


def run(size, seconds, payloads, url):
    import pulsar
    client = pulsar.Client(url, operation_timeout_seconds=30)
    producer = client.create_producer(
        f"persistent://public/default/stress-{size}-{uuid.uuid4().hex[:6]}",
        batching_enabled=True, batching_max_publish_delay_ms=10, batching_max_messages=1000,
        block_if_queue_full=True, max_pending_messages=20000, compression_type=pulsar.CompressionType.LZ4)
    lock = threading.Lock()
    acked, failed = [0], [0]
    per_sec = {}
    lat = []

    def cb_factory(t_send, sample):
        def cb(res, _mid):
            now = time.time()
            with lock:
                if res == pulsar.Result.Ok:
                    acked[0] += 1
                    s = int(now - t0)
                    per_sec[s] = per_sec.get(s, 0) + 1
                    if sample:
                        lat.append(now - t_send)
                else:
                    failed[0] += 1
        return cb

    t0 = time.time()
    sent = 0
    while time.time() - t0 < seconds:
        p = payloads[sent % len(payloads)]
        producer.send_async(p, cb_factory(time.time(), sent % 50 == 0))
        sent += 1
    producer.flush()
    wall = time.time() - t0
    producer.close()
    client.close()
    secs = [per_sec.get(i, 0) for i in range(int(seconds))]
    lat.sort()
    return {"payload": size, "payload_bytes": len(payloads[0]), "seconds": seconds, "sent": sent,
            "acked": acked[0], "failed": failed[0], "wall_s": wall,
            "throughput_mean": statistics.mean(secs) if secs else 0,
            "throughput_min": min(secs) if secs else 0, "throughput_max": max(secs) if secs else 0,
            "throughput_overall": acked[0] / wall if wall else 0,
            "mb_per_s": acked[0] * len(payloads[0]) / wall / 1e6 if wall else 0,
            "ack_p50_ms": lat[len(lat) // 2] * 1000 if lat else None,
            "ack_p99_ms": lat[min(len(lat) - 1, int(len(lat) * .99))] * 1000 if lat else None,
            "per_second": secs}


def main():
    import redis
    ap = argparse.ArgumentParser()
    ap.add_argument("--sizes", nargs="+", default=["tiny", "k2", "k5"])
    ap.add_argument("--seconds", type=float, default=30)
    ap.add_argument("--tag", default="")
    args = ap.parse_args()
    url = os.environ.get("PULSAR_URL", "pulsar://pulsar:6650")
    bb = redis.from_url(os.environ.get("BULLETIN_URL", "redis://bulletin:6379/0"), decode_responses=True)
    n_hex = bb.get("election:public_n")
    rows = []
    for size in args.sizes:
        print(f"  {size}: preparing payloads ...", flush=True)
        pl = make_payloads(size, n_hex)
        print(f"  {size}: {len(pl[0]):,}-byte records, driving the ledger for {args.seconds:.0f}s ...", flush=True)
        rows.append(run(size, args.seconds, pl, url))
    os.makedirs(OUT_DIR, exist_ok=True)
    name = f"ledger_stress{('_' + args.tag) if args.tag else ''}.json"
    with open(os.path.join(OUT_DIR, name), "w") as f:
        json.dump(rows, f, indent=2)
    print("\n" + "=" * 104)
    print("  SECTION 5.12 — SUSTAINED LEDGER STRESS  (Pulsar + 4 BookKeeper nodes, E=3 / Qw=2 / Qa=2, every write on 2 nodes)")
    print("=" * 104)
    print(f"  {'Payload':<8} {'Bytes':>8} {'Seconds':>8} {'Acked':>11} {'Failed':>7} {'Mean/s':>9} {'Min/s':>8} {'Max/s':>8} {'MB/s':>7} {'Ack p50':>9} {'Ack p99':>9}")
    for r in rows:
        print(f"  {r['payload']:<8} {r['payload_bytes']:>8,} {r['seconds']:>8.0f} {r['acked']:>11,} {r['failed']:>7} "
              f"{r['throughput_mean']:>9,.0f} {r['throughput_min']:>8,} {r['throughput_max']:>8,} {r['mb_per_s']:>7.1f} "
              f"{(r['ack_p50_ms'] or 0):>7.1f}ms {(r['ack_p99_ms'] or 0):>7.1f}ms")
    print("=" * 104)


if __name__ == "__main__":
    main()
