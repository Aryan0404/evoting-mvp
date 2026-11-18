#!/usr/bin/env python3
# backend/tools/bench_tally.py
"""
Section 5.9 — Homomorphic tallying overhead (real 2048-bit Paillier).
───────────────────────────────────────────────────────────────────────────────

For a k-candidate election (default k = 5) and m ∈ {100K, 1M, 10M} ballots:

  • sequential accumulation  T[i] ← T[i] · c_i  (mod n²)  on one core;
  • parallel accumulation over P worker processes, each folding a slice of the
    ballot stream into partial products that are then multiplied together;
  • peak resident memory of each run, measured in a fresh process;
  • the threshold decryption ceremony (t = 3 of K = 5 trustees) on the k
    encrypted totals, and a correctness check against the ground truth.

Ballots are streamed, never all held in memory. Ciphertexts are drawn
cyclically from a pool of freshly encrypted, ZKP-valid-shaped one-hot ballots
(default 2,000), so every accumulation is a genuine 4096-bit modular
multiplication of real ciphertexts; only the encryption work is not repeated
for every one of the 10 million ballots (encryption happens on voters'
devices, not in the tally).

Run:  python -m tools.bench_tally                     # 100K, 1M, 10M
      python -m tools.bench_tally --sizes 100000 1000000 --procs 8
Output: paper/results/docker/tally.json (+ printed table)
"""

from __future__ import annotations

import argparse
import json
import os
import pickle
import resource
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ProcessPoolExecutor

from gmpy2 import mpz

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.services import ballot_proof as bp          # noqa: E402
from app.services import threshold_paillier as tp    # noqa: E402

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ── worker state for parallel accumulation ──────────────────────────────────
_POOL = None
_N2 = None


def _init(pool_path):
    global _POOL, _N2
    with open(pool_path, "rb") as f:
        d = pickle.load(f)
    _N2 = mpz(d["n2"])
    _POOL = [[mpz(c) for c in b] for b in d["pool"]]


def _fold(args):
    start, stop = args
    pool, n2 = _POOL, _N2
    k = len(pool[0])
    P = len(pool)
    T = [mpz(1)] * k
    for j in range(start, stop):
        b = pool[j % P]
        for i in range(k):
            T[i] = T[i] * b[i] % n2
    return [int(x) for x in T]


def _one(pool_path, m, mode, procs):
    """Runs inside a fresh process: accumulate m ballots, report time + peak RSS."""
    _init(pool_path)
    k = len(_POOL[0])
    t0 = time.perf_counter()
    if mode == "seq":
        T = _fold((0, m))
    else:
        step = (m + procs - 1) // procs
        slices = [(s, min(m, s + step)) for s in range(0, m, step)]
        with ProcessPoolExecutor(max_workers=procs, initializer=_init, initargs=(pool_path,)) as ex:
            parts = list(ex.map(_fold, slices))
        T = [mpz(1)] * k
        for part in parts:
            T = [(a * mpz(b)) % _N2 for a, b in zip(T, part)]
        T = [int(x) for x in T]
    dt = time.perf_counter() - t0
    peak_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if mode == "par":
        peak_kb += resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss * procs
    return {"m": m, "mode": mode, "seconds": dt, "peak_rss_mb": peak_kb / 1024, "T": [format(x, "x") for x in T]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sizes", type=int, nargs="+", default=[100_000, 1_000_000, 10_000_000])
    ap.add_argument("--candidates", type=int, default=5)
    ap.add_argument("--pool", type=int, default=2000)
    ap.add_argument("--procs", type=int, default=os.cpu_count())
    ap.add_argument("--trustees", type=int, default=5)
    ap.add_argument("--threshold", type=int, default=3)
    ap.add_argument("--key-bits", type=int, default=2048)
    ap.add_argument("--out", default=os.path.join(BACKEND, "paper", "results", "docker", "tally.json"))
    ap.add_argument("--_one", nargs=4, help=argparse.SUPPRESS)
    args = ap.parse_args()

    if args._one:
        pool_path, m, mode, procs = args._one
        print(json.dumps(_one(pool_path, int(m), mode, int(procs))))
        return

    k = args.candidates
    print(f"Threshold key ceremony: {args.threshold}-of-{args.trustees}, {args.key_bits}-bit ...", flush=True)
    t0 = time.perf_counter()
    key = tp.keygen(args.key_bits, K=args.trustees, t=args.threshold)
    keygen_s = time.perf_counter() - t0
    pp = bp.PublicParams.from_n(key.n)

    print(f"Encrypting a pool of {args.pool:,} one-hot ballots (k={k}) ...", flush=True)
    t0 = time.perf_counter()
    choices = [i % k for i in range(args.pool)]
    pool = [[int(c) for c in bp.encrypt_ballot(pp, ch, k)[0]] for ch in choices]
    pool_s = time.perf_counter() - t0
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".pkl")
    pickle.dump({"n2": int(pp.n2), "pool": pool}, tmp)
    tmp.close()

    def truth(m):
        full, rem = divmod(m, args.pool)
        counts = [0] * k
        for j, ch in enumerate(choices):
            counts[ch] += full + (1 if j < rem else 0)
        return counts

    rows = []
    for m in args.sizes:
        for mode in ("seq", "par"):
            print(f"  m = {m:>12,}  {mode} ...", flush=True)
            out = subprocess.run([sys.executable, "-m", "tools.bench_tally", "--_one", tmp.name, str(m), mode,
                                  str(args.procs)], cwd=BACKEND, capture_output=True, text=True, check=True)
            r = json.loads(out.stdout.strip().splitlines()[-1])
            T = [mpz(x, 16) for x in r.pop("T")]
            trustees = list(range(1, args.threshold + 1))
            t0 = time.perf_counter()
            per_trustee = []
            parts = {}
            for i in trustees:
                ts = time.perf_counter()
                parts[i] = [tp.partial_decrypt(key, i, c) for c in T]
                per_trustee.append(time.perf_counter() - ts)
            tc = time.perf_counter()
            result = [tp.combine(key, {i: parts[i][j] for i in trustees}) for j in range(k)]
            combine_s = time.perf_counter() - tc
            r.update({
                "ballots_per_sec": m / r["seconds"],
                "decrypt_partial_per_trustee_s": sum(per_trustee) / len(per_trustee),
                "decrypt_combine_s": combine_s,
                "decrypt_ceremony_parallel_trustees_s": max(per_trustee) + combine_s,
                "result": result,
                "correct": result == truth(m),
            })
            rows.append(r)
    os.unlink(tmp.name)

    by = {(r["m"], r["mode"]): r for r in rows}
    report = {"candidates": k, "key_bits": args.key_bits, "trustees": args.trustees,
              "threshold": args.threshold, "procs": args.procs, "pool": args.pool,
              "keygen_ceremony_s": keygen_s, "pool_encrypt_s": pool_s, "rows": rows}
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(report, f, indent=2)

    print("\n" + "=" * 92)
    print(f"  SECTION 5.9 — HOMOMORPHIC TALLY  (k = {k}, Paillier {args.key_bits}-bit, "
          f"{args.threshold}-of-{args.trustees} threshold decryption, {args.procs} worker processes)")
    print("=" * 92)
    print(f"  {'Ballots':>12} {'Seq (s)':>10} {'Par (s)':>10} {'Speedup':>9} {'Seq ballots/s':>15}"
          f" {'Peak mem seq':>13} {'Peak mem par':>13} {'Correct':>8}")
    for m in args.sizes:
        s, p = by[(m, "seq")], by[(m, "par")]
        print(f"  {m:>12,} {s['seconds']:>10.2f} {p['seconds']:>10.2f} {s['seconds']/p['seconds']:>8.2f}x"
              f" {s['ballots_per_sec']:>15,.0f} {s['peak_rss_mb']:>10.0f} MB {p['peak_rss_mb']:>10.0f} MB"
              f" {str(s['correct'] and p['correct']):>8}")
    d = rows[0]
    print("  " + "-" * 88)
    print(f"  Threshold decryption of {k} totals: {d['decrypt_partial_per_trustee_s']*1000:.1f} ms per trustee "
          f"(trustees work in parallel) + {d['decrypt_combine_s']*1000:.2f} ms to combine "
          f"= {d['decrypt_ceremony_parallel_trustees_s']*1000:.1f} ms")
    print(f"  Key ceremony (one-off, before the election): {keygen_s:.1f} s")
    print(f"  Results written to {args.out}")
    print("=" * 92)


if __name__ == "__main__":
    main()
