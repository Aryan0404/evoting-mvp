#!/usr/bin/env python3
# backend/tools/run_all_benchmarks_real.py
"""
Single-machine, fully-documented benchmark runner (paper-grade).
───────────────────────────────────────────────────────────────────────────────

Every performance number in the paper must come from ONE documented
experimental setup. This script records that setup and runs every CPU-bound
cryptographic / algorithmic benchmark back-to-back on the same machine,
optionally repeated N times, and reports mean ± standard deviation.

What it measures (all real, no simulation)
------------------------------------------
  A. Zero-knowledge proof        — Schnorr over NIST P-256 (gen/verify/size)
  B. Homomorphic tally           — Paillier 2048-bit: sequential tally of N
                                   ballots on one core + decryption of the K
                                   totals. B is the headline "count N votes".
  C. Merkle sealing + bisection  — root over a 10k bundle; O(log n) locate
  D. Full election               — generate N voters, encrypt in parallel,
                                   tally, verify against ground truth, seal.
                                   Note: in D the per-ballot additions happen
                                   inside the parallel workers, so D's "merge +
                                   decrypt" time is NOT the time to count N
                                   votes — use B for that.

Live-stack throughput (Redis/Pulsar ceilings, end-to-end HTTP, online
replay/flood) needs the running services; see tools/bench_components.py,
tools/loadtest.py, tools/bench_adversarial.py, or run ./benchmark.sh at the
repository root to reproduce everything with Docker.

Run:
    python -m tools.run_all_benchmarks_real
    python -m tools.run_all_benchmarks_real --repeats 5 --host-label "Apple M2"
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
import platform
import random
import socket
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.services.zkp_service import run_zkp_benchmark            # noqa: E402
from app.services.tally_service import run_tally_benchmark        # noqa: E402
from app.services.merkle_service import MerkleTree, locate_tampered_leaves  # noqa: E402
from tools.election_simulation import run as run_election         # noqa: E402

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ─────────────────────────────────────────────────────────────────────────────
#  Experimental setup capture
# ─────────────────────────────────────────────────────────────────────────────
def _cpu_model() -> str:
    try:
        if platform.system() == "Linux":
            with open("/proc/cpuinfo") as f:
                for line in f:
                    if line.startswith("model name"):
                        return line.split(":", 1)[1].strip()
        elif platform.system() == "Darwin":
            return subprocess.check_output(
                ["sysctl", "-n", "machdep.cpu.brand_string"]
            ).decode().strip()
    except Exception:
        pass
    return platform.processor() or platform.machine()


def _mem_gb() -> float:
    try:
        if platform.system() == "Linux":
            with open("/proc/meminfo") as f:
                for line in f:
                    if line.startswith("MemTotal"):
                        return round(int(line.split()[1]) / 1024 / 1024, 1)
        elif platform.system() == "Darwin":
            b = int(subprocess.check_output(["sysctl", "-n", "hw.memsize"]).decode())
            return round(b / 1024 ** 3, 1)
    except Exception:
        pass
    return 0.0


def _lib_versions() -> dict:
    out = {}
    for mod in ("phe", "ecdsa", "gmpy2"):
        try:
            m = __import__(mod)
            out[mod] = getattr(m, "__version__", None) or (
                m.version() if hasattr(m, "version") else "installed"
            )
        except Exception:
            out[mod] = "absent"
    out["gmpy2_accelerated_paillier"] = out.get("gmpy2") != "absent"
    return out


def capture_setup(host_label: str) -> dict:
    return {
        "captured_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "host_label": host_label or None,
        "in_docker_container": os.path.exists("/.dockerenv"),
        "hostname": socket.gethostname(),
        "os": f"{platform.system()} {platform.release()}",
        "python": platform.python_version(),
        "cpu_model": _cpu_model(),
        "logical_cores": os.cpu_count(),
        "ram_gb": _mem_gb(),
        "libraries": _lib_versions(),
    }


# ─────────────────────────────────────────────────────────────────────────────
#  C. Merkle sealing + tamper localization
# ─────────────────────────────────────────────────────────────────────────────
def bench_merkle(bundle_size: int = 10_000) -> dict:
    leaves = [hashlib.sha256(f"ballot-{i}".encode()).digest() for i in range(bundle_size)]

    t0 = time.perf_counter()
    root = MerkleTree(leaves).root_hex()
    t_build = time.perf_counter() - t0

    hexes = [leaf.hex() for leaf in leaves]
    locate = {}
    for k in (1, 10, 100):
        tampered = list(hexes)
        idx = sorted(random.sample(range(bundle_size), k))
        for i in idx:
            tampered[i] = hashlib.sha256(f"TAMPER-{i}".encode()).hexdigest()
        t0 = time.perf_counter()
        found = locate_tampered_leaves(hexes, tampered)
        locate[k] = {
            "located": len(found),
            "correct": found == idx,
            "time_ms": round((time.perf_counter() - t0) * 1000, 3),
        }

    return {
        "bundle_size": bundle_size,
        "build_root_sec": round(t_build, 4),
        "root_prefix": root[:32],
        "tamper_localization": locate,
    }


# ─────────────────────────────────────────────────────────────────────────────
#  One full pass of A–D
# ─────────────────────────────────────────────────────────────────────────────
def one_pass(args, quiet: bool) -> dict:
    zkp = run_zkp_benchmark(n_samples=args.zkp_samples)
    tally = run_tally_benchmark(
        num_ballots=args.tally_ballots, num_candidates=args.candidates, n_length=args.key_bits
    )
    merkle = bench_merkle(bundle_size=args.bundle_size)
    sink = io.StringIO() if quiet else sys.stdout
    with contextlib.redirect_stdout(sink):
        election = run_election(voters=args.voters, candidates=args.candidates,
                                procs=os.cpu_count(), key_bits=args.key_bits)
    return {"zkp": zkp, "tally": tally, "merkle": merkle, "election": election}


# Metrics reported in the summary: key -> (label, unit, extractor, decimals)
METRICS = [
    ("zkp_gen_ms",        "ZKP proof generation (mean of samples)",  "ms",
     lambda r: r["zkp"]["gen_time_ms"]["mean"], 3),
    ("zkp_verify_ms",     "ZKP proof verification (mean of samples)", "ms",
     lambda r: r["zkp"]["verify_time_ms"]["mean"], 3),
    ("count_sec",         "COUNT N votes: tally + decrypt (1 core)", "s",
     lambda r: r["tally"]["tally_sec"] + r["tally"]["decrypt_sec"], 3),
    ("tally_sec",         "  homomorphic tally (sequential)",        "s",
     lambda r: r["tally"]["tally_sec"], 3),
    ("tally_rate",        "  tally rate",                            "ballots/s",
     lambda r: r["tally"]["tally_rate_votes_per_sec"], 0),
    ("decrypt_ms",        "  decrypt K totals",                      "ms",
     lambda r: r["tally"]["decrypt_sec"] * 1000, 2),
    ("merkle_build_ms",   "Merkle root over bundle",                 "ms",
     lambda r: r["merkle"]["build_root_sec"] * 1000, 2),
    ("locate_1_ms",       "  locate 1 tampered ballot",              "ms",
     lambda r: r["merkle"]["tamper_localization"][1]["time_ms"], 1),
    ("locate_10_ms",      "  locate 10 tampered ballots",            "ms",
     lambda r: r["merkle"]["tamper_localization"][10]["time_ms"], 1),
    ("locate_100_ms",     "  locate 100 tampered ballots",           "ms",
     lambda r: r["merkle"]["tamper_localization"][100]["time_ms"], 1),
    ("election_encrypt_sec", "Election: vote + encrypt + seal (all cores)", "s",
     lambda r: r["election"]["vote_encrypt_sec"], 2),
    ("election_merge_sec",   "Election: merge partial tallies + decrypt", "s",
     lambda r: r["election"]["count_sec"], 3),
    ("election_seal_ms",     "Election: Merkle seal over all ballots", "ms",
     lambda r: r["election"]["seal_sec"] * 1000, 1),
]


def summarise(runs: list) -> dict:
    out = {}
    for key, _label, unit, fn, _d in METRICS:
        xs = [float(fn(r)) for r in runs]
        out[key] = {
            "unit": unit,
            "n": len(xs),
            "mean": statistics.mean(xs),
            "sd": statistics.stdev(xs) if len(xs) > 1 else 0.0,
            "min": min(xs),
            "max": max(xs),
            "values": xs,
        }
    out["all_correct"] = all(
        r["zkp"]["all_valid"] and r["zkp"]["forged_rejected"]
        and r["tally"]["correct"] and r["election"]["correct"]
        and all(v["correct"] for v in r["merkle"]["tamper_localization"].values())
        for r in runs
    )
    out["zkp_proof_size_bytes"] = runs[0]["zkp"]["proof_size_bytes"]
    return out


# ─────────────────────────────────────────────────────────────────────────────
#  Rendering
# ─────────────────────────────────────────────────────────────────────────────
def render(setup: dict, cfg: dict, summary: dict) -> str:
    n = cfg["repeats"]
    L = []
    w = L.append
    w("\n" + "=" * 76)
    w("  CONSOLIDATED BENCHMARK  —  single documented machine")
    w("=" * 76)
    w("\n  EXPERIMENTAL SETUP (report this as the paper's setup table)")
    w("  " + "-" * 72)
    if setup["host_label"]:
        w(f"  Host machine       : {setup['host_label']}")
    w(f"  Environment        : {'Docker container' if setup['in_docker_container'] else 'native'}")
    w(f"  CPU (as seen)      : {setup['cpu_model']}")
    w(f"  Logical cores      : {setup['logical_cores']}")
    w(f"  RAM (as seen)      : {setup['ram_gb']} GB")
    w(f"  OS                 : {setup['os']}")
    w(f"  Python             : {setup['python']}")
    libs = setup["libraries"]
    w(f"  Crypto libs        : phe {libs.get('phe')}, ecdsa {libs.get('ecdsa')}, "
      f"gmpy2 {libs.get('gmpy2')} (Paillier accel: {libs.get('gmpy2_accelerated_paillier')})")
    w(f"  Workload           : {cfg['voters']:,} voters, {cfg['candidates']} candidates, "
      f"Paillier {cfg['key_bits']}-bit, {cfg['zkp_samples']} ZKP samples/run, "
      f"bundle {cfg['bundle_size']:,}")
    w(f"  Repeats            : {n} full run(s)")
    w(f"  Captured (UTC)     : {setup['captured_at_utc']}")

    w("\n  RESULTS" + (f"  (mean ± SD over {n} runs)" if n > 1 else ""))
    w("  " + "-" * 72)
    w(f"  {'Metric':<46}{'Value':>26}")
    w("  " + "-" * 72)
    for key, label, unit, _fn, d in METRICS:
        s = summary[key]
        if d == 0:
            val = f"{s['mean']:,.0f}" + (f" ± {s['sd']:,.0f}" if n > 1 else "")
        else:
            val = f"{s['mean']:.{d}f}" + (f" ± {s['sd']:.{d}f}" if n > 1 else "")
        w(f"  {label:<46}{val + ' ' + unit:>26}")
    w(f"  {'ZKP proof size':<46}{str(summary['zkp_proof_size_bytes']) + ' bytes':>26}")
    w(f"  {'All correctness checks passed (every run)':<46}{str(summary['all_correct']):>26}")
    w("  " + "-" * 72)
    w("  Headline 'count N votes' = the COUNT row (sequential, one core).")
    w("  The election 'merge' row excludes per-ballot additions done in the")
    w("  parallel workers, so it is not a counting time.")
    w("=" * 76 + "\n")
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--voters", type=int, default=5000)
    ap.add_argument("--candidates", type=int, default=4)
    ap.add_argument("--tally-ballots", type=int, default=5000)
    ap.add_argument("--zkp-samples", type=int, default=500)
    ap.add_argument("--bundle-size", type=int, default=10000)
    ap.add_argument("--key-bits", type=int, default=2048)
    ap.add_argument("--repeats", type=int, default=1,
                    help="repeat the full A-D pass N times and report mean ± SD")
    ap.add_argument("--host-label", default=os.environ.get("BENCH_HOST_LABEL", ""),
                    help='physical machine, e.g. "Apple M2, 16 GB" (useful inside Docker)')
    ap.add_argument("--out", default=os.path.join(BACKEND_DIR, "paper", "results", "benchmark_run.json"))
    args = ap.parse_args()

    setup = capture_setup(args.host_label)
    cfg = {k: getattr(args, k) for k in
           ("voters", "candidates", "tally_ballots", "zkp_samples", "bundle_size", "key_bits", "repeats")}

    runs = []
    for i in range(args.repeats):
        print(f"Run {i + 1}/{args.repeats}: ZKP, tally, Merkle, election ...", flush=True)
        t0 = time.perf_counter()
        runs.append(one_pass(args, quiet=(i > 0)))
        print(f"  done in {time.perf_counter() - t0:.0f}s", flush=True)

    summary = summarise(runs)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w") as f:
        json.dump({"setup": setup, "config": cfg, "summary": summary, "runs": runs},
                  f, indent=2, default=str)

    print(render(setup, cfg, summary))
    print(f"  Machine-readable results written to: {args.out}\n")


if __name__ == "__main__":
    main()
