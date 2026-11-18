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
from app.services.merkle_service import MerkleTree, bisect_trees, verify_inclusion  # noqa: E402
from app.services import threshold_paillier as tp                 # noqa: E402
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
def bench_merkle(bundle_size: int = 10_000, bisect_bundle: int = 5_000) -> dict:
    """5.4 + 5.10: build a bundle, verify a voter receipt, localise tampering."""
    leaves = [hashlib.sha256(f"ballot-{i}".encode()).digest() for i in range(bundle_size)]
    t0 = time.perf_counter()
    tree = MerkleTree(leaves)
    t_build = time.perf_counter() - t0

    # voter receipt check: one inclusion proof (depth hashes), averaged over 1,000 leaves
    idx = random.sample(range(bundle_size), 1000)
    proofs = [(leaves[i].hex(), tree.inclusion_proof(i)) for i in idx]
    root = tree.root_hex()
    t0 = time.perf_counter()
    ok = all(verify_inclusion(h, pr, root) for h, pr in proofs)
    t_verify = (time.perf_counter() - t0) / len(proofs)

    # Algorithm 4 on a bundle of `bisect_bundle` votes (manuscript Table 10)
    base = [hashlib.sha256(f"b-{i}".encode()).digest() for i in range(bisect_bundle)]
    tb = MerkleTree(base)
    loc = {}
    for k in (1, 10, 100, 1000):
        tidx = sorted(random.sample(range(bisect_bundle), k))
        rep = list(base)
        for i in tidx:
            rep[i] = hashlib.sha256(f"TAMPER-{i}".encode()).digest()
        tr = MerkleTree(rep)
        t0 = time.perf_counter()
        found, comps = bisect_trees(tb, tr)
        loc[k] = {"correct": found == tidx, "time_ms": (time.perf_counter() - t0) * 1000,
                  "comparisons": comps, "depth": tb.depth}
    return {"bundle_size": bundle_size, "depth": tree.depth, "build_root_sec": t_build,
            "receipt_hashes": len(proofs[0][1]), "receipt_verify_ms": t_verify * 1000,
            "receipts_ok": ok, "bisect_bundle": bisect_bundle, "tamper_localization": loc}


# ─────────────────────────────────────────────────────────────────────────────
#  One full pass of A–D
# ─────────────────────────────────────────────────────────────────────────────
def one_pass(args, key, quiet: bool) -> dict:
    zkp = run_zkp_benchmark(n_samples=args.zkp_samples)
    merkle = bench_merkle(bundle_size=args.bundle_size)
    sink = io.StringIO() if quiet else sys.stdout
    with contextlib.redirect_stdout(sink):
        election = run_election(voters=args.voters, candidates=args.candidates,
                                procs=os.cpu_count(), key_bits=args.key_bits,
                                trustees=args.trustees, threshold=args.threshold, key=key)
    return {"zkp": zkp, "merkle": merkle, "election": election}


# Metrics reported in the summary: key -> (label, unit, extractor, decimals)
METRICS = [
    ("zkp_gen_ms",        "Schnorr credential proof: generate",      "ms",
     lambda r: r["zkp"]["gen_time_ms"]["mean"], 3),
    ("zkp_verify_ms",     "Schnorr credential proof: verify",        "ms",
     lambda r: r["zkp"]["verify_time_ms"]["mean"], 3),
    ("device_ms",         "Voter device: encrypt + ballot ZKP",      "ms",
     lambda r: r["election"]["device_encrypt_prove_ms_mean"], 1),
    ("verify_wall_s",     "Server: verify all N ballot proofs",      "s",
     lambda r: r["election"]["verify_wall_s"], 2),
    ("count_sec",         "COUNT N votes: tally + threshold decrypt", "s",
     lambda r: r["election"]["count_s"], 3),
    ("tally_sec",         "  homomorphic tally (1 core)",            "s",
     lambda r: r["election"]["tally_s"], 3),
    ("decrypt_ms",        "  threshold decryption (t of K)",         "ms",
     lambda r: r["election"]["decrypt_s"] * 1000, 1),
    ("seal_ms",           "Merkle seal over all N ballots",          "ms",
     lambda r: r["election"]["seal_s"] * 1000, 2),
    ("merkle_build_ms",   "Merkle root over a 10,000-vote bundle",   "ms",
     lambda r: r["merkle"]["build_root_sec"] * 1000, 2),
    ("receipt_ms",        "Voter receipt check (inclusion proof)",   "ms",
     lambda r: r["merkle"]["receipt_verify_ms"], 4),
    ("locate_1_ms",       "Bisection: 1 tampered in 5,000",          "ms",
     lambda r: r["merkle"]["tamper_localization"][1]["time_ms"], 3),
    ("locate_10_ms",      "Bisection: 10 tampered in 5,000",         "ms",
     lambda r: r["merkle"]["tamper_localization"][10]["time_ms"], 3),
    ("locate_100_ms",     "Bisection: 100 tampered in 5,000",        "ms",
     lambda r: r["merkle"]["tamper_localization"][100]["time_ms"], 3),
    ("locate_1000_ms",    "Bisection: 1,000 tampered in 5,000",      "ms",
     lambda r: r["merkle"]["tamper_localization"][1000]["time_ms"], 3),
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
        and r["election"]["correct"] and r["merkle"]["receipts_ok"]
        and all(v["correct"] for v in r["merkle"]["tamper_localization"].values())
        for r in runs
    )
    out["zkp_proof_size_bytes"] = runs[0]["zkp"]["proof_size_bytes"]
    out["bisection_comparisons"] = {k: v["comparisons"] for k, v in runs[0]["merkle"]["tamper_localization"].items()}
    out["receipt_hashes"] = runs[0]["merkle"]["receipt_hashes"]
    out["election_result"] = runs[0]["election"]["tally"]
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
      f"Paillier {cfg['key_bits']}-bit, {cfg['threshold']}-of-{cfg['trustees']} trustees, "
      f"{cfg['zkp_samples']} Schnorr samples/run, bundle {cfg['bundle_size']:,}")
    w(f"  Key ceremony       : {cfg['keygen_s']:.1f} s (one-off)")
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
    w(f"  {'Schnorr proof size':<46}{str(summary['zkp_proof_size_bytes']) + ' bytes':>26}")
    w(f"  {'Voter receipt = hashes per inclusion proof':<46}{summary['receipt_hashes']:>26}")
    w(f"  {'Bisection comparisons (1/10/100/1000)':<46}{'/'.join(str(v) for v in summary['bisection_comparisons'].values()):>26}")
    w(f"  {'Election result (run 1)':<46}{str(summary['election_result']):>26}")
    w(f"  {'All correctness checks passed (every run)':<46}{str(summary['all_correct']):>26}")
    w("  " + "-" * 72)
    w("  COUNT = sequential homomorphic tally on one core + threshold decryption")
    w("  (trustees decrypt in parallel). Key ceremony is a one-off, reported above.")
    w("=" * 76 + "\n")
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--voters", type=int, default=5000)
    ap.add_argument("--candidates", type=int, default=4)
    ap.add_argument("--trustees", type=int, default=5)
    ap.add_argument("--threshold", type=int, default=3)
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
    print(f"Threshold key ceremony ({args.threshold} of {args.trustees}, {args.key_bits}-bit) ...", flush=True)
    t0 = time.perf_counter()
    key = tp.keygen(args.key_bits, K=args.trustees, t=args.threshold)
    keygen_s = time.perf_counter() - t0
    cfg = {k: getattr(args, k) for k in
           ("voters", "candidates", "trustees", "threshold", "zkp_samples", "bundle_size", "key_bits", "repeats")}
    cfg["keygen_s"] = keygen_s

    runs = []
    for i in range(args.repeats):
        print(f"Run {i + 1}/{args.repeats}: ZKP, tally, Merkle, election ...", flush=True)
        t0 = time.perf_counter()
        runs.append(one_pass(args, key, quiet=(i > 0)))
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
