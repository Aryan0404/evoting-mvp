#!/usr/bin/env python3
# backend/tools/bench_zkp.py
"""
Section 5.8 — Proof generation and verification overhead (all measured).
───────────────────────────────────────────────────────────────────────────────

  1. Ballot-validity proof (app/services/ballot_proof.py): the proof that an
     encrypted one-hot ballot is well formed — each slot encrypts 0 or 1 and
     the slots sum to 1. Measured for k = 2 and k = 5 candidates:
     generation (including ballot encryption), batched verification, size.
  2. Schnorr proof of knowledge over NIST P-256 (app/services/zkp_service.py),
     the credential proof.
  3. Device signature: ECDSA P-256 sign / verify over the ballot package
     (what the phone's secure enclave produces; RSA-4096 is not available in
     mobile secure enclaves).
  4. Verification capacity: ballot proofs verified per second with
     1, 2, 4 and 8 worker processes (no GIL contention between processes).

Samples: 1,000 generations and 2,000 verifications per scheme by default
(each generated proof is verified twice), matching the manuscript's protocol.

Run:  python -m tools.bench_zkp
Output: paper/results/docker/zkp.json (+ printed table)
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time
from concurrent.futures import ProcessPoolExecutor

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from phe import paillier

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.services import ballot_proof as bp      # noqa: E402
from app.services import zkp_service             # noqa: E402

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CTX = "election-2026|nullifier-bench"


def stats_ms(xs):
    xs = sorted(xs)
    return {"mean": statistics.mean(xs) * 1000, "sd": statistics.stdev(xs) * 1000 if len(xs) > 1 else 0,
            "p50": xs[len(xs) // 2] * 1000, "p99": xs[min(len(xs) - 1, int(len(xs) * 0.99))] * 1000,
            "n": len(xs)}


# ── capacity workers ────────────────────────────────────────────────────────
_PP = None
_PROOFS = None


def _cap_init(n_hex, proofs):
    global _PP, _PROOFS
    _PP = bp.PublicParams.from_n(int(n_hex, 16))
    _PROOFS = [bp.decode(c, p) for c, p in proofs]


def _cap_run(seconds):
    done, i = 0, 0
    t_end = time.perf_counter() + seconds
    while time.perf_counter() < t_end:
        cts, pr = _PROOFS[i % len(_PROOFS)]
        assert bp.verify_ballot(_PP, cts, pr, CTX)
        done += 1
        i += 1
    return done


def bench_ballot_proof(pp, k, n_gen, n_ver):
    gen, ver, enc = [], [], []
    proofs = []
    for j in range(n_gen):
        t = time.perf_counter()
        cts, rs = bp.encrypt_ballot(pp, j % k, k)
        te = time.perf_counter() - t
        pr = bp.prove_ballot(pp, cts, rs, j % k, CTX)
        gen.append(time.perf_counter() - t)
        enc.append(te)
        proofs.append((cts, pr))
    for j in range(n_ver):
        cts, pr = proofs[j % len(proofs)]
        t = time.perf_counter()
        ok = bp.verify_ballot(pp, cts, pr, CTX)
        ver.append(time.perf_counter() - t)
        assert ok
    ctj, pj = bp.encode(*proofs[0])
    return {"k": k, "generate_incl_encryption_ms": stats_ms(gen), "encryption_only_ms": stats_ms(enc),
            "verify_ms": stats_ms(ver), "proof_bytes": bp.proof_size_bytes(pj),
            "ciphertext_bytes": len("".join(__import__("json").loads(ctj))) // 2}, proofs


def bench_schnorr(n_gen, n_ver):
    secret, pub = zkp_service.keypair()
    msg = b"ballot-package"
    gen, ver, proofs = [], [], []
    for _ in range(n_gen):
        t = time.perf_counter()
        p = zkp_service.prove(secret, pub, msg)
        gen.append(time.perf_counter() - t)
        proofs.append(p)
    for j in range(n_ver):
        t = time.perf_counter()
        ok = zkp_service.verify(pub, proofs[j % len(proofs)], msg)
        ver.append(time.perf_counter() - t)
        assert ok
    return {"generate_ms": stats_ms(gen), "verify_ms": stats_ms(ver),
            "proof_bytes": zkp_service.proof_size_bytes(proofs[0])}


def bench_ecdsa(n_gen, n_ver):
    key = ec.generate_private_key(ec.SECP256R1())
    pub = key.public_key()
    msg = os.urandom(3000)          # roughly the size of a k = 5 ballot package
    sign, ver, sigs = [], [], []
    for _ in range(n_gen):
        t = time.perf_counter()
        s = key.sign(msg, ec.ECDSA(hashes.SHA256()))
        sign.append(time.perf_counter() - t)
        sigs.append(s)
    for j in range(n_ver):
        t = time.perf_counter()
        pub.verify(sigs[j % len(sigs)], msg, ec.ECDSA(hashes.SHA256()))
        ver.append(time.perf_counter() - t)
    return {"sign_ms": stats_ms(sign), "verify_ms": stats_ms(ver), "signature_bytes": len(sigs[0])}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gen", type=int, default=1000)
    ap.add_argument("--ver", type=int, default=2000)
    ap.add_argument("--capacity-seconds", type=float, default=10)
    ap.add_argument("--key-bits", type=int, default=2048)
    ap.add_argument("--out", default=os.path.join(BACKEND, "paper", "results", "docker", "zkp.json"))
    args = ap.parse_args()

    pub, _ = paillier.generate_paillier_keypair(n_length=args.key_bits)
    pp = bp.PublicParams.from_n(pub.n)
    report = {"key_bits": args.key_bits, "samples": {"generate": args.gen, "verify": args.ver}}

    print(f"Ballot-validity proof, k = 2 ({args.gen} gen / {args.ver} verify) ...", flush=True)
    report["ballot_proof_k2"], _ = bench_ballot_proof(pp, 2, args.gen, args.ver)
    print(f"Ballot-validity proof, k = 5 ({args.gen} gen / {args.ver} verify) ...", flush=True)
    report["ballot_proof_k5"], proofs5 = bench_ballot_proof(pp, 5, args.gen, args.ver)
    print("Schnorr P-256 credential proof ...", flush=True)
    report["schnorr_p256"] = bench_schnorr(args.gen, args.ver)
    print("ECDSA P-256 device signature ...", flush=True)
    report["ecdsa_p256"] = bench_ecdsa(args.gen, args.ver)

    print("Verification capacity (k = 5 ballot proofs) ...", flush=True)
    enc = [bp.encode(c, p) for c, p in proofs5[:200]]
    cap = {}
    for procs in (1, 2, 4, 8):
        if procs > (os.cpu_count() or 1):
            continue
        with ProcessPoolExecutor(max_workers=procs, initializer=_cap_init,
                                 initargs=(format(int(pp.n), "x"), enc)) as ex:
            list(ex.map(_cap_run, [0.2] * procs))              # warm-up
            t0 = time.perf_counter()
            done = sum(ex.map(_cap_run, [args.capacity_seconds] * procs))
            cap[procs] = done / (time.perf_counter() - t0)
    report["verify_capacity_per_s_k5"] = cap

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(report, f, indent=2)

    b2, b5, s, e = report["ballot_proof_k2"], report["ballot_proof_k5"], report["schnorr_p256"], report["ecdsa_p256"]
    f = lambda d: f"{d['mean']:.2f} ± {d['sd']:.2f} (p99 {d['p99']:.2f})"
    print("\n" + "=" * 100)
    print(f"  SECTION 5.8 — PROOF OVERHEAD  (Paillier {args.key_bits}-bit; {args.gen} generations, {args.ver} verifications each)")
    print("=" * 100)
    print(f"  {'Scheme':<36}{'Generate (ms)':>26}{'Verify (ms)':>26}{'Size':>10}")
    print(f"  {'Ballot validity, k = 2 (incl. encrypt)':<36}{f(b2['generate_incl_encryption_ms']):>26}{f(b2['verify_ms']):>26}{str(b2['proof_bytes'])+' B':>10}")
    print(f"  {'Ballot validity, k = 5 (incl. encrypt)':<36}{f(b5['generate_incl_encryption_ms']):>26}{f(b5['verify_ms']):>26}{str(b5['proof_bytes'])+' B':>10}")
    print(f"  {'Schnorr PoK, P-256 (credential)':<36}{f(s['generate_ms']):>26}{f(s['verify_ms']):>26}{str(s['proof_bytes'])+' B':>10}")
    print(f"  {'ECDSA P-256 device signature':<36}{f(e['sign_ms']):>26}{f(e['verify_ms']):>26}{str(e['signature_bytes'])+' B':>10}")
    print("  " + "-" * 96)
    print("  Ballot-proof verification capacity (k = 5): " +
          ", ".join(f"{p} proc: {v:,.0f}/s" for p, v in cap.items()))
    print(f"  Results written to {args.out}")
    print("=" * 100)


if __name__ == "__main__":
    main()
