#!/usr/bin/env python3
# backend/tools/election_simulation.py
"""
Full election on a generated voter dataset — complete cryptographic pipeline.
───────────────────────────────────────────────────────────────────────────────

The reference paper (Razaque et al.) evaluates on a *generated* dataset of
eligible participants, each holding an authentication token. This reproduces
that methodology on our consensus-free system, end to end, with every
cryptographic step real:

  0. KEY CEREMONY   threshold Paillier key, t-of-K trustees (default 3 of 5).
  1. VOTE           every voter's device encrypts a one-hot ballot and
                    produces the ballot-validity ZKP (parallel: devices act
                    independently, so this is per-voter work, not server work).
  2. VERIFY         the server verifies every ballot proof (parallel workers).
  3. SEAL           every ballot is hashed into a SHA-256 Merkle tree.
  4. COUNT          ballots are multiplied together homomorphically
                    (sequential, one core) and only the k totals are
                    decrypted, by t of the K trustees.
  5. CHECK          the decrypted result must equal the ground truth.

Run:  python -m tools.election_simulation --voters 5000 --candidates 4
"""

from __future__ import annotations

import argparse
import hashlib
import os
import random
import sys
import time
from concurrent.futures import ProcessPoolExecutor

from gmpy2 import mpz

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.services import ballot_proof as bp          # noqa: E402
from app.services import threshold_paillier as tp    # noqa: E402
from app.services.merkle_service import MerkleTree   # noqa: E402

CONTEXT = "election-sim-2026"

_PP = None


def _init(n_hex, k=4):
    global _PP, K_CAND
    _PP = bp.PublicParams.from_n(int(n_hex, 16))
    K_CAND = k


def _vote_shard(args):
    """One shard of voters: encrypt + prove. Returns encoded ballots and timings."""
    choices, seed = args
    out, times = [], []
    for v, ch in enumerate(choices):
        t = time.perf_counter()
        cts, rs = bp.encrypt_ballot(_PP, ch, K_CAND)
        pr = bp.prove_ballot(_PP, cts, rs, ch, f"{CONTEXT}|voter-{seed}-{v}")
        times.append(time.perf_counter() - t)
        out.append((bp.encode(cts, pr), f"{CONTEXT}|voter-{seed}-{v}"))
    return out, times


def _verify_shard(items):
    ok = 0
    for (ctj, pj), ctx in items:
        cts, pr = bp.decode(ctj, pj)
        ok += bp.verify_ballot(_PP, cts, pr, ctx)
    return ok


K_CAND = 4


def run(voters: int, candidates: int, procs: int, key_bits: int = 2048,
        trustees: int = 5, threshold: int = 3, key: "tp.ThresholdKey | None" = None,
        seed: int = 2026, quiet: bool = False):
    global K_CAND
    K_CAND = candidates
    say = (lambda *a, **k: None) if quiet else print
    say(f"\n{'='*62}\n  ELECTION  (consensus-free; full cryptographic pipeline)\n{'='*62}")
    say(f"  Eligible voters (generated dataset): {voters:,}")
    say(f"  Candidates                         : {candidates}")
    say(f"  Encryption                         : Paillier {key_bits}-bit + ballot-validity ZKP")
    say(f"  Decryption                         : threshold, {threshold} of {trustees} trustees")

    keygen_s = 0.0
    if key is None:
        t = time.perf_counter()
        key = tp.keygen(key_bits, K=trustees, t=threshold)
        keygen_s = time.perf_counter() - t
        say(f"  Trustee key ceremony               : {keygen_s:.1f}s")
    pp = bp.PublicParams.from_n(key.n)

    rng = random.Random(seed)
    choices = [rng.randrange(candidates) for _ in range(voters)]
    ground_truth = [choices.count(j) for j in range(candidates)]
    per = (voters + procs - 1) // procs
    shards = [(choices[i:i + per], i) for i in range(0, voters, per)]

    # 1. voters' devices: encrypt + prove (parallel)
    t = time.perf_counter()
    with ProcessPoolExecutor(max_workers=procs, initializer=_init, initargs=(format(int(key.n), "x"), candidates)) as ex:
        res = list(ex.map(_vote_shard, shards))
        t_vote = time.perf_counter() - t
        ballots = [b for part, _ in res for b in part]
        dev_times = [x for _, ts in res for x in ts]

        # 2. server: verify every proof (parallel)
        t = time.perf_counter()
        vs = [ballots[i:i + per] for i in range(0, len(ballots), per)]
        valid = sum(ex.map(_verify_shard, vs))
        t_verify = time.perf_counter() - t

    # 3. seal
    t = time.perf_counter()
    leaves = [hashlib.sha256((ctj + pj).encode()).digest() for (ctj, pj), _ in ballots]
    root = MerkleTree(leaves).root_hex()
    t_seal = time.perf_counter() - t

    # 4. count: sequential homomorphic accumulation, then threshold decryption
    decoded = [bp.decode(ctj, pj)[0] for (ctj, pj), _ in ballots]
    t = time.perf_counter()
    T = [mpz(1)] * candidates
    n2 = pp.n2
    for cts in decoded:
        for i in range(candidates):
            T[i] = T[i] * cts[i] % n2
    t_tally = time.perf_counter() - t
    trustee_ids = list(range(1, threshold + 1))
    per_trustee, parts = [], {}
    for i in trustee_ids:
        ts = time.perf_counter()
        parts[i] = [tp.partial_decrypt(key, i, c) for c in T]
        per_trustee.append(time.perf_counter() - ts)
    tc = time.perf_counter()
    tally = [tp.combine(key, {i: parts[i][j] for i in trustee_ids}) for j in range(candidates)]
    t_combine = time.perf_counter() - tc
    t_decrypt = max(per_trustee) + t_combine        # trustees decrypt in parallel

    correct = tally == ground_truth and valid == voters
    total_cast = sum(tally)
    winner = max(range(candidates), key=lambda j: tally[j])

    say(f"\n  Voters' devices: encrypt + prove     : {t_vote:.2f}s wall ({procs} workers), "
        f"{sum(dev_times)/len(dev_times)*1000:.0f} ms per voter")
    say(f"  Server: verify all ballot proofs     : {t_verify:.2f}s wall, {valid:,}/{voters:,} valid")
    say(f"  Merkle seal over all ballots         : {t_seal:.3f}s")
    say(f"  Homomorphic tally (1 core)           : {t_tally:.3f}s")
    say(f"  Threshold decryption ({threshold} of {trustees})      : {t_decrypt*1000:.0f} ms")
    say(f"  COUNT = tally + decryption           : {t_tally + t_decrypt:.3f}s")
    say(f"  Integrity root                       : {root[:32]}...")
    say(f"\n  {'-'*40}\n  OFFICIAL RESULT\n  {'-'*40}")
    say(f"  {'Candidate':<14}{'Votes':>10}{'Share':>10}")
    for j in range(candidates):
        share = (tally[j] / total_cast * 100) if total_cast else 0
        mark = "  <= WINNER" if j == winner else ""
        say(f"  {'Candidate '+chr(65+j):<14}{tally[j]:>10,}{share:>9.1f}%{mark}")
    say(f"  {'-'*40}\n  {'Total':<14}{total_cast:>10,}")
    say(f"\n  Result matches ground truth exactly : {correct}")
    say(f"{'='*62}\n")

    return {
        "voters": voters, "candidates": candidates, "cast": total_cast,
        "trustees": trustees, "threshold": threshold, "keygen_s": keygen_s,
        "vote_encrypt_prove_wall_s": t_vote,
        "device_encrypt_prove_ms_mean": sum(dev_times) / len(dev_times) * 1000,
        "verify_wall_s": t_verify, "valid_proofs": valid,
        "seal_s": t_seal, "tally_s": t_tally, "decrypt_s": t_decrypt,
        "count_s": t_tally + t_decrypt, "tally": tally, "ground_truth": ground_truth,
        "winner": winner, "correct": correct, "root": root,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--voters", type=int, default=5000)
    ap.add_argument("--candidates", type=int, default=4)
    ap.add_argument("--procs", type=int, default=os.cpu_count())
    ap.add_argument("--key-bits", type=int, default=2048)
    ap.add_argument("--trustees", type=int, default=5)
    ap.add_argument("--threshold", type=int, default=3)
    args = ap.parse_args()
    run(args.voters, args.candidates, args.procs, args.key_bits, args.trustees, args.threshold)


if __name__ == "__main__":
    main()
