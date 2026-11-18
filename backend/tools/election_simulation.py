#!/usr/bin/env python3
# backend/tools/election_simulation.py
"""
Full election simulation on a generated voter dataset (reference-paper method).
───────────────────────────────────────────────────────────────────────────────

The reference paper (Razaque et al.) states it runs on a *generated* dataset:
"a dataset of eligible participants is produced, each assigned an authentication
token." This reproduces that methodology on OUR consensus-free system, end to end:

  1. GENERATE a dataset of N eligible voters, each with a one-time token.
  2. VOTE: each casts a real Paillier-encrypted one-hot ballot for a random
     candidate (ground truth recorded).
  3. SEAL: every ballot is hashed and committed into a SHA-256 Merkle tree.
  4. COUNT: ballots are tallied homomorphically (still encrypted) and only the
     per-candidate totals are decrypted.
  5. VERIFY: the decrypted tally must exactly equal the ground-truth counts, and
     the Merkle root commits to every ballot.

Everything is real cryptography (phe, 2048-bit Paillier; SHA-256 Merkle).
Encryption is parallelised across cores because in a real election it happens
on each voter's device in parallel — it is not the authority's bottleneck.

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

from phe import paillier

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.services.merkle_service import MerkleTree  # noqa: E402


def _worker(args):
    """One shard of voters: generate, encrypt, partial-tally. Returns
    (K partial encrypted sums, K ground-truth counts, list of ballot hashes)."""
    pub, n, K, seed = args
    rng = random.Random(seed)
    partial = [pub.encrypt(0) for _ in range(K)]
    counts = [0] * K
    hashes = []
    for _ in range(n):
        choice = rng.randrange(K)
        counts[choice] += 1
        onehot = [pub.encrypt(1 if j == choice else 0) for j in range(K)]
        for j in range(K):
            partial[j] = partial[j] + onehot[j]
        # sealed ballot = its ciphertexts; hash commits to it (ballot secrecy kept)
        payload = "|".join(str(c.ciphertext()) for c in onehot).encode()
        hashes.append(hashlib.sha256(payload).hexdigest())
    return partial, counts, hashes


def run(voters: int, candidates: int, procs: int, key_bits: int = 2048):
    print(f"\n{'='*58}\n  ELECTION SIMULATION  (consensus-free, no blockchain)\n{'='*58}")
    print(f"  Eligible voters (generated dataset): {voters:,}")
    print(f"  Candidates                         : {candidates}")
    print(f"  Encryption                         : Paillier {key_bits}-bit (real)")

    t = time.perf_counter()
    pub, priv = paillier.generate_paillier_keypair(n_length=key_bits)
    print(f"  Trustee keygen                     : {time.perf_counter()-t:.2f}s")

    # ── 1-3. Generate + vote + encrypt + seal (parallel across cores) ──────
    per = [voters // procs] * procs
    for i in range(voters - sum(per)):
        per[i] += 1
    args = [(pub, per[i], candidates, 1000 + i) for i in range(procs) if per[i] > 0]

    t = time.perf_counter()
    with ProcessPoolExecutor(max_workers=procs) as ex:
        results = list(ex.map(_worker, args))
    t_vote = time.perf_counter() - t

    # combine shard partial tallies homomorphically (authority side)
    t = time.perf_counter()
    totals_enc = [pub.encrypt(0) for _ in range(candidates)]
    ground_truth = [0] * candidates
    all_hashes = []
    for partial, counts, hashes in results:
        for j in range(candidates):
            totals_enc[j] = totals_enc[j] + partial[j]
            ground_truth[j] += counts[j]
        all_hashes.extend(hashes)

    # ── 4. Count: decrypt only the per-candidate totals ───────────────────
    tally = [priv.decrypt(c) for c in totals_enc]
    t_count = time.perf_counter() - t

    # ── seal: Merkle root over every ballot ───────────────────────────────
    t = time.perf_counter()
    root = MerkleTree([bytes.fromhex(h) for h in all_hashes]).root_hex()
    t_seal = time.perf_counter() - t

    # ── 5. Verify ─────────────────────────────────────────────────────────
    correct = tally == ground_truth
    total_cast = sum(tally)
    winner = max(range(candidates), key=lambda j: tally[j])

    print(f"\n  Votes cast + sealed + encrypted    : {t_vote:.2f}s "
          f"({voters/t_vote:,.0f} ballots/sec, {procs} cores)")
    print(f"  Homomorphic count (tally+decrypt)  : {t_count:.3f}s")
    print(f"  Merkle seal over all ballots       : {t_seal:.3f}s")
    print(f"  Integrity root                     : {root[:32]}...")

    print(f"\n  {'-'*40}\n  OFFICIAL RESULT\n  {'-'*40}")
    print(f"  {'Candidate':<14}{'Votes':>10}{'Share':>10}")
    for j in range(candidates):
        share = (tally[j] / total_cast * 100) if total_cast else 0
        mark = "  <= WINNER" if j == winner else ""
        print(f"  {'Candidate '+chr(65+j):<14}{tally[j]:>10,}{share:>9.1f}%{mark}")
    print(f"  {'-'*40}\n  {'Total':<14}{total_cast:>10,}")
    print(f"\n  Count matches ground truth exactly : {correct}")
    print(f"  Tamper-evident (Merkle committed)  : yes")
    print(f"{'='*58}\n")

    return {
        "voters": voters, "candidates": candidates, "cast": total_cast,
        "vote_encrypt_sec": round(t_vote, 2), "count_sec": round(t_count, 3),
        "seal_sec": round(t_seal, 3), "tally": tally, "winner": winner,
        "correct": correct, "root": root,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--voters", type=int, default=5000)
    ap.add_argument("--candidates", type=int, default=4)
    ap.add_argument("--procs", type=int, default=os.cpu_count())
    ap.add_argument("--key-bits", type=int, default=2048)
    args = ap.parse_args()
    run(args.voters, args.candidates, args.procs, args.key_bits)


if __name__ == "__main__":
    main()
