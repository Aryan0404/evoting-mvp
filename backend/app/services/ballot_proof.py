# backend/app/services/ballot_proof.py
"""
Ballot-validity zero-knowledge proof for Paillier one-hot ballots.
───────────────────────────────────────────────────────────────────────────────

A ballot for k candidates is k Paillier ciphertexts c_1..c_k encrypting a
one-hot vector v (each v_i ∈ {0,1} and Σ v_i = 1). The proof π convinces the
server that the ballot is well-formed WITHOUT revealing the chosen candidate:

  • for every i: a Cramer–Damgård–Schoenmakers OR-proof that c_i encrypts 0
    or 1 — i.e. that c_i (case 0) or c_i·g⁻¹ (case 1) is an n-th residue
    modulo n²;
  • a proof that Π c_i · g⁻¹ is an n-th residue, i.e. that the k plaintexts
    sum to exactly 1.

Each statement uses the Σ-protocol for n-th residuosity (commitment
a = ρⁿ, challenge e, response z = ρ·rᵉ mod n, check zⁿ ≡ a·uᵉ mod n²),
made non-interactive with Fiat–Shamir over SHA-256. All hashes bind the
election context and the full ballot, so proofs cannot be transplanted.

Verification batches all 2k+1 equations into ONE full-size exponentiation
using the small-exponent test (Bellare–Garay–Rabin): pick random 64-bit δ_j
and check  (Π z_j^{δ_j})^{2n} ≡ Π (a_j · u_j^{e_j})^{2δ_j}  (mod n²).
Squaring removes the order-2 elements of Z*_{n²}; accepting a factor that is
a square root of unity does not affect soundness because such factors are
themselves n-th residues. A cheating proof passes with probability ≤ 2⁻⁶³.

Encryption here is raw Paillier with g = n + 1 so the randomness r is known
to the prover; ciphertexts are fully compatible with the `phe` library used by
the homomorphic tally.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
from dataclasses import dataclass
from typing import List, Sequence, Tuple

import gmpy2
from gmpy2 import mpz, powmod

CHALLENGE_BITS = 128
CHALLENGE_MOD = mpz(1) << CHALLENGE_BITS
BATCH_BITS = 64


# ─────────────────────────────────────────────────────────────────────────────
#  Raw Paillier (g = n + 1)
# ─────────────────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class PublicParams:
    n: mpz
    n2: mpz
    g_inv: mpz          # (n+1)^-1 mod n² = 1 - n

    @classmethod
    def from_n(cls, n) -> "PublicParams":
        n = mpz(n)
        n2 = n * n
        return cls(n=n, n2=n2, g_inv=(1 - n) % n2)


def _rand_unit(n: mpz) -> mpz:
    while True:
        r = mpz(secrets.randbelow(int(n) - 1) + 1)
        if gmpy2.gcd(r, n) == 1:
            return r


def encrypt_bit(pp: PublicParams, m: int, r: mpz | None = None) -> Tuple[mpz, mpz]:
    """Return (ciphertext, randomness) for plaintext m with g = n + 1."""
    if r is None:
        r = _rand_unit(pp.n)
    c = ((1 + m * pp.n) * powmod(r, pp.n, pp.n2)) % pp.n2
    return c, r


def encrypt_ballot(pp: PublicParams, choice: int, k: int) -> Tuple[List[mpz], List[mpz]]:
    cts, rs = [], []
    for i in range(k):
        c, r = encrypt_bit(pp, 1 if i == choice else 0)
        cts.append(c)
        rs.append(r)
    return cts, rs


# ─────────────────────────────────────────────────────────────────────────────
#  Fiat–Shamir
# ─────────────────────────────────────────────────────────────────────────────
def _h(*parts) -> mpz:
    hsh = hashlib.sha256()
    for p in parts:
        if isinstance(p, (int, type(mpz(0)))):
            b = int(p).to_bytes((int(p).bit_length() + 7) // 8 or 1, "big")
        elif isinstance(p, str):
            b = p.encode()
        else:
            b = bytes(p)
        hsh.update(len(b).to_bytes(4, "big"))
        hsh.update(b)
    return mpz(int.from_bytes(hsh.digest(), "big")) % CHALLENGE_MOD


def _ballot_digest(pp: PublicParams, cts: Sequence[mpz], context: str) -> bytes:
    hsh = hashlib.sha256(context.encode())
    hsh.update(int(pp.n).to_bytes((int(pp.n).bit_length() + 7) // 8, "big"))
    for c in cts:
        hsh.update(int(c).to_bytes((int(pp.n2).bit_length() + 7) // 8, "big"))
    return hsh.digest()


# ─────────────────────────────────────────────────────────────────────────────
#  Prover
# ─────────────────────────────────────────────────────────────────────────────
def prove_ballot(pp: PublicParams, cts: Sequence[mpz], rs: Sequence[mpz],
                 choice: int, context: str) -> dict:
    n, n2, g_inv = pp.n, pp.n2, pp.g_inv
    bd = _ballot_digest(pp, cts, context)
    ors = []
    for i, (c, r) in enumerate(zip(cts, rs)):
        m = 1 if i == choice else 0
        u = (c, (c * g_inv) % n2)              # statements for "0" and "1"
        a = [None, None]
        e = [None, None]
        z = [None, None]
        # simulate the false branch
        f = 1 - m
        e[f] = mpz(secrets.randbits(CHALLENGE_BITS))
        z[f] = _rand_unit(n)
        a[f] = (powmod(z[f], n, n2) * powmod(gmpy2.invert(u[f], n2), e[f], n2)) % n2
        # commit for the true branch
        rho = _rand_unit(n)
        a[m] = powmod(rho, n, n2)
        e_total = _h("or", bd, i, c, a[0], a[1])
        e[m] = (e_total - e[f]) % CHALLENGE_MOD
        z[m] = (rho * powmod(r, e[m], n)) % n
        ors.append({"a0": a[0], "a1": a[1], "e0": e[0], "e1": e[1], "z0": z[0], "z1": z[1]})

    # sum proof: Π c_i · g⁻¹ is an n-th residue with witness Π r_i
    C = mpz(1)
    R = mpz(1)
    for c, r in zip(cts, rs):
        C = (C * c) % n2
        R = (R * r) % n
    U = (C * g_inv) % n2
    rho = _rand_unit(n)
    a = powmod(rho, n, n2)
    e = _h("sum", bd, a)
    z = (rho * powmod(R, e, n)) % n
    return {"or": ors, "sum": {"a": a, "z": z}}


# ─────────────────────────────────────────────────────────────────────────────
#  Verifier
# ─────────────────────────────────────────────────────────────────────────────
def _collect_equations(pp: PublicParams, cts: Sequence[mpz], proof: dict, context: str):
    """Return list of (z, a, u, e) such that a valid proof satisfies zⁿ ≡ a·uᵉ (mod n²),
    or None if a structural / Fiat–Shamir check fails."""
    n, n2, g_inv = pp.n, pp.n2, pp.g_inv
    if len(proof.get("or", [])) != len(cts) or len(cts) == 0:
        return None
    bd = _ballot_digest(pp, cts, context)
    eqs = []
    for i, (c, p) in enumerate(zip(cts, proof["or"])):
        a0, a1, e0, e1, z0, z1 = (mpz(p[x]) for x in ("a0", "a1", "e0", "e1", "z0", "z1"))
        if not (0 <= e0 < CHALLENGE_MOD and 0 <= e1 < CHALLENGE_MOD):
            return None
        if (e0 + e1) % CHALLENGE_MOD != _h("or", bd, i, c, a0, a1):
            return None
        eqs.append((z0, a0, c, e0))
        eqs.append((z1, a1, (c * g_inv) % n2, e1))
    C = mpz(1)
    for c in cts:
        C = (C * c) % n2
    U = (C * g_inv) % n2
    a, z = mpz(proof["sum"]["a"]), mpz(proof["sum"]["z"])
    eqs.append((z, a, U, _h("sum", bd, a)))
    for zz, aa, uu, _ in eqs:
        if not (0 < zz < n) or not (0 < aa < n2) or not (0 < uu < n2):
            return None
        if gmpy2.gcd(zz, n) != 1 or gmpy2.gcd(aa, n) != 1 or gmpy2.gcd(uu, n) != 1:
            return None
    return eqs


def verify_ballot(pp: PublicParams, cts: Sequence[mpz], proof: dict, context: str) -> bool:
    """Batched verification: one full-size exponentiation per ballot."""
    try:
        cts = [mpz(c) for c in cts]
        eqs = _collect_equations(pp, cts, proof, context)
    except Exception:
        return False
    if eqs is None:
        return False
    n, n2 = pp.n, pp.n2
    left = mpz(1)
    right = mpz(1)
    for z, a, u, e in eqs:
        d = mpz(int.from_bytes(os.urandom(BATCH_BITS // 8), "big") | 1)
        left = (left * powmod(z, d, n2)) % n2
        right = (right * powmod(a, d, n2) * powmod(u, e * d, n2)) % n2
    left = powmod(left, 2 * n, n2)
    right = powmod(right, 2, n2)
    return left == right


def verify_ballot_unbatched(pp: PublicParams, cts: Sequence[mpz], proof: dict, context: str) -> bool:
    """Reference verifier: checks every equation separately (2k+1 full exponentiations)."""
    try:
        cts = [mpz(c) for c in cts]
        eqs = _collect_equations(pp, cts, proof, context)
    except Exception:
        return False
    if eqs is None:
        return False
    n, n2 = pp.n, pp.n2
    return all(powmod(z, n, n2) == (a * powmod(u, e, n2)) % n2 for z, a, u, e in eqs)


# ─────────────────────────────────────────────────────────────────────────────
#  Wire format
# ─────────────────────────────────────────────────────────────────────────────
def encode(cts: Sequence[mpz], proof: dict) -> Tuple[str, str]:
    """Serialise ciphertexts and proof as compact JSON with hex integers."""
    ct_json = json.dumps([format(int(c), "x") for c in cts], separators=(",", ":"))
    pj = {"or": [{k: format(int(v), "x") for k, v in p.items()} for p in proof["or"]],
          "sum": {k: format(int(v), "x") for k, v in proof["sum"].items()}}
    return ct_json, json.dumps(pj, separators=(",", ":"))


def decode(ct_json: str, proof_json: str) -> Tuple[List[mpz], dict]:
    cts = [mpz(x, 16) for x in json.loads(ct_json)]
    pj = json.loads(proof_json)
    proof = {"or": [{k: mpz(v, 16) for k, v in p.items()} for p in pj["or"]],
             "sum": {k: mpz(v, 16) for k, v in pj["sum"].items()}}
    return cts, proof


def proof_size_bytes(proof_json: str) -> int:
    """Binary size of the proof (hex digits / 2), excluding JSON punctuation."""
    pj = json.loads(proof_json)
    hexlen = sum(len(v) for p in pj["or"] for v in p.values()) + sum(len(v) for v in pj["sum"].values())
    return (hexlen + 1) // 2
