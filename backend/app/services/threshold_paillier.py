# backend/app/services/threshold_paillier.py
"""
Threshold Paillier decryption — t of K trustees (Algorithm 6, lines 10–13).
───────────────────────────────────────────────────────────────────────────────

Shoup-style threshold Paillier (Fouque–Poupard–Stern, FC 2000):

  • n = p·q with safe primes p = 2p'+1, q = 2q'+1;  m = p'·q'.
  • The decryption exponent d satisfies d ≡ 0 (mod m) and d ≡ 1 (mod n).
  • d is Shamir-shared among K trustees with a random polynomial of degree
    t−1 over Z_{n·m};  trustee i holds s_i = f(i).
  • Partial decryption by trustee i:   c_i = c^{2Δ·s_i} mod n²,  Δ = K!.
  • Any t partials combine with integer Lagrange coefficients μ_i = Δ·λ_{0,i}:
        c' = Π c_i^{2μ_i} = c^{4Δ²d}  ⇒  M = L(c') · (4Δ²)^{-1} mod n,
    where L(x) = (x − 1)/n.

Fewer than t shares reveal nothing about d. The public key is the ordinary
Paillier key (n, g = n+1), so ballots encrypted with `phe` or with
`ballot_proof.encrypt_ballot` decrypt correctly.

The trusted-dealer key generation is a one-off ceremony before the election;
its cost is reported separately from decryption.
"""

from __future__ import annotations

import math
import secrets
from dataclasses import dataclass
from typing import Dict, List, Sequence

import gmpy2
from gmpy2 import mpz, powmod


def _safe_prime(bits: int) -> tuple[mpz, mpz]:
    """Return (p, p') with p = 2p' + 1, both prime, p of the given bit length."""
    while True:
        q = mpz(secrets.randbits(bits - 1)) | (mpz(1) << (bits - 2)) | 1
        q = gmpy2.next_prime(q)
        # walk forward through primes q until 2q+1 is prime too
        for _ in range(20000):
            p = 2 * q + 1
            if p.bit_length() != bits:
                break
            # cheap filters before the full test
            if p % 3 != 0 and gmpy2.is_prime(p, 25):
                return p, q
            q = gmpy2.next_prime(q)


@dataclass
class ThresholdKey:
    n: mpz
    n2: mpz
    K: int
    t: int
    delta: mpz
    shares: Dict[int, mpz]          # trustee index (1..K) -> secret share s_i

    @property
    def public_n(self) -> int:
        return int(self.n)


def keygen(bits: int = 2048, K: int = 5, t: int = 3) -> ThresholdKey:
    if not (1 <= t <= K):
        raise ValueError("need 1 <= t <= K")
    half = bits // 2
    while True:
        p, p1 = _safe_prime(half)
        q, q1 = _safe_prime(half)
        if p != q and (p * q).bit_length() == bits:
            break
    n = p * q
    m = p1 * q1
    nm = n * m
    d = (m * gmpy2.invert(m, n)) % nm          # d ≡ 0 mod m, d ≡ 1 mod n
    coeffs = [d] + [mpz(secrets.randbelow(int(nm))) for _ in range(t - 1)]
    shares = {}
    for i in range(1, K + 1):
        acc = mpz(0)
        for c in reversed(coeffs):
            acc = (acc * i + c) % nm
        shares[i] = acc
    return ThresholdKey(n=n, n2=n * n, K=K, t=t, delta=mpz(math.factorial(K)), shares=shares)


def partial_decrypt(key: ThresholdKey, i: int, c) -> mpz:
    """Trustee i's decryption share of ciphertext c."""
    return powmod(mpz(c), 2 * key.delta * key.shares[i], key.n2)


def _lagrange_times_delta(i: int, S: Sequence[int], delta: mpz) -> mpz:
    num, den = mpz(1), mpz(1)
    for j in S:
        if j == i:
            continue
        num *= j
        den *= (j - i)
    val = delta * num
    assert val % den == 0
    return val // den


def combine(key: ThresholdKey, partials: Dict[int, mpz]) -> int:
    """Combine at least t partial decryptions into the plaintext."""
    S = sorted(partials)[: key.t]
    if len(S) < key.t:
        raise ValueError(f"need {key.t} shares, got {len(S)}")
    n, n2 = key.n, key.n2
    acc = mpz(1)
    for i in S:
        mu = _lagrange_times_delta(i, S, key.delta)
        base = partials[i] if mu >= 0 else gmpy2.invert(partials[i], n2)
        acc = (acc * powmod(base, 2 * abs(mu), n2)) % n2
    L = (acc - 1) // n
    return int((L * gmpy2.invert(4 * key.delta * key.delta, n)) % n)


def decrypt_totals(key: ThresholdKey, ciphertexts: Sequence, trustees: Sequence[int]) -> List[int]:
    """Full ceremony for a vector of encrypted totals using the given trustees."""
    out = []
    for c in ciphertexts:
        parts = {i: partial_decrypt(key, i, c) for i in trustees}
        out.append(combine(key, parts))
    return out
