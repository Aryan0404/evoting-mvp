# backend/app/services/zkp_service.py
"""
Zero-Knowledge Proof service — real Schnorr (elliptic-curve).
─────────────────────────────────────────────────────────────

A voter attaches a short proof that their ballot was formed correctly WITHOUT
revealing anything about it. The building block is a Schnorr proof of knowledge
of a discrete logarithm, made non-interactive with the Fiat–Shamir transform:

    Public:  P = x·G    (G is the curve generator, x is the secret)
    Prove:   r ← random;  R = r·G;  c = H(G,P,R,msg);  s = r + c·x (mod n)
    Proof:   (R, s)   — ~65 bytes compressed
    Verify:  s·G  ==  R + c·P

This replaces the SHA-256 "mock ZKP" used in the old benchmark harness with a
real, sound proof, so the Section 5.6 numbers (proof size, generation time,
verification time) become real measurements.

A full ballot-validity proof ("exactly one candidate chosen") is a disjunctive
(one-of-K) composition of these Schnorr proofs, so its cost is ≈ K × the base
numbers measured here. We measure the honest building block and state the
composition factor rather than inventing a figure.
"""

from __future__ import annotations

import hashlib
import secrets
import time
from typing import Tuple

from ecdsa import NIST256p

# NIST P-256: 128-bit security, the curve the paper targets.
_CURVE = NIST256p
_G = _CURVE.generator
_N = _CURVE.order


def _encode_point(pt) -> bytes:
    """33-byte compressed SEC1 encoding (0x02/0x03 prefix + x)."""
    x = pt.x().to_bytes(32, "big")
    prefix = b"\x03" if (pt.y() & 1) else b"\x02"
    return prefix + x


def _challenge(public_pt, commitment_pt, msg: bytes) -> int:
    """Fiat–Shamir challenge c = H(G, P, R, msg) mod n."""
    h = hashlib.sha256()
    h.update(_encode_point(_G * 1))
    h.update(_encode_point(public_pt))
    h.update(_encode_point(commitment_pt))
    h.update(msg)
    return int.from_bytes(h.digest(), "big") % _N


def keypair() -> Tuple[int, object]:
    """Return (secret x, public P = x·G)."""
    x = secrets.randbelow(_N - 1) + 1
    return x, x * _G


def prove(secret: int, public_pt, msg: bytes = b"") -> Tuple[bytes, int]:
    """
    Produce a Schnorr proof of knowledge of `secret` (the discrete log of
    public_pt), bound to `msg` (e.g. the ballot ciphertext). Returns
    (R_compressed, s).
    """
    r = secrets.randbelow(_N - 1) + 1
    R = r * _G
    c = _challenge(public_pt, R, msg)
    s = (r + c * secret) % _N
    return _encode_point(R), s


def verify(public_pt, proof: Tuple[bytes, int], msg: bytes = b"") -> bool:
    """Verify a Schnorr proof: s·G == R + c·P."""
    from ecdsa.ellipticcurve import Point

    R_bytes, s = proof
    # decompress R
    R = _CURVE.curve.point_from_bytes(R_bytes) if hasattr(_CURVE.curve, "point_from_bytes") \
        else _point_from_compressed(R_bytes)
    c = _challenge(public_pt, R, msg)
    lhs = s * _G
    rhs = R + (c * public_pt)
    return lhs == rhs


def _point_from_compressed(data: bytes):
    """Decompress a SEC1 point for ecdsa versions without point_from_bytes."""
    from ecdsa.ellipticcurve import Point

    p = _CURVE.curve.p()
    a = _CURVE.curve.a()
    b = _CURVE.curve.b()
    prefix = data[0]
    x = int.from_bytes(data[1:33], "big")
    alpha = (pow(x, 3, p) + a * x + b) % p
    y = pow(alpha, (p + 1) // 4, p)  # p ≡ 3 (mod 4) for P-256
    if (y & 1) != (prefix & 1):
        y = p - y
    return Point(_CURVE.curve, x, y)


def proof_size_bytes(proof: Tuple[bytes, int]) -> int:
    """Wire size of a proof: compressed R + 32-byte scalar s."""
    R_bytes, _ = proof
    return len(R_bytes) + 32


def run_zkp_benchmark(n_samples: int = 500) -> dict:
    """
    Real Section 5.6 measurement: generate and verify n Schnorr proofs,
    reporting mean generation time, verification time, and proof size.
    """
    secret, public_pt = keypair()
    msg = b"ballot-ciphertext-placeholder"

    gen_times, ver_times = [], []
    size = 0
    all_valid = True
    for _ in range(n_samples):
        t0 = time.perf_counter()
        proof = prove(secret, public_pt, msg)
        gen_times.append(time.perf_counter() - t0)

        t0 = time.perf_counter()
        ok = verify(public_pt, proof, msg)
        ver_times.append(time.perf_counter() - t0)
        all_valid &= ok
        size = proof_size_bytes(proof)

    # soundness spot-check: a wrong proof must fail
    bad = (prove(secret, public_pt, msg)[0], (prove(secret, public_pt, msg)[1] + 1) % _N)
    forged_rejected = not verify(public_pt, bad, msg)

    def ms(xs):
        xs = sorted(xs)
        return {
            "mean": round(sum(xs) / len(xs) * 1000, 4),
            "median": round(xs[len(xs) // 2] * 1000, 4),
            "p99": round(xs[min(len(xs) - 1, int(len(xs) * 0.99))] * 1000, 4),
        }

    return {
        "scheme": "schnorr-NIST-P256",
        "n_samples": n_samples,
        "proof_size_bytes": size,
        "gen_time_ms": ms(gen_times),
        "verify_time_ms": ms(ver_times),
        "all_valid": all_valid,
        "forged_rejected": forged_rejected,
    }
