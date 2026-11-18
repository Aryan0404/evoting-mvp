# backend/tools/ballot_factory.py
"""
Valid ballot packages for load and adversarial experiments.
───────────────────────────────────────────────────────────────────────────────

Every package sent by the experiments is fully valid under Algorithm 1:
a one-hot Paillier ballot, a ballot-validity proof bound to the election and
to that package's own ticket, a fresh timestamp, and an ECDSA P-256 signature
by the device key registered with the ticket. The server performs the full
verification on every one.

Producing tens of thousands of proofs from scratch would dominate experiment
time, so the factory uses the standard offline/online split of Σ-protocols:
all full-size exponentiations of a proof (ρⁿ for the real branches, zⁿ·u⁻ᵉ for
the simulated branches, rⁿ for the ciphertexts) are computed once per
*template*; binding a template to a new ticket needs only the Fiat–Shamir
hash and a few 128-bit exponentiations mod n. A phone can use exactly the
same split, precomputing while the voter reads the ballot.

Load-test only: reusing a template's randomness across packages would leak
information about that ballot's randomness, which is irrelevant for synthetic
votes but must never be done by a real voter device (devices use
`ballot_proof.prove_ballot`, which is what Section 5.8 measures).
"""

from __future__ import annotations

import hashlib
import os
import secrets
import time
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from typing import List

import gmpy2
from gmpy2 import mpz, powmod

from app.services import ballot_proof as bp
from app.services import device_sig

ELECTION_ID = os.environ.get("ELECTION_ID", "election-2026")


# ── templates: all expensive exponentiations done once ──────────────────────
def _make_template(args):
    n_hex, k, choice = args
    pp = bp.PublicParams.from_n(int(n_hex, 16))
    n, n2, g_inv = pp.n, pp.n2, pp.g_inv
    cts, rs = bp.encrypt_ballot(pp, choice, k)
    slots = []
    for i, (c, r) in enumerate(zip(cts, rs)):
        m = 1 if i == choice else 0
        f = 1 - m
        u = (c, (c * g_inv) % n2)
        e_f = mpz(secrets.randbits(bp.CHALLENGE_BITS))
        z_f = bp._rand_unit(n)
        a_f = (powmod(z_f, n, n2) * powmod(gmpy2.invert(u[f], n2), e_f, n2)) % n2
        rho = bp._rand_unit(n)
        a_m = powmod(rho, n, n2)
        slots.append({"m": m, "e_f": int(e_f), "z_f": int(z_f), "a_f": int(a_f),
                      "rho": int(rho), "a_m": int(a_m), "r": int(r), "c": int(c)})
    R = mpz(1)
    for r in rs:
        R = (R * r) % n
    rho = bp._rand_unit(n)
    return {"k": k, "choice": choice, "slots": slots, "R": int(R),
            "sum_rho": int(rho), "sum_a": int(powmod(rho, n, n2)), "cts": [int(c) for c in cts]}


def make_templates(n_hex: str, k: int, count: int, procs: int | None = None) -> List[dict]:
    procs = procs or os.cpu_count() or 1
    args = [(n_hex, k, i % k) for i in range(count)]
    if procs == 1:
        return [_make_template(a) for a in args]
    with ProcessPoolExecutor(max_workers=procs) as ex:
        return list(ex.map(_make_template, args))


def instantiate(pp: bp.PublicParams, tpl: dict, context: str) -> tuple[str, str]:
    """Bind a template to a context (election | nullifier): cheap online phase."""
    n = pp.n
    cts = [mpz(c) for c in tpl["cts"]]
    bd = bp._ballot_digest(pp, cts, context)
    ors = []
    for i, s in enumerate(tpl["slots"]):
        m, f = s["m"], 1 - s["m"]
        a = [None, None]; e = [None, None]; z = [None, None]
        a[f], e[f], z[f] = mpz(s["a_f"]), mpz(s["e_f"]), mpz(s["z_f"])
        a[m] = mpz(s["a_m"])
        e_total = bp._h("or", bd, i, cts[i], a[0], a[1])
        e[m] = (e_total - e[f]) % bp.CHALLENGE_MOD
        z[m] = (mpz(s["rho"]) * powmod(mpz(s["r"]), e[m], n)) % n
        ors.append({"a0": a[0], "a1": a[1], "e0": e[0], "e1": e[1], "z0": z[0], "z1": z[1]})
    a = mpz(tpl["sum_a"])
    e = bp._h("sum", bd, a)
    z = (mpz(tpl["sum_rho"]) * powmod(mpz(tpl["R"]), e, n)) % n
    return bp.encode(cts, {"or": ors, "sum": {"a": a, "z": z}})


# ── packages ────────────────────────────────────────────────────────────────
@dataclass
class Package:
    uti: str
    key: object            # device private key (ECDSA P-256)
    pk_hex: str
    k: int
    ciphertext: str
    proof: str
    choice: int

    def body(self, ts: float | None = None, tamper: str | None = None) -> dict:
        """JSON body with a fresh timestamp and a valid signature.
        tamper ∈ {None, 'proof', 'signature', 'timestamp'} corrupts one field."""
        ts = time.time() if ts is None else ts
        proof = self.proof
        if tamper == "proof":
            proof = proof.replace('"z0":"', '"z0":"1', 1)
        if tamper == "timestamp":
            ts = ts - 3600
        msg = device_sig.package_bytes(ELECTION_ID, self.uti, self.k, self.ciphertext, proof, ts)
        sig = device_sig.sign(self.key, msg)
        if tamper == "signature":
            sig = device_sig.sign(device_sig.new_device_key(), msg)
        return {"uti": self.uti, "ciphertext": self.ciphertext, "zkp_proof": proof,
                "num_candidates": self.k, "ts": ts, "signature": sig}


def make_packages(n_hex: str, count: int, k: int = 2, templates: int = 64,
                  procs: "int | None" = None) -> List[Package]:
    pp = bp.PublicParams.from_n(int(n_hex, 16))
    tpls = make_templates(n_hex, k, min(templates, max(count, 1)), procs)
    out = []
    for j in range(count):
        uti = secrets.token_hex(32)
        nullifier = hashlib.sha256(uti.encode()).hexdigest()
        tpl = tpls[j % len(tpls)]
        ct, pr = instantiate(pp, tpl, f"{ELECTION_ID}|{nullifier}")
        key = device_sig.new_device_key()
        out.append(Package(uti, key, device_sig.public_key_hex(key), k, ct, pr, tpl["choice"]))
    return out


async def seed_tickets(redis, packages: List[Package], ttl: int = 7200) -> None:
    pipe = redis.pipeline(transaction=False)
    for p in packages:
        pipe.set(f"ballot_ticket:{p.uti}", p.pk_hex, ex=ttl)
    await pipe.execute()


async def election_n_hex(bulletin) -> str:
    n_hex = await bulletin.get("election:public_n")
    if not n_hex:
        raise SystemExit("No election key on the bulletin board — run: python -m tools.election_setup")
    return n_hex
