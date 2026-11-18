/**
 * On-device ballot encryption and ballot-validity proof.
 *
 * Byte-for-byte compatible with backend/app/services/ballot_proof.py:
 *   - raw Paillier with g = n + 1:  c = (1 + m·n) · rⁿ  mod n²
 *   - per slot, a Cramer–Damgård–Schoenmakers OR-proof that c encrypts 0 or 1
 *     (c or c·g⁻¹ is an n-th residue), plus a proof that the slots sum to 1;
 *   - Fiat–Shamir over SHA-256 with 128-bit challenges, bound to the election
 *     and to the ticket's nullifier ("<election_id>|sha256(uti)").
 *
 * Offline / online split. All full-size exponentiations (rⁿ, ρⁿ, zⁿ mod n²)
 * do not depend on the voter's choice, so `precompute` runs them while the
 * voter is reading the ballot. `finishBallot` then needs only 128-bit
 * exponentiations and hashing, so pressing "Cast vote" is near-instant.
 * Every precomputation is fresh randomness used for exactly one ballot.
 */
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils";
import {
  bitLength, bytesToBigInt, mod, modInv, modPow, randBits, randUnit,
  toFixedBytes, toMinimalBytes,
} from "./bigint";

export const CHALLENGE_BITS = 128;
const CHALLENGE_MOD = 1n << BigInt(CHALLENGE_BITS);

export type PublicParams = { n: bigint; n2: bigint; gInv: bigint; nBytes: number; n2Bytes: number };

export function publicParamsFromHex(nHex: string): PublicParams {
  const n = BigInt("0x" + nHex);
  const n2 = n * n;
  return {
    n, n2, gInv: mod(1n - n, n2),
    nBytes: Math.ceil(bitLength(n) / 8),
    n2Bytes: Math.ceil(bitLength(n2) / 8),
  };
}

/** Context string the server uses: "<election_id>|<hex sha256 of the ticket>". */
export function proofContext(electionId: string, uti: string): string {
  return `${electionId}|${bytesToHex(sha256(utf8ToBytes(uti)))}`;
}

/* ── Fiat–Shamir, identical to ballot_proof._h ───────────────────────────── */
type Part = string | bigint | number | Uint8Array;

function H(...parts: Part[]): bigint {
  const h = sha256.create();
  for (const p of parts) {
    let b: Uint8Array;
    if (typeof p === "string") b = utf8ToBytes(p);
    else if (typeof p === "bigint") b = toMinimalBytes(p);
    else if (typeof p === "number") b = toMinimalBytes(BigInt(p));
    else b = p;
    const len = new Uint8Array(4);
    new DataView(len.buffer).setUint32(0, b.length, false);
    h.update(len);
    h.update(b);
  }
  return bytesToBigInt(h.digest()) % CHALLENGE_MOD;
}

function ballotDigest(pp: PublicParams, cts: bigint[], context: string): Uint8Array {
  const h = sha256.create();
  h.update(utf8ToBytes(context));
  h.update(toFixedBytes(pp.n, pp.nBytes));
  for (const c of cts) h.update(toFixedBytes(c, pp.n2Bytes));
  return h.digest();
}

/* ── Offline phase ───────────────────────────────────────────────────────── */
export type SlotPre = { r: bigint; rn: bigint; rho: bigint; an: bigint; zf: bigint; zn: bigint; ef: bigint };
export type Precomputed = { k: number; slots: SlotPre[]; sumRho: bigint; sumA: bigint; used: boolean };

const yieldToUi = () => new Promise<void>((res) => setTimeout(res, 0));

/**
 * Run the 3k + 1 full-size exponentiations for a k-candidate ballot.
 * Yields to the UI between exponentiations; `onProgress` gets 0..1.
 */
export async function precompute(
  pp: PublicParams, k: number, onProgress?: (f: number) => void,
): Promise<Precomputed> {
  const total = 3 * k + 1;
  let done = 0;
  const step = async () => { done++; onProgress?.(done / total); await yieldToUi(); };
  const slots: SlotPre[] = [];
  for (let i = 0; i < k; i++) {
    const r = randUnit(pp.n);   const rn = modPow(r, pp.n, pp.n2);   await step();
    const rho = randUnit(pp.n); const an = modPow(rho, pp.n, pp.n2); await step();
    const zf = randUnit(pp.n);  const zn = modPow(zf, pp.n, pp.n2);  await step();
    slots.push({ r, rn, rho, an, zf, zn, ef: randBits(CHALLENGE_BITS) });
  }
  const sumRho = randUnit(pp.n);
  const sumA = modPow(sumRho, pp.n, pp.n2);
  await step();
  return { k, slots, sumRho, sumA, used: false };
}

/* ── Online phase ────────────────────────────────────────────────────────── */
export type OrProof = { a0: bigint; a1: bigint; e0: bigint; e1: bigint; z0: bigint; z1: bigint };
export type BallotProof = { or: OrProof[]; sum: { a: bigint; z: bigint } };

export function finishBallot(
  pp: PublicParams, pre: Precomputed, choice: number, context: string,
): { cts: bigint[]; proof: BallotProof } {
  if (pre.used) throw new Error("precomputation already used — randomness must never be reused");
  if (!(choice >= 0 && choice < pre.k)) throw new Error("choice out of range");
  pre.used = true;
  const { n, n2, gInv } = pp;

  const cts = pre.slots.map((s, i) => (i === choice ? ((1n + n) * s.rn) % n2 : s.rn));
  const bd = ballotDigest(pp, cts, context);

  const ors: OrProof[] = pre.slots.map((s, i) => {
    const m = i === choice ? 1 : 0;
    const f = 1 - m;
    const u = [cts[i], (cts[i] * gInv) % n2];
    const a: bigint[] = [0n, 0n], e: bigint[] = [0n, 0n], z: bigint[] = [0n, 0n];
    // simulated (false) branch: a_f = z_fⁿ · u_f^(−e_f)
    e[f] = s.ef;
    z[f] = s.zf;
    a[f] = (s.zn * modPow(modInv(u[f], n2), s.ef, n2)) % n2;
    // real branch: a_m = ρⁿ, e_m = H − e_f, z_m = ρ · r^(e_m)
    a[m] = s.an;
    const eTotal = H("or", bd, i, cts[i], a[0], a[1]);
    e[m] = mod(eTotal - e[f], CHALLENGE_MOD);
    z[m] = (s.rho * modPow(s.r, e[m], n)) % n;
    return { a0: a[0], a1: a[1], e0: e[0], e1: e[1], z0: z[0], z1: z[1] };
  });

  let R = 1n;
  for (const s of pre.slots) R = (R * s.r) % n;
  const eSum = H("sum", bd, pre.sumA);
  const zSum = (pre.sumRho * modPow(R, eSum, n)) % n;

  // wipe the witnesses
  for (const s of pre.slots) { s.r = 0n; s.rho = 0n; }
  pre.sumRho = 0n;

  return { cts, proof: { or: ors, sum: { a: pre.sumA, z: zSum } } };
}

/* ── Wire format, identical to ballot_proof.encode ───────────────────────── */
export function encodeBallot(cts: bigint[], proof: BallotProof): { ciphertext: string; zkp_proof: string } {
  const hx = (x: bigint) => x.toString(16);
  const ciphertext = JSON.stringify(cts.map(hx));
  const zkp_proof = JSON.stringify({
    or: proof.or.map((p) => ({ a0: hx(p.a0), a1: hx(p.a1), e0: hx(p.e0), e1: hx(p.e1), z0: hx(p.z0), z1: hx(p.z1) })),
    sum: { a: hx(proof.sum.a), z: hx(proof.sum.z) },
  });
  return { ciphertext, zkp_proof };
}
