/**
 * Arbitrary-precision helpers on native BigInt (Hermes and V8 both support it).
 *
 * Byte conventions match the Python verifier exactly:
 *   - minimal big-endian bytes, with 0 encoded as a single 0x00 byte
 *     (Python: int.to_bytes((x.bit_length()+7)//8 or 1, "big"))
 *   - fixed-length big-endian bytes where the protocol pads to a length.
 */
import { randomBytes } from "@noble/hashes/utils";

export function bitLength(x: bigint): number {
  return x === 0n ? 0 : x.toString(2).length;
}

export function bytesToBigInt(b: Uint8Array): bigint {
  let hex = "";
  for (let i = 0; i < b.length; i++) hex += b[i].toString(16).padStart(2, "0");
  return hex.length ? BigInt("0x" + hex) : 0n;
}

/** Big-endian bytes of exactly `len` bytes (throws if x does not fit). */
export function toFixedBytes(x: bigint, len: number): Uint8Array {
  let hex = x.toString(16);
  if (hex.length > len * 2) throw new Error("integer does not fit in " + len + " bytes");
  hex = hex.padStart(len * 2, "0");
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

/** Minimal big-endian bytes; 0 → [0x00]. */
export function toMinimalBytes(x: bigint): Uint8Array {
  return toFixedBytes(x, Math.max(1, Math.ceil(bitLength(x) / 8)));
}

export function mod(a: bigint, m: bigint): bigint {
  const r = a % m;
  return r < 0n ? r + m : r;
}

export function gcd(a: bigint, b: bigint): bigint {
  a = a < 0n ? -a : a;
  b = b < 0n ? -b : b;
  while (b) [a, b] = [b, a % b];
  return a;
}

export function modInv(a: bigint, m: bigint): bigint {
  let [r0, r1] = [mod(a, m), m];
  let [s0, s1] = [1n, 0n];
  while (r1) {
    const q = r0 / r1;
    [r0, r1] = [r1, r0 - q * r1];
    [s0, s1] = [s1, s0 - q * s1];
  }
  if (r0 !== 1n) throw new Error("not invertible");
  return mod(s0, m);
}

/** base^exp mod m, fixed 4-bit window (about 1.25 multiplications per exponent bit). */
export function modPow(base: bigint, exp: bigint, m: bigint): bigint {
  if (m === 1n) return 0n;
  base = mod(base, m);
  if (exp === 0n) return 1n;
  const table: bigint[] = [1n, base];
  for (let i = 2; i < 16; i++) table.push((table[i - 1] * base) % m);
  const hex = exp.toString(16);
  let acc = table[parseInt(hex[0], 16)];
  for (let i = 1; i < hex.length; i++) {
    acc = (acc * acc) % m;
    acc = (acc * acc) % m;
    acc = (acc * acc) % m;
    acc = (acc * acc) % m;
    const d = parseInt(hex[i], 16);
    if (d) acc = (acc * table[d]) % m;
  }
  return acc;
}

/** Uniform integer in [0, n). */
export function randBelow(n: bigint): bigint {
  const bits = bitLength(n);
  const bytes = Math.ceil(bits / 8);
  const excess = BigInt(bytes * 8 - bits);
  for (;;) {
    const x = bytesToBigInt(randomBytes(bytes)) >> excess;
    if (x < n) return x;
  }
}

export function randBits(bits: number): bigint {
  const bytes = Math.ceil(bits / 8);
  return bytesToBigInt(randomBytes(bytes)) >> BigInt(bytes * 8 - bits);
}

/** Uniform unit of Z*_n (Python: randbelow(n-1)+1 with gcd check). */
export function randUnit(n: bigint): bigint {
  for (;;) {
    const r = randBelow(n - 1n) + 1n;
    if (gcd(r, n) === 1n) return r;
  }
}
