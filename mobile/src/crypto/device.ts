/**
 * Device signing key and ballot-package signatures (Algorithm 1, step 4).
 *
 * Compatible with backend/app/services/device_sig.py:
 *   - ECDSA P-256 over SHA-256, DER-encoded signature as hex;
 *   - public key registered as a compressed point (hex, 33 bytes);
 *   - signed bytes: election_id | uti | k | ciphertext | proof | ts(3 decimals).
 *
 * The private key never leaves the phone. It is kept in the OS keystore-backed
 * secure storage (see secureStore.ts). Note for the paper: this is a software
 * key protected by the Keychain / Android Keystore, not a key generated inside
 * the Secure Enclave or StrongBox, which would need a native module.
 */
import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils";

export function newDeviceKey(): string {
  return bytesToHex(p256.utils.randomPrivateKey());
}

export function publicKeyHex(privHex: string): string {
  return bytesToHex(p256.getPublicKey(hexToBytes(privHex), true));
}

/**
 * Timestamps are whole milliseconds expressed in seconds, so that JavaScript's
 * toFixed(3) and Python's f"{ts:.3f}" always print the same digits.
 */
export function packageTimestamp(serverOffsetMs = 0): number {
  return Math.round(Date.now() + serverOffsetMs) / 1000;
}

export function packageBytes(
  electionId: string, uti: string, k: number, ciphertext: string, proof: string, ts: number,
): Uint8Array {
  return utf8ToBytes([electionId, uti, String(k), ciphertext, proof, ts.toFixed(3)].join("|"));
}

export function signPackage(privHex: string, message: Uint8Array): string {
  return p256.sign(sha256(message), hexToBytes(privHex)).toDERHex();
}
