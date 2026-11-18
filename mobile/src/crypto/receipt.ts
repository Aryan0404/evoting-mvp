/**
 * Receipt verification on the voter's own device.
 *
 * The server returns the Merkle audit path for the voter's receipt
 * (ballot_hash) and the bundle root published by the air-gapped replica on the
 * bulletin board. The phone recomputes the root from ITS OWN receipt and the
 * path; only if it equals the replica's root is the ballot proven to be in
 * the ledger exactly as cast. Same tree rules as merkle_service.py:
 * SHA-256(left || right), sibling side given per level.
 */
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";

export type PathStep = { side: "L" | "R"; hash: string };

export function rootFromPath(leafHex: string, path: PathStep[]): string {
  let acc = hexToBytes(leafHex);
  for (const step of path) {
    const sib = hexToBytes(step.hash);
    const buf = new Uint8Array(64);
    if (step.side === "R") { buf.set(acc, 0); buf.set(sib, 32); }
    else { buf.set(sib, 0); buf.set(acc, 32); }
    acc = sha256(buf);
  }
  return bytesToHex(acc);
}

export function verifyInclusion(receiptHex: string, path: PathStep[], replicaRootHex: string): boolean {
  return rootFromPath(receiptHex.toLowerCase(), path) === replicaRootHex.toLowerCase();
}
