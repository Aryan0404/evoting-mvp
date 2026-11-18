/**
 * The voter's device: everything the phone does cryptographically, in order.
 *
 *   1. ensureDeviceKey()  — at registration: create (once) the signing key and
 *                           return its public key for /registration/verify-identity.
 *   2. prepareBallot()    — when the ballot opens: fetch the election key and run
 *                           the expensive precomputation in the background.
 *   3. sealBallot()       — when the voter presses "Cast": finish the proof for the
 *                           chosen slot, stamp and sign the package.
 *   4. checkReceipt()     — afterwards: verify the Merkle path to the replica's root.
 */
import {
  encodeBallot, finishBallot, precompute, proofContext, publicParamsFromHex,
  type Precomputed, type PublicParams,
} from "./ballot";
import { newDeviceKey, packageBytes, packageTimestamp, publicKeyHex, signPackage } from "./device";
import { verifyInclusion, type PathStep } from "./receipt";
import { secrets } from "./secureStore";

export async function ensureDeviceKey(): Promise<string> {
  let priv = await secrets.getDeviceKey();
  if (!priv) {
    priv = newDeviceKey();
    await secrets.setDeviceKey(priv);
  }
  return publicKeyHex(priv);
}

export type ElectionInfo = {
  election_id: string;
  public_n: string;
  num_candidates: number;
  candidates: { id: string; name: string; party: string; symbol: string; position: number }[];
  max_skew_seconds: number;
  server_time: number;
};

export type PreparedBallot = {
  election: ElectionInfo;
  pp: PublicParams;
  pre: Precomputed;
  clockOffsetMs: number;
  precomputeMs: number;
};

export async function prepareBallot(
  election: ElectionInfo, onProgress?: (f: number) => void,
): Promise<PreparedBallot> {
  const clockOffsetMs = election.server_time * 1000 - Date.now();
  const pp = publicParamsFromHex(election.public_n);
  const t0 = Date.now();
  const pre = await precompute(pp, election.num_candidates, onProgress);
  return { election, pp, pre, clockOffsetMs, precomputeMs: Date.now() - t0 };
}

export type SealedBallot = {
  uti: string;
  ciphertext: string;
  zkp_proof: string;
  num_candidates: number;
  ts: number;
  signature: string;
  sealMs: number;
};

/** choiceIndex is the 0-based slot, i.e. candidate.position − 1. */
export async function sealBallot(prepared: PreparedBallot, choiceIndex: number): Promise<SealedBallot> {
  const uti = await secrets.getTicket();
  const priv = await secrets.getDeviceKey();
  if (!uti) throw new Error("No ballot ticket on this phone. Complete registration first.");
  if (!priv) throw new Error("No device key on this phone. Complete registration first.");
  const { election, pp, pre } = prepared;
  const t0 = Date.now();
  const { cts, proof } = finishBallot(pp, pre, choiceIndex, proofContext(election.election_id, uti));
  const { ciphertext, zkp_proof } = encodeBallot(cts, proof);
  const ts = packageTimestamp(prepared.clockOffsetMs);
  const k = election.num_candidates;
  const signature = signPackage(priv, packageBytes(election.election_id, uti, k, ciphertext, zkp_proof, ts));
  return { uti, ciphertext, zkp_proof, num_candidates: k, ts, signature, sealMs: Date.now() - t0 };
}

export function checkReceipt(receiptHex: string, path: PathStep[], replicaRoot: string): boolean {
  return verifyInclusion(receiptHex, path, replicaRoot);
}

/**
 * Retry after a transient failure (network, 503): the ticket was not consumed,
 * so the same ballot and proof are sent again with a fresh timestamp and
 * signature. The proof does not cover the timestamp, so no new proof is needed.
 */
export async function restampBallot(prepared: PreparedBallot, sealed: SealedBallot): Promise<SealedBallot> {
  const priv = await secrets.getDeviceKey();
  if (!priv) throw new Error("No device key on this phone.");
  const ts = packageTimestamp(prepared.clockOffsetMs);
  const signature = signPackage(priv, packageBytes(
    prepared.election.election_id, sealed.uti, sealed.num_candidates, sealed.ciphertext, sealed.zkp_proof, ts));
  return { ...sealed, ts, signature };
}
