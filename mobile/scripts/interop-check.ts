import { publicParamsFromHex, precompute, finishBallot, encodeBallot, proofContext } from "../src/crypto/ballot";
import { newDeviceKey, publicKeyHex, packageBytes, packageTimestamp, signPackage } from "../src/crypto/device";
import { execSync } from "child_process";
import { randomBytes } from "crypto";

// Interop check: phone crypto (this TypeScript) against the Python server.
// Seeds tickets directly in the ticket store, so run it against a local stack:
//   cd mobile && npx esbuild scripts/interop-check.ts --bundle --platform=node --outfile=/tmp/ic.js && node /tmp/ic.js
// Env: API (default http://localhost:8000/api/v1), REDIS_CLI (default "docker exec evoting_redis redis-cli")
const API = process.env.API ?? "http://localhost:8000/api/v1";
const REDIS_CLI = process.env.REDIS_CLI ?? "docker exec evoting_redis redis-cli";
async function main() {
  const el = await (await fetch(`${API}/election`)).json();
  const pp = publicParamsFromHex(el.public_n);
  const k = el.num_candidates;
  const offset = el.server_time * 1000 - Date.now();
  const results: any[] = [];
  for (let trial = 0; trial < 3; trial++) {
    const priv = newDeviceKey();
    const pk = publicKeyHex(priv);
    const uti = randomBytes(32).toString("hex");
    execSync(`${REDIS_CLI} set ballot_ticket:${uti} ${pk} EX 600`);
    const t0 = performance.now();
    const pre = await precompute(pp, k);
    const t1 = performance.now();
    const choice = trial % k;
    const { cts, proof } = finishBallot(pp, pre, choice, proofContext(el.election_id, uti));
    const { ciphertext, zkp_proof } = encodeBallot(cts, proof);
    const ts = packageTimestamp(offset);
    const signature = signPackage(priv, packageBytes(el.election_id, uti, k, ciphertext, zkp_proof, ts));
    const t2 = performance.now();
    const res = await fetch(`${API}/vote/cast`, { method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ uti, ciphertext, zkp_proof, num_candidates: k, ts, signature }) });
    const body = await res.json();
    results.push({ status: res.status, precompute_ms: Math.round(t1 - t0), online_ms: Math.round(t2 - t1), receipt: body.ballot_hash });
    // replay must fail
    if (trial === 0) {
      const r2 = await fetch(`${API}/vote/cast`, { method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ uti, ciphertext, zkp_proof, num_candidates: k, ts, signature }) });
      results.push({ replay_status: r2.status });
    }
  }
  // wrong choice-proof: tamper one ciphertext → 422
  const priv = newDeviceKey(); const uti = randomBytes(32).toString("hex");
  execSync(`${REDIS_CLI} set ballot_ticket:${uti} ${publicKeyHex(priv)} EX 600`);
  const pre = await precompute(pp, k);
  const { cts, proof } = finishBallot(pp, pre, 1, proofContext(el.election_id, "f".repeat(64)));  // bound to another ticket
  const enc = encodeBallot(cts, proof); const ts = packageTimestamp(offset);
  const sig = signPackage(priv, packageBytes(el.election_id, uti, k, enc.ciphertext, enc.zkp_proof, ts));
  const r3 = await fetch(`${API}/vote/cast`, { method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ uti, ...enc, num_candidates: k, ts, signature: sig }) });
  results.push({ proof_for_other_ticket_status: r3.status });
  console.log(JSON.stringify(results, null, 1));
}
main();
