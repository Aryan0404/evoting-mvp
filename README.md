# Consensus-free electronic voting — prototype

A blockchain-free e-voting pipeline: atomic one-time ballot tickets (Redis
`GETDEL`), an append-only ledger (Apache Pulsar / BookKeeper), an air-gapped
forensic replica that re-verifies SHA-256 Merkle roots every 5 seconds,
Schnorr zero-knowledge proofs (NIST P-256) and Paillier homomorphic tallying.

## Reproduce every experiment in the paper

Requires Docker (Docker Desktop on macOS/Windows) with about 8 GB of memory.

```bash
git clone <this repository>
cd evoting-mvp
# .env is created automatically from .env.example on the first run (random secrets, never committed)
./run_paper_experiments.sh smoke  # 2-minute functional check
./run_paper_experiments.sh        # every experiment in Section 5 (~70–90 minutes)
```

The ledger runs as a real local cluster — Apache Pulsar with four BookKeeper
storage nodes, ensemble 3, write quorum 2, ack quorum 2 (`docker-compose.cluster.yml`).
Every vote in every experiment is a complete, valid ballot package: a Paillier
one-hot ballot, a zero-knowledge proof that it is well formed, a fresh
timestamp and an ECDSA P-256 device signature, all checked by the server.

| Step | Section | What it measures | Output |
|---|---|---|---|
| `smoke` | — | end-to-end functional check (votes, rejections, tamper → lockdown → restore) | `smoke.txt` |
| `crypto` | 5.4, 5.9 | full election (5,000 voters, ballot proofs, threshold decryption), Merkle receipts, bisection — mean ± SD over 5 runs | `crypto.json` |
| `zkp` | 5.8 | ballot-validity proof (k = 2, 5), Schnorr, ECDSA; verification capacity per core count | `zkp.json` |
| `tally` | 5.9 | homomorphic tally of 100K / 1M / 10M ballots, sequential vs parallel, memory, 3-of-5 decryption | `tally.json` |
| `load` | 5.3 | throughput ceiling (closed loop, 3 runs) | `load_closed_*.json` |
| `latency` | 5.3 | latency at a steady 100 votes/s (open loop, 3 independent runs) | `load_open_*.json` |
| `sweep` | 5.6 | offered-load sweep 50–400 votes/s with admission control, collector scaling 1–8 workers | `load_sweep.json`, `load_closed_w*.json` |
| `locust` | 5.3 | 200 users, ramp 20/s, 120 s | `locust.json` |
| `adversarial` | 5.10 | 1,000 replays, five forgery types, double voting, 10% / 50% invalid traffic | `adversarial.json`, `load_mix.json` |
| `integrity` | 5.5 | insider tampering of the primary ledger: detection latency, exact localisation, lockdown; liveness when the replica stops | `integrity_*.json` |
| `fault` | 5.7 | storage node killed, replica killed, storage quorum lost — no vote lost | `ft_summary.json` |
| `stress` | 5.12 | sustained ledger throughput with real ballot-sized records | `ledger_stress*.json` |
| `summary` | all | collects everything into one report | `paper_results.md` |

Results are written to `backend/paper/results/docker/`.

### Literature-matched benchmarks

`./run_paper_experiments.sh lit` runs the system under the same scenarios as the compared papers (about 2 hours; each `lit-*` step can also run on its own). Results are summarised in `lit_results.md`.

| Step | Scenario |
|---|---|
| `lit-wr` | Burst (all votes in 5 s) and even (spread over 60 s) voting with 1,000–5,000 votes; write speed, then read speed: ledger read-back, primary-ledger scan, receipt lookups, Merkle audit paths, counting |
| `lit-window` | 15-minute voting window, even and burst, plus a 5-minute tail: votes cast, durable and replica-verified at 0–20 min |
| `lit-rates` | Send rates 50–250 votes/s, 1,000 votes per round, 5 rounds, no retries |
| `lit-clients` | One sequential client (9,000 votes) and seven sequential clients |
| `lit-concurrent` | 10,000 votes submitted at once, with voter-app retries |
| `lit-ledger` | Replicated ledger offered 1,000–8,000 ballot records/s, read back and compared byte for byte |
| `lit-crypto` | Verifying election records of 25–1,341 ballots (6 contests), per-operation costs for a 7-contest ballot, tally of 64 and 1,024 voters |

### Architecture as deployed by `docker compose`

* **Vote collectors** (`backend`): Algorithm 1 — timestamp, one-time ticket, ballot-validity ZKP, device signature, then an atomic Redis `GETDEL` and the ledger append.
* **Ledger** (`pulsar` + `bookie1..4`): append-only, replicated, no consensus protocol.
* **Ledger worker** (`ledger-worker`): materialises the primary vote ledger in PostgreSQL.
* **Primary integrity service** (`integrity`): every 5 s re-hashes the primary ledger, publishes bundle roots and a fresh liveness nonce through the one-way stream and to the bulletin board.
* **Forensic replica** (`replica`): write-once copy of every ballot; compares roots, localises tampering by Merkle bisection, raises the lockdown alert, answers liveness nonces. It sits on an isolated network that reaches only the broker and the bulletin board.
* **Public bulletin board** (`bulletin`): election key, commitments, replica verdicts, alerts. Read via `/api/v1/audit/board`, `/audit/liveness`, `/audit/alerts`.
* **Admission control**: each collector process accepts at most `LIMIT_CONCURRENCY` (default 64) concurrent requests and answers the rest with an immediate 503, before the ticket is touched, so overload is shed instead of building an unbounded queue.

## Mobile app (`mobile/`, Expo / React Native)

The phone does all voter-side cryptography itself, in TypeScript (`mobile/src/crypto/`), byte-compatible with the Python verifier:

* **Registration**: after the liveness check, the phone creates an ECDSA P-256 key, keeps it in the OS keystore-backed secure storage, and sends only the public key with `/registration/verify-identity`; the returned one-time ticket is stored the same way.
* **Ballot**: `GET /api/v1/election` gives the trustees' Paillier key and the candidate list. While the voter reads the ballot, the phone precomputes all full-size exponentiations; when they press *Submit* it finishes the one-hot encryption and ballot-validity proof, signs the package and sends it to `/vote/cast`. Transient failures are retried with a fresh timestamp; the ticket is deleted only after the server's receipt.
* **Verification**: `/audit/proof/{receipt}` returns the Merkle path and the bundle root published by the replica; the phone recomputes the root from its own receipt.
* **Device benchmark** (home screen link): times key generation, precomputation, proof completion, signing and the receipt check on the phone, for the paper.

Run: `cd mobile && npm install && npx expo run:android` (a native rebuild is needed because the app now uses `expo-secure-store` and `react-native-get-random-values`). Set the server address in `app.json` → `extra.BASE_URL`.

Interop check against a running stack: `cd mobile && npx esbuild scripts/interop-check.ts --bundle --platform=node --outfile=/tmp/ic.js && node /tmp/ic.js`, which casts real ballots built by the app's code and expects 201, then 409 for a replay and 422 for a proof bound to another ticket.

## Author

**Aryan Poojary** — author and maintainer ([@Aryan0404](https://github.com/Aryan0404)).

## Licence

Released under the [MIT License](LICENSE).

The face-liveness endpoint expects a photo you supply yourself (for example in
the Postman collection under `backend/tests/`); no face images are included in
this repository.
