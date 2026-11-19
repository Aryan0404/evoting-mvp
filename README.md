# Consensus-free electronic voting — prototype

A blockchain-free e-voting pipeline: atomic one-time ballot tickets (Redis
`GETDEL`), an append-only ledger (Apache Pulsar / BookKeeper), an air-gapped
forensic replica that re-verifies SHA-256 Merkle roots every 5 seconds,
Schnorr zero-knowledge proofs (NIST P-256) and Paillier homomorphic tallying.

## Reproduce every experiment in the paper

### Requirements

| | Needed | Used for the paper |
|---|---|---|
| OS | macOS or Linux (Windows: inside WSL 2) | macOS, Apple M2, 16 GB RAM |
| Docker | Docker Desktop (or Docker Engine + Compose v2 on Linux) | Docker 29.9.3, Compose 5.7.0 |
| Docker resources | at least 8 CPUs and 12 GB memory (Docker Desktop → Settings → Resources) | 8 CPUs, 11.8 GB |
| Free disk | 15 GB (images about 3 GB, plus ledger data while the experiments run) | |
| Free ports | 5432, 6379, 6380, 6650, 8000, 8080 | |

Nothing else is installed on the host: every tool, including the load generators, runs inside the containers. Images are built from the Dockerfiles in this repository on the first run.

### Run

```bash
git clone https://github.com/Aryan0404/evoting-mvp.git
cd evoting-mvp
./run_paper_experiments.sh smoke   # about 5 minutes the first time (images build), then 2 minutes: functional check
./run_paper_experiments.sh         # every experiment in Section 5, about 70–90 minutes
```

* The first run creates `.env` from `.env.example` with fresh random secrets. It is never committed and never needs to be shared.
* The script checks Docker, Compose, memory and disk first, and prints what to fix if something is missing.
* Every run starts a fresh stack, so runs do not depend on each other. Run one invocation at a time.
* Results go to `backend/paper/results/docker/`; `paper_results.md` there is the summary the paper's tables are taken from.
* Phone timings for Table 8: `./run_phone_benchmark.sh`, then open the printed address on an iPhone or Android phone (see [Phone benchmark](#phone-benchmark-table-8-on-iphone-or-android)).
* Timings depend on the machine. Let the computer rest for 15–20 minutes before a long run, keep it plugged in, and keep other heavy programs closed.

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

### Troubleshooting

| Message | Cause | Fix |
|---|---|---|
| `docker: command not found` | Docker Desktop is not installed, or not on the shell's PATH | Install Docker Desktop and open it once. On macOS, if the install is blocked, allow Terminal under System Settings → Privacy & Security → App Management |
| `Docker is installed but not running` | Docker Desktop is closed | Open Docker Desktop and wait for "Engine running" |
| `container evoting_postgres is unhealthy` or a password error | a database volume made with an older `.env` | `docker compose -f docker-compose.yml -f docker-compose.cluster.yml down -v`, then run again |
| `no space left on device` / Docker Desktop "Disk full" | ledger data and old images | `docker compose -f docker-compose.yml -f docker-compose.cluster.yml down -v` and `docker builder prune -f`; the stress steps skip themselves below their disk limit |
| `port is already allocated` | another program uses one of the ports above | stop it (for example a local PostgreSQL or Redis) |
| a step stays on `waiting for …` for minutes | the machine is short of memory | raise Docker's memory to 12 GB |

When finished, free the machine with `docker compose -f docker-compose.yml -f docker-compose.cluster.yml down`.

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

Run: `cd mobile && npm install && npx expo run:android` (Android Studio) or `npx expo run:ios` (Xcode). The app is built natively (Expo SDK 55); the Expo Go app from the stores only runs the newest SDK, so it cannot open this project. Set the server address in `app.json` → `extra.BASE_URL` to your computer's address on the local network (for example `http://192.168.1.20:8000`; find it with `ipconfig getifaddr en0` on macOS); the phone and the computer must be on the same Wi-Fi.

Interop check against a running stack: `cd mobile && npx esbuild scripts/interop-check.ts --bundle --platform=node --outfile=/tmp/ic.js && node /tmp/ic.js`, which casts real ballots built by the app's code and expects 201, then 409 for a replay and 422 for a proof bound to another ticket.

## Phone benchmark (Table 8), on iPhone or Android

No app build needed: `mobile/benchmark/device-benchmark.html` runs the same voter-side cryptography as the app (2048-bit Paillier ballot, ballot-validity proof, ECDSA P-256 key and signature, receipt check) in the phone's browser, with the key size and ballot sizes of the paper. It needs no backend and works offline once loaded.

1. Put the phone on the same Wi-Fi as the computer (or connect the computer to the phone's hotspot).
2. On the computer: `./run_phone_benchmark.sh`. It prints an address such as `http://192.168.1.20:8090/device-benchmark.html`. If macOS asks whether to allow incoming connections, choose Allow.
3. On the phone, open that address: **Safari** on iPhone, **Chrome** on Android.
4. Plug the phone in, close other apps, tap **Run benchmark** and keep the screen on with the page open for about two minutes.
5. Tap **Copy results** (or long-press the results and copy) and note the phone model.
6. Press Ctrl+C on the computer.

The page reports mean ± SD over 5 ballots per size (20 key generations, 200 receipt checks) and prints the browser's user agent. It times the browser's JavaScript engine (JavaScriptCore on iPhone, V8 on Android); the native app's engine (Hermes) can differ, so label the figures "mobile browser".

## Author

**Aryan Poojary** — author and maintainer ([@Aryan0404](https://github.com/Aryan0404)).

## Licence

Released under the [MIT License](LICENSE).

The face-liveness endpoint expects a photo you supply yourself (for example in
the Postman collection under `backend/tests/`); no face images are included in
this repository.
