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
cp .env.example .env              # then set POSTGRES_USER, POSTGRES_PASSWORD, SECRET_KEY
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
| `load` | 5.3, 5.6 | throughput ceiling, latency at 100 votes/s, offered-load sweep, collector scaling | `load_*.json` |
| `locust` | 5.3 | 200 users, ramp 20/s, 120 s | `locust.json` |
| `adversarial` | 5.10 | 1,000 replays, five forgery types, double voting, 10% / 50% invalid traffic | `adversarial.json`, `load_mix.json` |
| `integrity` | 5.5 | insider tampering of the primary ledger: detection latency, exact localisation, lockdown; liveness when the replica stops | `integrity_*.json` |
| `fault` | 5.7 | storage node killed, replica killed, storage quorum lost — no vote lost | `ft_summary.json` |
| `stress` | 5.12 | sustained ledger throughput with real ballot-sized records | `ledger_stress*.json` |
| `summary` | all | collects everything into one report | `paper_results.md` |

Results are written to `backend/paper/results/docker/`.

### Architecture as deployed by `docker compose`

* **Vote collectors** (`backend`): Algorithm 1 — timestamp, one-time ticket, ballot-validity ZKP, device signature, then an atomic Redis `GETDEL` and the ledger append.
* **Ledger** (`pulsar` + `bookie1..4`): append-only, replicated, no consensus protocol.
* **Ledger worker** (`ledger-worker`): materialises the primary vote ledger in PostgreSQL.
* **Primary integrity service** (`integrity`): every 5 s re-hashes the primary ledger, publishes bundle roots and a fresh liveness nonce through the one-way stream and to the bulletin board.
* **Forensic replica** (`replica`): write-once copy of every ballot; compares roots, localises tampering by Merkle bisection, raises the lockdown alert, answers liveness nonces. It sits on an isolated network that reaches only the broker and the bulletin board.
* **Public bulletin board** (`bulletin`): election key, commitments, replica verdicts, alerts. Read via `/api/v1/audit/board`, `/audit/liveness`, `/audit/alerts`.

## Author

**Aryan Poojary** — author and maintainer ([@Aryan0404](https://github.com/Aryan0404)).

## Licence

Released under the [MIT License](LICENSE).

The face-liveness endpoint expects a photo you supply yourself (for example in
the Postman collection under `backend/tests/`); no face images are included in
this repository.
