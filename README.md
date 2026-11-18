# Consensus-free electronic voting — prototype

A blockchain-free e-voting pipeline: atomic one-time ballot tickets (Redis
`GETDEL`), an append-only ledger (Apache Pulsar / BookKeeper), an air-gapped
forensic replica that re-verifies SHA-256 Merkle roots every 5 seconds,
Schnorr zero-knowledge proofs (NIST P-256) and Paillier homomorphic tallying.

## Reproduce the benchmarks

Requires Docker (Docker Desktop on macOS/Windows) with about 8 GB of memory.

```bash
git clone <this repository>
cd evoting-mvp
cp .env.example .env    # then set POSTGRES_USER, POSTGRES_PASSWORD, SECRET_KEY
./benchmark.sh          # REPEATS=3 ./benchmark.sh for a quicker run
```

The script builds and starts the full stack, then runs:

| Step | What it measures | Output file |
|---|---|---|
| 2 | ZKP, Paillier tally, Merkle sealing and tamper localisation, full election (mean ± SD over `REPEATS` runs) | `crypto.txt`, `crypto.json` |
| 3 | Redis ticket, Pulsar ledger and SHA-256 throughput ceilings | `components.txt` |
| 4 | Replay attack, 50% bogus-ballot flood, tamper localisation on the live system | `adversarial.txt` |
| 5 | End-to-end vote throughput | `loadtest.txt` |

All results, plus a `setup.txt` describing the host machine and Docker
allocation, are written to `backend/paper/results/docker/`.

The cryptographic suite can also be run without Docker:

```bash
cd backend
pip install phe==1.5.0 ecdsa==0.19.2 gmpy2==2.3.2
python -m tools.run_all_benchmarks_real --repeats 5
```

## Author

**Aryan Poojary** — author and maintainer ([@Aryan0404](https://github.com/Aryan0404)).

## Licence

Released under the [MIT License](LICENSE).

The face-liveness endpoint expects a photo you supply yourself (for example in
the Postman collection under `backend/tests/`); no face images are included in
this repository.
