#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  Reproduce every benchmark reported in the paper — locally, with Docker.
#
#    ./benchmark.sh                  # 5 repeats of the crypto suite (default)
#    REPEATS=3 ./benchmark.sh        # fewer repeats, faster
#
#  Requirements: Docker (Desktop on macOS/Windows), ~8 GB RAM for Docker.
#  Results are written to backend/paper/results/docker/
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
cd "$(dirname "$0")"

REPEATS="${REPEATS:-5}"
LOADTEST_VOTES="${LOADTEST_VOTES:-20000}"
OUT="backend/paper/results/docker"
mkdir -p "$OUT"

# ── Describe the physical host (goes into every result file) ────────────────
if [[ "$(uname)" == "Darwin" ]]; then
  HOST_CPU="$(sysctl -n machdep.cpu.brand_string)"
  HOST_RAM="$(( $(sysctl -n hw.memsize) / 1073741824 )) GB"
else
  HOST_CPU="$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | xargs || true)"
  HOST_CPU="${HOST_CPU:-$(uname -m)}"
  HOST_RAM="$(awk '/MemTotal/{printf "%d GB", $2/1048576}' /proc/meminfo)"
fi
read -r DCPU DMEM <<<"$(docker info --format '{{.NCPU}} {{.MemTotal}}')"
DOCKER_RES="${DCPU} CPUs, $(awk -v m="$DMEM" 'BEGIN{printf "%.1f GB", m/1073741824}')"
HOST_LABEL="${HOST_CPU}, ${HOST_RAM} RAM; Docker allocation: ${DOCKER_RES}"

echo "Host: ${HOST_LABEL}"
echo

# ── 1. Build and start the full stack ───────────────────────────────────────
echo "== [1/5] Building and starting the stack (Postgres, Redis, Pulsar, backend, replica) =="
docker compose up -d --build
echo -n "Waiting for the backend to come up"
for _ in $(seq 1 120); do
  if curl -sf http://localhost:8000/docs >/dev/null; then break; fi
  echo -n "."; sleep 2
done
echo
curl -sf http://localhost:8000/docs >/dev/null || { echo "Backend did not start — run: docker compose logs backend"; exit 1; }

{
  echo "host: ${HOST_LABEL}"
  echo "date_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "git_commit: $(git rev-parse HEAD 2>/dev/null || echo unknown)"
  echo "docker: $(docker version --format '{{.Server.Version}}')"
  echo "compose: $(docker compose version --short)"
  echo "repeats: ${REPEATS}"
  echo "loadtest_votes: ${LOADTEST_VOTES}"
} > "$OUT/setup.txt"

# ── 2. Cryptographic / algorithmic suite (repeated, mean ± SD) ──────────────
echo "== [2/5] Cryptographic benchmarks: ZKP, Paillier tally, Merkle, full election (${REPEATS} repeats) =="
docker compose exec -T backend python -m tools.run_all_benchmarks_real \
  --repeats "$REPEATS" --host-label "$HOST_LABEL" \
  --out /app/paper/results/docker/crypto.json | tee "$OUT/crypto.txt"

# ── 3. Component ceilings ───────────────────────────────────────────────────
echo "== [3/5] Component ceilings: Redis GETDEL, Pulsar ingest, SHA-256 =="
docker compose exec -T backend python -m tools.bench_components | tee "$OUT/components.txt"

# ── 4. Adversarial tests on the live system ─────────────────────────────────
echo "== [4/5] Adversarial: replay, 50% bogus flood, tamper localisation =="
docker compose exec -T backend python tools/bench_adversarial.py | tee "$OUT/adversarial.txt"

# ── 5. End-to-end vote throughput ───────────────────────────────────────────
echo "== [5/5] End-to-end vote throughput (${LOADTEST_VOTES} votes) =="
docker compose exec -T backend python -m tools.loadtest \
  --votes "$LOADTEST_VOTES" --concurrency 100 | tee "$OUT/loadtest.txt"

echo
echo "All benchmarks finished. Results: $OUT/"
ls -1 "$OUT"
