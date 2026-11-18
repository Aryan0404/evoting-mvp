#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  Reproduce every benchmark reported in the paper — locally, with Docker.
#
#    ./benchmark.sh                      # everything (crypto suite: 5 repeats)
#    REPEATS=3 ./benchmark.sh            # fewer crypto repeats, faster
#    CLUSTER=1 ./benchmark.sh            # live tests on the replicated 4-bookie
#                                        # ledger (E=3/Qw=2/Qa=2), as in the paper
#    CLUSTER=1 SKIP_CRYPTO=1 ./benchmark.sh   # live tests only
#
#  Requirements: Docker (Desktop on macOS/Windows), ~8 GB RAM for Docker.
#  Results are written to backend/paper/results/docker/
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail
cd "$(dirname "$0")"

REPEATS="${REPEATS:-5}"
LOADTEST_VOTES="${LOADTEST_VOTES:-20000}"
CLUSTER="${CLUSTER:-0}"
SKIP_CRYPTO="${SKIP_CRYPTO:-0}"
OUT="backend/paper/results/docker"
mkdir -p "$OUT"

if [[ "$CLUSTER" == "1" ]]; then
  C="docker compose -f docker-compose.yml -f docker-compose.cluster.yml"
  SFX="_cluster"; LEDGER="4-bookie cluster, E=3/Qw=2/Qa=2"
else
  C="docker compose"
  SFX=""; LEDGER="Pulsar standalone (single bookie)"
fi
FAILED=""
step() {  # step <name> <output file> <command...>
  local name="$1" file="$2"; shift 2
  "$@" 2>&1 | grep -v -E '^[0-9-]+ [0-9:.]+ (INFO|WARN) ' | tee "$file"
  local rc=${PIPESTATUS[0]}
  if [[ $rc -ne 0 ]]; then echo "!! step '$name' failed (exit $rc) — continuing"; FAILED="$FAILED $name"; fi
}
wait_for() {  # wait_for <description> <timeout_s> <command...>
  local what="$1" limit="$2"; shift 2
  echo -n "Waiting for $what"
  for _ in $(seq 1 "$limit"); do
    if "$@" >/dev/null 2>&1; then echo " — ready"; return 0; fi
    echo -n "."; sleep 1
  done
  echo " — TIMED OUT"; return 1
}

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
echo "Host:   ${HOST_LABEL}"
echo "Ledger: ${LEDGER}"
echo

# ── 1. Build and start the full stack ───────────────────────────────────────
echo "== [1/5] Building and starting the stack =="
if [[ "$CLUSTER" == "1" ]]; then
  $C rm -sf zookeeper pulsar-init bookie1 bookie2 bookie3 bookie4 pulsar >/dev/null 2>&1 || true
fi
$C up -d --build --remove-orphans || { echo "Stack failed to start"; exit 1; }
wait_for "the ledger (Pulsar broker + storage)" 300 \
  $C exec -T pulsar curl -sf http://localhost:8080/admin/v2/brokers/health || exit 1
if [[ "$CLUSTER" == "1" ]]; then
  $C exec -T pulsar bin/pulsar-admin namespaces set-persistence public/default \
    --bookkeeper-ensemble 3 --bookkeeper-write-quorum 2 --bookkeeper-ack-quorum 2 \
    --ml-mark-delete-max-rate 0
  $C restart backend replica >/dev/null
fi
wait_for "the backend" 180 curl -sf http://localhost:8000/docs || exit 1

{
  echo "host: ${HOST_LABEL}"
  echo "ledger: ${LEDGER}"
  echo "date_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "git_commit: $(git rev-parse HEAD 2>/dev/null || echo unknown)"
  echo "docker: $(docker version --format '{{.Server.Version}}')"
  echo "compose: $(docker compose version --short)"
  echo "repeats: ${REPEATS}"
  echo "loadtest_votes: ${LOADTEST_VOTES}"
} > "$OUT/setup${SFX}.txt"

# ── 2. Cryptographic / algorithmic suite (repeated, mean ± SD) ──────────────
if [[ "$SKIP_CRYPTO" == "1" ]]; then
  echo "== [2/5] Cryptographic benchmarks: skipped (SKIP_CRYPTO=1) =="
else
  echo "== [2/5] Cryptographic benchmarks: ZKP, Paillier tally, Merkle, full election (${REPEATS} repeats) =="
  step crypto "$OUT/crypto.txt" $C exec -T backend python -m tools.run_all_benchmarks_real \
    --repeats "$REPEATS" --host-label "$HOST_LABEL" --out /app/paper/results/docker/crypto.json
fi

# ── 3. Component ceilings ───────────────────────────────────────────────────
echo "== [3/5] Component ceilings: Redis GETDEL, Pulsar ingest, SHA-256 =="
step components "$OUT/components${SFX}.txt" $C exec -T backend python -m tools.bench_components

# ── 4. Adversarial tests on the live system ─────────────────────────────────
echo "== [4/5] Adversarial: replay, 50% bogus flood, tamper localisation =="
step adversarial "$OUT/adversarial${SFX}.txt" $C exec -T backend python tools/bench_adversarial.py

# ── 5. End-to-end vote throughput ───────────────────────────────────────────
echo "== [5/5] End-to-end vote throughput (${LOADTEST_VOTES} votes) =="
step loadtest "$OUT/loadtest${SFX}.txt" $C exec -T backend python -m tools.loadtest \
  --votes "$LOADTEST_VOTES" --concurrency 100

echo
if [[ -z "$FAILED" ]]; then
  echo "All benchmarks finished. Results: $OUT/"
else
  echo "Finished with failed steps:$FAILED — see the files in $OUT/"
fi
ls -1 "$OUT"
[[ -z "$FAILED" ]]
