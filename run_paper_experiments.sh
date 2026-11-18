#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  Every experiment in Section 5 of the manuscript — one command, locally, with
#  Docker, on the replicated ledger (Pulsar + 4 BookKeeper nodes, E=3/Qw=2/Qa=2).
#
#    ./run_paper_experiments.sh                 # everything (~70–90 min)
#    ./run_paper_experiments.sh smoke           # 2-minute functional check only
#    ./run_paper_experiments.sh load integrity  # selected experiments
#
#  Steps: smoke crypto zkp tally load locust adversarial integrity fault stress summary
#  Results: backend/paper/results/docker/   (paper_results.md is the summary)
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail
cd "$(dirname "$0")"

C="docker compose -f docker-compose.yml -f docker-compose.cluster.yml"
OUT="backend/paper/results/docker"
REPEATS="${REPEATS:-5}"
ALL="smoke crypto zkp tally load sweep scaling locust adversarial integrity fault stress summary"
STEPS="${*:-$ALL}"
FAILED=""
# A full run starts from an empty results folder; earlier results are archived, never mixed in.
if [ $# -eq 0 ] && [ -d "$OUT" ] && [ -n "$(ls -A "$OUT" 2>/dev/null)" ]; then
  ARCHIVE="backend/paper/results/archive-$(date +%Y%m%d-%H%M%S)"
  mkdir -p backend/paper/results && mv "$OUT" "$ARCHIVE"
  echo "Earlier results moved to $ARCHIVE"
fi
mkdir -p "$OUT"

now()   { python3 -c 'import time; print(f"{time.time():.3f}")'; }
log()   { echo "[$(date +%H:%M:%S)] $*" | tee -a "$OUT/run_log.txt"; }
has()   { case " $STEPS " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }
be()    { $C exec -T backend "$@"; }
quiet() { grep --line-buffered -v -E '^[0-9-]+ [0-9:.]+ (INFO|WARN) |ClientConnection|ConnectionPool|HandlerBase|ProducerImpl|ConsumerImpl|BinaryProtoLookup|ClientImpl'; }

run_step() {  # run_step <name> <output file> <command...>
  local name="$1" file="$2"; shift 2
  log "→ $name"
  "$@" 2>&1 | quiet | tee "$OUT/$file"
  local rc=${PIPESTATUS[0]}
  if [ "$rc" -ne 0 ]; then log "!! $name failed (exit $rc)"; FAILED="$FAILED $name"; fi
  return 0
}

wait_for() {  # wait_for <description> <timeout_s> <command...>
  local what="$1" limit="$2"; shift 2
  printf "   waiting for %s" "$what"
  local i=0
  while [ "$i" -lt "$limit" ]; do
    if "$@" >/dev/null 2>&1; then echo " — ready"; return 0; fi
    printf "."; sleep 1; i=$((i + 1))
  done
  echo " — TIMED OUT"; return 1
}

host_label() {
  local cpu ram dcpu dmem
  if [ "$(uname)" = "Darwin" ]; then
    cpu="$(sysctl -n machdep.cpu.brand_string)"; ram="$(( $(sysctl -n hw.memsize) / 1073741824 )) GB"
  else
    cpu="$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | xargs)"; cpu="${cpu:-$(uname -m)}"
    ram="$(awk '/MemTotal/{printf "%d GB", $2/1048576}' /proc/meminfo)"
  fi
  read -r dcpu dmem <<EOF
$(docker info --format '{{.NCPU}} {{.MemTotal}}')
EOF
  echo "${cpu}, ${ram} RAM; Docker allocation: ${dcpu} CPUs, $(awk -v m="$dmem" 'BEGIN{printf "%.1f GB", m/1073741824}')"
}

start_stack() {
  log "Starting a fresh replicated ledger (ZooKeeper + 4 bookies + broker) and the full stack"
  $C rm -sf bulletin zookeeper pulsar-init bookie1 bookie2 bookie3 bookie4 pulsar >/dev/null 2>&1 || true
  $C up -d --build --remove-orphans || { log "stack failed to start"; exit 1; }
  wait_for "broker + storage nodes" 300 $C exec -T pulsar curl -sf http://localhost:8080/admin/v2/brokers/health || exit 1
  $C exec -T pulsar bin/pulsar-admin namespaces set-persistence public/default \
    --bookkeeper-ensemble 3 --bookkeeper-write-quorum 2 --bookkeeper-ack-quorum 2 --ml-mark-delete-max-rate 0
  { echo "Read-write bookies:"; $C exec -T pulsar bin/pulsar-admin bookies list-bookies
    echo; echo "Persistence policy:"; $C exec -T pulsar bin/pulsar-admin namespaces get-persistence public/default
  } > "$OUT/cluster.txt" 2>&1
}

reset_state() {  # identical clean start for an experiment
  # Restart the collectors FIRST: after an overload run they can still be
  # draining queued requests, and ballots they append after the ledger is
  # cleared would leak into the next experiment.
  $C restart backend >/dev/null
  wait_for "backend (drained)" 180 curl -sf http://localhost:8000/docs || exit 1
  $C stop replica ledger-worker integrity >/dev/null 2>&1
  for sub in ledger-worker forensic-replica; do
    $C exec -T pulsar bin/pulsar-admin topics skip-all persistent://public/default/ballots -s "$sub" >/dev/null 2>&1 || true
  done
  $C exec -T pulsar bin/pulsar-admin topics skip-all persistent://public/default/diode-primary -s forensic-replica-diode >/dev/null 2>&1 || true
  be python -m tools.reset_state || { log "reset failed"; exit 1; }
  be python -m tools.election_setup --reuse || { log "key ceremony failed"; exit 1; }
  $C start ledger-worker integrity replica >/dev/null
  $C restart backend >/dev/null
  wait_for "backend" 180 curl -sf http://localhost:8000/docs || exit 1
  sleep 8
}

ensembles() {
  local lids
  lids=$(docker exec evoting_pulsar bin/pulsar-admin topics stats-internal persistent://public/default/ballots 2>/dev/null \
         | grep -o '"ledgerId" : [0-9]*' | grep -o '[0-9]*$')
  for id in $lids; do
    echo "ledger $id: $(docker exec evoting_bookie1 bin/bookkeeper shell ledgermetadata -ledgerid "$id" 2>/dev/null | grep -o 'ensembles={[^}]*}')"
  done
}

second_victim() {  # a live member of the current ledger's ensemble, other than $1
  local dead="$1" execb="" lid
  for b in evoting_bookie1 evoting_bookie3 evoting_bookie4; do if [ "$b" != "$dead" ]; then execb="$b"; break; fi; done
  lid=$(docker exec evoting_pulsar bin/pulsar-admin topics stats-internal persistent://public/default/ballots 2>/dev/null \
        | grep -o '"ledgerId" : [0-9]*' | grep -o '[0-9]*$' | tail -1)
  docker exec "$execb" bin/bookkeeper shell ledgermetadata -ledgerid "$lid" 2>/dev/null | grep -o 'ensembles={[^}]*}' | \
    python3 -c '
import re, sys
groups = re.findall(r"\[([^\]]*)\]", sys.stdin.read())
members = [m.strip().split(":")[0] for m in groups[-1].split(",")] if groups else []
dead = sys.argv[1].replace("evoting_", "")
alive = [m for m in members if m != dead]
print("evoting_" + (alive[0] if alive else "bookie3"))' "$dead"
}

# ── preamble ─────────────────────────────────────────────────────────────────
: > "$OUT/run_log.txt"
HOST="$(host_label)"
log "Host: $HOST"
log "Steps: $STEPS"
start_stack
{
  echo "host: $HOST"
  echo "ledger: Apache Pulsar 3.1.0 + 4 BookKeeper nodes, E=3/Qw=2/Qa=2"
  echo "date_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "git_commit: $(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
  echo "docker: $(docker version --format '{{.Server.Version}}'); compose: $(docker compose version --short)"
} > "$OUT/setup.txt"

# ── experiments ──────────────────────────────────────────────────────────────
if has smoke; then
  reset_state
  run_step "smoke test" smoke.txt be python -m tools.smoke_test
  case "$FAILED" in *smoke*) log "Smoke test failed — stopping. Send smoke.txt."; exit 1 ;; esac
fi

if has crypto; then
  run_step "crypto suite ($REPEATS repeats: Schnorr, Merkle, full election)" crypto.txt \
    be python -m tools.run_all_benchmarks_real --repeats "$REPEATS" --host-label "$HOST" --out /app/paper/results/docker/crypto.json
fi
has zkp   && run_step "5.8 proof overhead" zkp.txt be python -m tools.bench_zkp
has tally && run_step "5.9 homomorphic tally" tally.txt be python -m tools.bench_tally

if has load; then
  for r in 1 2 3; do
    reset_state
    run_step "5.3 ceiling, run $r" "load_closed_r$r.txt" be python -m tools.bench_load closed --votes 20000 --concurrency 100 --tag "r$r"
  done
  reset_state
  for r in 1 2 3; do
    run_step "5.3 latency at 100 votes/s, run $r" "load_open_r$r.txt" be python -m tools.bench_load open --rate 100 --duration 60 --tag "r$r"
  done
fi

if has sweep; then
  reset_state
  run_step "5.6 offered-load sweep" load_sweep.txt be python -m tools.bench_load sweep --rates 50 100 150 200 250 300 400 --duration 30
fi

if has scaling; then
  for W in 1 2 4 8; do
    reset_state
    WORKERS=$W LIMIT_CONCURRENCY=256 $C up -d backend >/dev/null   # no shedding: this run measures raw scaling
    wait_for "backend with $W worker(s)" 180 curl -sf http://localhost:8000/docs
    sleep 3
    run_step "5.6 collectors = $W worker(s)" "load_closed_w$W.txt" be python -m tools.bench_load closed --votes 5000 --concurrency 100 --tag "w$W"
  done
  WORKERS= $C up -d backend >/dev/null
  wait_for "backend (all workers)" 180 curl -sf http://localhost:8000/docs
fi

if has locust; then
  reset_state
  run_step "5.3 Locust (200 users, ramp 20/s, 120 s)" locust.txt \
    $C exec -T -e LOCUST_PACKAGES=20000 backend locust -f tools/locustfile.py --headless -u 200 -r 20 -t 120s \
    --host http://localhost:8000 --only-summary
fi

if has adversarial; then
  reset_state
  run_step "5.10 replay / forgeries / double vote" adversarial.txt be python -m tools.bench_adversarial
  run_step "5.10 adversarial load (10% and 50% invalid)" load_mix.txt be python -m tools.bench_load mix --rate 100 --duration 30 --invalid 0.1 0.5
fi

if has integrity; then
  reset_state
  run_step "5.5 fill ledger (25,000 votes)" integrity_fill.txt be python -m tools.bench_integrity fill --votes 25000 --rate 150
  run_step "5.5 live tamper detection" integrity_tamper.txt be python -m tools.bench_integrity tamper --sizes 1 10 100 1000 --trials 5
  rm -f "$OUT/integrity_events.txt"
  log "→ 5.5 liveness: pausing the replica for 30 s"
  be python -m tools.bench_integrity monitor --seconds 110 > "$OUT/integrity_monitor.txt" 2>&1 &
  MON=$!
  sleep 25; echo "$(now) pause_replica" >> "$OUT/integrity_events.txt"; docker pause evoting_replica >/dev/null
  sleep 30; echo "$(now) resume_replica" >> "$OUT/integrity_events.txt"; docker unpause evoting_replica >/dev/null
  wait "$MON"
  run_step "5.5 liveness verdicts" integrity_liveness.txt be python -m tools.bench_integrity analyse-liveness
fi

if has fault; then
  reset_state
  rm -f "$OUT"/ft_*
  ev() { echo "$(now) $*" >> "$OUT/ft_events.txt"; log "   >>> $*"; }
  log "→ 5.7 fault tolerance: 100 votes/s for 150 s with faults on schedule"
  be python -m tools.bench_fault_tolerance --run --rate 100 --duration 150 > "$OUT/ft_run.txt" 2>&1 &
  RUN=$!
  sleep 3;  ev run_started
  sleep 30; ev "kill_bookie evoting_bookie2 (SIGKILL; stays down)"; docker kill evoting_bookie2 >/dev/null
  sleep 30; ev "kill_replica (SIGKILL)"; docker kill evoting_replica >/dev/null
  sleep 15; ev restart_replica; docker start evoting_replica >/dev/null
  sleep 20; Q="$(second_victim evoting_bookie2)"
  ev "kill_quorum $Q (SIGKILL; storage now below the ensemble size)"; docker kill "$Q" >/dev/null
  sleep 15; ev "restore_quorum $Q"; docker start "$Q" >/dev/null
  wait "$RUN"
  cat "$OUT/ft_run.txt" | quiet
  ensembles | tee "$OUT/ft_ensembles.txt"
  run_step "5.7 verify every vote (bookie2 still down)" ft_summary.txt be python -m tools.bench_fault_tolerance --verify --rate 100
  docker start evoting_bookie2 >/dev/null && ev "restart_bookie evoting_bookie2"
  wait_for "all 4 bookies" 120 sh -c "$C exec -T pulsar bin/pulsar-admin bookies list-bookies | grep -c bookieId | grep -q 4"
fi

if has stress; then
  # The stress test writes several GB (every record twice, plus journals).
  FREE_GB=$(df -Pk "$PWD" | awk 'NR==2 {printf "%d", $4/1048576}')
  if [ "${FREE_GB:-0}" -lt 10 ]; then
    log "!! only ${FREE_GB} GB free on this disk — the ledger stress test needs about 10 GB; skipping it"
    FAILED="$FAILED stress(disk)"
  else
  run_step "5.12 ledger ceilings by payload size" ledger_stress.txt be python -m tools.bench_ledger_stress --sizes tiny k2 k5 --seconds 20
  echo "epoch,cpu_total_pct" > "$OUT/stress_docker_stats.csv"
  be python -m tools.bench_ledger_stress --sizes k2 --seconds 60 --tag sustained > "$OUT/ledger_stress_sustained.txt" 2>&1 &
  ST=$!
  log "→ 5.12 sustained 60 s stress (sampling container CPU)"
  while kill -0 "$ST" 2>/dev/null; do
    docker stats --no-stream --format '{{.CPUPerc}}' | awk -v t="$(now)" '{gsub("%",""); s+=$1} END {printf "%s,%.1f\n", t, s}' >> "$OUT/stress_docker_stats.csv"
    sleep 4
  done
  wait "$ST"; cat "$OUT/ledger_stress_sustained.txt" | quiet
  fi
fi

has summary && run_step "summary" summary.txt be python -m tools.summarise_results

echo
if [ -z "$FAILED" ]; then
  log "ALL EXPERIMENTS FINISHED. Summary: $OUT/paper_results.md"
else
  log "Finished; failed steps:$FAILED — see the matching files in $OUT/"
fi
