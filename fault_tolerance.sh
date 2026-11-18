#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  Section 5.5 — Fault tolerance, locally with Docker.
#
#  Runs the ledger as a real 4-bookie BookKeeper cluster
#  (Ensemble 3 / Write quorum 2 / Ack quorum 2), keeps an election running at a
#  steady rate, and on schedule:
#     t = 30 s   SIGKILL one storage node (bookie)       — it stays down
#     t = 60 s   SIGKILL the air-gapped forensic replica
#     t = 75 s   restart the replica (must catch up on its own)
#  Then, with the storage node STILL DOWN, reads every ballot back from the
#  ledger and checks it against the server count and the replica.
#
#    ./fault_tolerance.sh
#    RATE=150 DURATION=180 ./fault_tolerance.sh
#
#  Results: backend/paper/results/docker/ft_*
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
cd "$(dirname "$0")"

C="docker compose -f docker-compose.yml -f docker-compose.cluster.yml"
RATE="${RATE:-100}"
DURATION="${DURATION:-120}"
KILL_BOOKIE_AT="${KILL_BOOKIE_AT:-30}"
KILL_REPLICA_AT="${KILL_REPLICA_AT:-60}"
RESTART_REPLICA_AT="${RESTART_REPLICA_AT:-75}"
VICTIM="${VICTIM:-evoting_bookie2}"
OUT="backend/paper/results/docker"
mkdir -p "$OUT"
rm -f "$OUT"/ft_*

now() { python3 -c 'import time; print(f"{time.time():.3f}")'; }
event() { echo "$(now) $*" >> "$OUT/ft_events.txt"; echo "   >>> $*"; }

wait_for() {  # wait_for <description> <timeout_s> <command...>
  local what="$1" limit="$2"; shift 2
  echo -n "   waiting for $what"
  for _ in $(seq 1 "$limit"); do
    if "$@" >/dev/null 2>&1; then echo " — ready"; return 0; fi
    echo -n "."; sleep 1
  done
  echo " — TIMED OUT"; return 1
}

echo "== [1/6] Starting a fresh 4-bookie Pulsar cluster =="
$C rm -sf zookeeper pulsar-init bookie1 bookie2 bookie3 bookie4 pulsar >/dev/null 2>&1 || true
$C up -d --remove-orphans
wait_for "the broker and all storage nodes" 300 \
  $C exec -T pulsar curl -sf http://localhost:8080/admin/v2/brokers/health
$C exec -T pulsar bin/pulsar-admin namespaces set-persistence public/default \
  --bookkeeper-ensemble 3 --bookkeeper-write-quorum 2 --bookkeeper-ack-quorum 2 \
  --ml-mark-delete-max-rate 0
$C restart backend replica >/dev/null
wait_for "the backend" 120 curl -sf http://localhost:8000/docs

echo "== [2/6] Cluster configuration =="
{
  echo "Read-write bookies:"; $C exec -T pulsar bin/pulsar-admin bookies list-bookies
  echo; echo "Persistence policy for public/default:"
  $C exec -T pulsar bin/pulsar-admin namespaces get-persistence public/default
} | tee "$OUT/ft_cluster_before.txt"

echo "== [3/6] Election running: ${RATE} votes/s for ${DURATION}s (faults on schedule) =="
$C exec -T backend python -m tools.bench_fault_tolerance --run \
  --rate "$RATE" --duration "$DURATION" > "$OUT/ft_run.txt" 2>&1 &
RUN_PID=$!
sleep 3   # ticket seeding
event "run_started"
sleep "$KILL_BOOKIE_AT";                               event "kill_bookie $VICTIM (SIGKILL)"; docker kill "$VICTIM" >/dev/null
sleep $(( KILL_REPLICA_AT - KILL_BOOKIE_AT ));         event "kill_replica (SIGKILL)";        docker kill evoting_replica >/dev/null
sleep $(( RESTART_REPLICA_AT - KILL_REPLICA_AT ));     event "restart_replica";               docker start evoting_replica >/dev/null
echo "   (voting continues until the end of the run)"
wait "$RUN_PID" || true
cat "$OUT/ft_run.txt"

echo "== [4/6] Cluster state with one storage node down =="
{
  echo "Read-write bookies:"; $C exec -T pulsar bin/pulsar-admin bookies list-bookies
  echo; echo "Ballot topic, internal ledger layout:"
  $C exec -T pulsar bin/pulsar-admin topics stats-internal persistent://public/default/ballots
} > "$OUT/ft_cluster_after.txt" 2>&1 || true
# Which storage nodes held the ballots, and where BookKeeper swapped in the spare
for id in $($C exec -T pulsar bin/pulsar-admin topics stats-internal persistent://public/default/ballots \
            | grep -o '"ledgerId" : [0-9]*' | grep -o '[0-9]*$'); do
  echo "ledger $id: $(docker exec evoting_bookie1 bin/bookkeeper shell ledgermetadata -ledgerid "$id" 2>/dev/null \
                      | grep -o 'ensembles={[^}]*}')"
done | tee "$OUT/ft_ensembles.txt"

echo "== [5/6] Verifying every vote (storage node still down) =="
set +e
$C exec -T backend python -m tools.bench_fault_tolerance --verify | tee "$OUT/ft_summary.txt"
VERIFY_RC=${PIPESTATUS[0]}
set -e

echo "== [6/6] Bringing the storage node back =="
docker start "$VICTIM" >/dev/null && event "restart_bookie $VICTIM"

echo
echo "Done. Results in $OUT/ (ft_summary.txt, ft_summary.json, ft_timeline.csv, ...)"
echo "To return to the normal single-node setup later:  docker compose up -d --remove-orphans"
exit "$VERIFY_RC"
