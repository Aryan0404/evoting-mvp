#!/usr/bin/env python3
# backend/app/replica/forensic_replica.py
"""
Algorithm 3 — Continuous Integrity Verification (the air-gapped replica).
────────────────────────────────────────────────────────────────────────

An independent process that trusts nobody and re-derives the truth from the
append-only ledger itself:

  1. Subscribes to the Pulsar ledger and copies every ballot into its own
     write-once SQLite store (a stand-in for WORM storage).
  2. Every 5 seconds, recomputes the SHA-256 Merkle root over the ballots it
     has seen and publishes the per-bundle roots to the bulletin board (Redis).
  3. A bundle, once full (10,000 ballots), is sealed and never recomputed; if a
     later recomputation of a *sealed* bundle ever produces a different root,
     that means the stored data was tampered with — and the replica raises a
     loud alert (and could run Merkle bisection to localise the altered ballot).

In a real deployment this runs behind a one-way data diode on isolated
hardware, so even a fully compromised primary cannot forge its verdict. Here it
runs as its own container, reading the same ledger.

Run (inside its own container):  python -m app.replica.forensic_replica
"""

from __future__ import annotations

import hashlib
import logging
import os
import sqlite3
import time

import redis as redis_sync

from app.services.merkle_service import MerkleTree

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [replica] %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)

PULSAR_URL = os.environ.get("PULSAR_URL", "pulsar://pulsar:6650")
REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
TOPIC = "persistent://public/default/ballots"
BUNDLE_SIZE = int(os.environ.get("BUNDLE_SIZE", "10000"))
CHECK_INTERVAL_SEC = int(os.environ.get("REPLICA_CHECK_INTERVAL", "5"))
DB_PATH = os.environ.get("REPLICA_DB", "/app/replica_data/replica.db")


def _setup_db() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS ballots ("
        " seq INTEGER PRIMARY KEY AUTOINCREMENT,"
        " ballot_hash TEXT UNIQUE NOT NULL,"
        " received_at REAL NOT NULL)"
    )
    conn.commit()
    return conn


def _recompute_and_publish(conn, r, sealed_roots: dict[int, str]) -> None:
    """Recompute per-bundle Merkle roots and publish them; detect tampering."""
    rows = conn.execute("SELECT ballot_hash FROM ballots ORDER BY seq").fetchall()
    hashes = [row[0] for row in rows]
    n = len(hashes)
    if n == 0:
        return

    # overall root over the whole ledger
    overall = MerkleTree([bytes.fromhex(h) for h in hashes]).root_hex()
    r.set("replica:root", overall)
    r.set("replica:count", n)
    r.set("replica:last_check", time.time())

    # per-bundle roots
    num_bundles = (n + BUNDLE_SIZE - 1) // BUNDLE_SIZE
    for b in range(num_bundles):
        chunk = hashes[b * BUNDLE_SIZE : (b + 1) * BUNDLE_SIZE]
        full = len(chunk) == BUNDLE_SIZE
        # a sealed (full) bundle is cached and never recomputed — unless we must
        # check it for tampering
        root = MerkleTree([bytes.fromhex(h) for h in chunk]).root_hex()

        if b in sealed_roots:
            if sealed_roots[b] != root:
                log.error(
                    "*** TAMPER DETECTED in sealed bundle %s: root changed "
                    "%s -> %s ***", b, sealed_roots[b], root,
                )
                r.set(f"bundle:{b}:tampered", "1")
            continue  # already sealed and verified; skip re-publish

        r.set(f"bundle:{b}:root", root)
        if full:
            sealed_roots[b] = root
            log.info("Sealed bundle %s (%d ballots) root=%s",
                     b, BUNDLE_SIZE, root[:16])

    log.info("Integrity check: %d ballots, overall root=%s", n, overall[:16])


def main() -> None:
    import pulsar

    conn = _setup_db()
    r = redis_sync.from_url(REDIS_URL, decode_responses=True)

    client = pulsar.Client(PULSAR_URL, operation_timeout_seconds=30)
    consumer = client.subscribe(
        TOPIC,
        subscription_name="forensic-replica",
        consumer_type=pulsar.ConsumerType.Exclusive,
        initial_position=pulsar.InitialPosition.Earliest,
    )
    log.info("Forensic replica started. Ledger=%s check=%ss bundle=%d",
             TOPIC, CHECK_INTERVAL_SEC, BUNDLE_SIZE)

    sealed_roots: dict[int, str] = {}
    last_check = 0.0

    try:
        while True:
            # drain whatever ballots are available
            try:
                msg = consumer.receive(timeout_millis=500)
                ballot_hash = hashlib.sha256(msg.data()).hexdigest()
                try:
                    conn.execute(
                        "INSERT OR IGNORE INTO ballots (ballot_hash, received_at)"
                        " VALUES (?, ?)",
                        (ballot_hash, time.time()),
                    )
                    conn.commit()
                finally:
                    consumer.acknowledge(msg)
            except Exception:
                # receive timeout (no new ballots) — fall through to the check
                pass

            now = time.time()
            if now - last_check >= CHECK_INTERVAL_SEC:
                try:
                    _recompute_and_publish(conn, r, sealed_roots)
                except Exception as exc:
                    log.error("integrity check failed: %s", exc)
                last_check = now
    except KeyboardInterrupt:
        log.info("Forensic replica shutting down.")
    finally:
        consumer.close()
        client.close()
        conn.close()


if __name__ == "__main__":
    main()
