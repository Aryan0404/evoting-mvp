#!/usr/bin/env python3
# backend/app/replica/forensic_replica.py
"""
The air-gapped forensic replica — Algorithms 3, 4 and 5.
───────────────────────────────────────────────────────────────────────────────

Inputs (one-way only, the data-diode side):
  • the ballot stream — every ballot, in ledger order, copied into a
    write-once store (SQLite here; WORM media in deployment);
  • the primary's diode stream — each cycle's bundle roots, the leaf hashes
    of bundles that changed, and a fresh liveness nonce N.

Every time primary roots arrive (and at least every cycle):
  Algorithm 3  recompute this replica's root for every bundle over exactly the
               ballots the primary covered, and compare.
  Algorithm 4  on a mismatch, descend both Merkle trees to the altered leaves,
               map them to ledger positions, and raise the forensic alert
               (which places the collectors in lockdown).
  Algorithm 5  for each nonce N covering `upto` ballots, compute
               C' = H(S' ∥ N) over this replica's first `upto` ballots and
               publish C' — any observer compares it with the primary's C.

Outputs go only to the public bulletin board (a separate store). Nothing is
ever sent back to the primary system. In deployment the one-way property is
enforced by a hardware data diode; in the prototype it is a read-only
subscription — the replica holds no producer and no write access upstream.

Run:  python -m app.replica.forensic_replica
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import time

import redis as redis_sync

from app.services.merkle_service import MerkleTree, bisect_trees
from app.workers.common import (BALLOT_TOPIC, BUNDLE_SIZE, CYCLE_SECONDS, DIODE_TOPIC,
                                bundle_roots, nonce_commitment, state_commitment)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [replica] %(levelname)s %(message)s")
log = logging.getLogger(__name__)

PULSAR_URL = os.environ.get("PULSAR_URL", "pulsar://pulsar:6650")
BULLETIN_URL = os.environ.get("BULLETIN_URL", "redis://bulletin:6379/0")
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


class Replica:
    def __init__(self, conn, bb):
        self.conn = conn
        self.bb = bb
        self.primary = {}            # bundle -> {"count", "root", "leaves": [bytes] | None}
        self.nonces = []             # pending (round, N, upto)
        self.alert_key = None
        self.cache = []              # local leaves, in ledger order
        self.last_seq = 0            # highest store row already in the cache

    # ── storage ────────────────────────────────────────────────────────────
    def store(self, payloads):
        import hashlib
        now = time.time()
        self.conn.executemany(
            "INSERT OR IGNORE INTO ballots (ballot_hash, received_at) VALUES (?, ?)",
            [(hashlib.sha256(p).hexdigest(), now) for p in payloads])
        self.conn.commit()

    def leaves(self):
        # Follow the store by its own row number, never by a count: row numbers
        # can have gaps (a crash or a redelivered ballot), and using the count as
        # the cursor would re-read rows and shift every later leaf.
        rows = self.conn.execute("SELECT seq, ballot_hash FROM ballots WHERE seq > ? ORDER BY seq",
                                 (self.last_seq,)).fetchall()
        if rows:
            self.cache.extend(bytes.fromhex(h) for _, h in rows)
            self.last_seq = rows[-1][0]
        return self.cache

    # ── diode input ────────────────────────────────────────────────────────
    def on_primary_cycle(self, msg):
        for e in msg["bundles"]:
            prev = self.primary.get(e["b"], {})
            lv = e.get("leaves")
            leaves = ([bytes.fromhex(lv[i:i + 64]) for i in range(0, len(lv), 64)] if lv is not None
                      else (prev.get("leaves") if prev.get("count") == e["count"] and prev.get("root") == e["root"] else None))
            self.primary[e["b"]] = {"count": e["count"], "root": e["root"], "leaves": leaves}
        for b in [b for b in self.primary if b >= len(msg["bundles"])]:
            del self.primary[b]
        self.nonces.append((msg["round"], msg["N"], msg["upto"]))

    # ── Algorithm 5 ────────────────────────────────────────────────────────
    def answer_nonces(self, leaves):
        keep = []
        for rnd, N, upto in self.nonces:
            if upto > len(leaves):
                keep.append((rnd, N, upto))          # not yet received that many ballots
                continue
            Cp = nonce_commitment(state_commitment(leaves[:upto]), N)
            self.bb.hset(f"liveness:round:{rnd}", mapping={"Cp": Cp, "t_replica": time.time()})
        self.nonces = keep

    # ── Algorithms 3 and 4 ─────────────────────────────────────────────────
    def compare(self, leaves):
        diverged, pending = [], 0
        for b, p in sorted(self.primary.items()):
            mine = leaves[b * BUNDLE_SIZE: b * BUNDLE_SIZE + p["count"]]
            if len(mine) < p["count"]:
                pending += 1
                continue
            tree_r = MerkleTree(mine)
            if tree_r.root_hex() == p["root"]:
                continue
            located = None
            if p["leaves"] is not None and len(p["leaves"]) == p["count"]:
                positions, comps = bisect_trees(MerkleTree(p["leaves"]), tree_r)
                located = {"positions": positions, "ledger_seq": [b * BUNDLE_SIZE + i + 1 for i in positions],
                           "comparisons": comps}
            diverged.append({"bundle": b, "primary_root": p["root"], "replica_root": tree_r.root_hex(),
                             "count": p["count"], "located": located})
        return diverged, pending

    def publish(self, leaves, diverged, pending):
        now = time.time()
        pipe = self.bb.pipeline(transaction=False)
        pipe.set("replica:count", len(leaves))
        pipe.set("replica:state", state_commitment(leaves))
        pipe.set("replica:last_check", now)
        pipe.set("replica:status", "FAIL" if diverged else ("PENDING" if pending else "PASS"))
        for e in bundle_roots(leaves):
            pipe.set(f"replica:bundle:{e['b']}:root", f"{e['count']}:{e['root']}")
            if e["count"] == BUNDLE_SIZE:
                pipe.set(f"bundle:{e['b']}:root", e["root"])     # sealed bundle, for voter receipts
        pipe.execute()
        if diverged:
            key = json.dumps([(d["bundle"], d["primary_root"]) for d in diverged])
            if key != self.alert_key or not self.bb.exists("alert:active"):
                alert = {"detected_at": now, "bundles": diverged}
                self.bb.set("alert:active", json.dumps(alert))
                self.bb.rpush("alerts:log", json.dumps(alert))
                self.alert_key = key
                log.error("*** TAMPER DETECTED in bundle(s) %s; located ledger positions %s ***",
                          [d["bundle"] for d in diverged],
                          [d["located"]["ledger_seq"][:20] if d["located"] else "pending" for d in diverged])
        else:
            self.alert_key = None


def main() -> None:
    import pulsar

    conn = _setup_db()
    bb = redis_sync.from_url(BULLETIN_URL, decode_responses=True)
    client = pulsar.Client(PULSAR_URL, operation_timeout_seconds=30)
    ballots = client.subscribe(BALLOT_TOPIC, subscription_name="forensic-replica",
                               consumer_type=pulsar.ConsumerType.Exclusive,
                               initial_position=pulsar.InitialPosition.Earliest)
    diode = client.subscribe(DIODE_TOPIC, subscription_name="forensic-replica-diode",
                             consumer_type=pulsar.ConsumerType.Exclusive,
                             initial_position=pulsar.InitialPosition.Earliest)
    rep = Replica(conn, bb)
    log.info("Forensic replica started. ballots=%s diode=%s cycle=%.1fs bundle=%d",
             BALLOT_TOPIC, DIODE_TOPIC, CYCLE_SECONDS, BUNDLE_SIZE)
    last_check = 0.0
    try:
        while True:
            batch = []
            t_end = time.monotonic() + 0.2
            while len(batch) < 2000 and time.monotonic() < t_end:
                try:
                    m = ballots.receive(timeout_millis=50)
                except Exception:
                    break
                batch.append(m)
            if batch:
                rep.store([m.data() for m in batch])
                for m in batch:
                    ballots.acknowledge(m)

            got_cycle = False
            while True:
                try:
                    m = diode.receive(timeout_millis=1)
                except Exception:
                    break
                try:
                    rep.on_primary_cycle(json.loads(m.data()))
                    got_cycle = True
                finally:
                    diode.acknowledge(m)

            now = time.time()
            if got_cycle or rep.nonces or now - last_check >= CYCLE_SECONDS:
                leaves = rep.leaves()
                rep.answer_nonces(leaves)
                if got_cycle or now - last_check >= CYCLE_SECONDS:
                    diverged, pending = rep.compare(leaves)
                    rep.publish(leaves, diverged, pending)
                    last_check = now
    except KeyboardInterrupt:
        log.info("Forensic replica shutting down.")
    finally:
        ballots.close()
        diode.close()
        client.close()
        conn.close()


if __name__ == "__main__":
    main()
