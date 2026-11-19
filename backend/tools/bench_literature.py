#!/usr/bin/env python3
# backend/tools/bench_literature.py
"""
Literature-matched benchmarks: the proposed system run under the SAME test
scenarios that the compared papers used, plus the two voting modes of
Razaque et al. (burst and even distribution) with write and read speed.
───────────────────────────────────────────────────────────────────────────────

Every vote is a complete Algorithm 1 package (one-hot Paillier ballot,
ballot-validity proof bound to its ticket, fresh timestamp, ECDSA P-256 device
signature). Where a scenario has voters retry (a voter app does), a 503 or a
time-out is retried with backoff and counted.

Sub-commands (run inside the backend container):

  wr        Two voting modes x N votes (Razaque Sec. 4.2 burst / even modes;
            N = 1,000..5,000 as in Razaque Fig. 10 and Patel Table 2).
            WRITE: votes accepted/s, completion time, latency, retries.
            READ:  ledger read-back (Pulsar), primary-ledger scan (PostgreSQL),
                   voter receipt proofs (HTTP), counting (tally + 3-of-5
                   threshold decryption), each checked for correctness.
  window    Razaque Figs. 5, 8, 9: a 15-minute voting window in either mode,
            cumulative votes cast, durably confirmed and replica-verified,
            sampled every second, followed by a 5-minute tail (0..20 min).
  rates     Saeed et al. 2022 (Hyperledger Fabric, Caliper): send rates
            50..250 votes/s, 1,000 votes per round, 5 rounds per rate; no
            retries; success, fail, avg/min/max latency, throughput.
  clients   Khan et al. 2020 (MultiChain): sequential clients, case 1 = one
            client, case 3 = seven concurrent clients; votes/s and s per vote.
  concurrent  ScalEVote (Berenjestanaki et al.): 10,000 votes submitted at once;
            mean +/- SD end-to-end latency with voter-app retries.
  ledger    Razaque Fig. 7 (accuracy vs send rate 1,000..8,000 tps): real
            ballot records offered to the replicated ledger at each rate, then
            read back and compared byte for byte.
  crypto    ElectionGuard verifier study (25..1,341 ballots, 6 contests,
            3-of-5 trustees), MERGE per-operation costs (7 contests x 4
            selections), STARK vector-commitment tally (64 and 1,024 voters).

Results are written to $RESULTS_DIR as lit_*.json and printed as tables.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import math
import os
import random
import resource
import statistics
import sys
import time
from collections import Counter
from concurrent.futures import ProcessPoolExecutor

import aiohttp
import redis.asyncio as aioredis

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tools import ballot_factory as bf    # noqa: E402

BASE = os.environ.get("LOADTEST_URL", "http://localhost:8000")
REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
BULLETIN_URL = os.environ.get("BULLETIN_URL", "redis://bulletin:6379/0")
PULSAR_URL = os.environ.get("PULSAR_URL", "pulsar://pulsar:6650")
OUT_DIR = os.environ.get("RESULTS_DIR", "/app/paper/results/docker")
SHARES_PATH = os.environ.get("TRUSTEE_SHARES", "/tmp/trustee_shares.json")
RETRY_CODES = {0, 429, 502, 503, 504}
PROOF_SAMPLE = int(os.environ.get("PROOF_SAMPLE", "300"))


# ── small helpers ───────────────────────────────────────────────────────────
def pct(xs, p):
    if not xs:
        return None
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(len(xs) * p))]


def ms(x):
    return None if x is None else round(x * 1000, 1)


def lat_stats(xs):
    if not xs:
        return {"n": 0}
    return {"n": len(xs), "mean_ms": ms(statistics.fmean(xs)), "sd_ms": ms(statistics.pstdev(xs)),
            "min_ms": ms(min(xs)), "p50_ms": ms(pct(xs, .5)), "p95_ms": ms(pct(xs, .95)),
            "p99_ms": ms(pct(xs, .99)), "max_ms": ms(max(xs))}


def save(name, data):
    os.makedirs(OUT_DIR, exist_ok=True)
    path = os.path.join(OUT_DIR, name)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    return path


def http(conns, timeout=30.0):
    return aiohttp.ClientSession(base_url=BASE,
                                 connector=aiohttp.TCPConnector(limit=conns, limit_per_host=conns),
                                 timeout=aiohttp.ClientTimeout(total=timeout))


def http_queued(conns):
    """Client for long open-loop runs: at most `conns` requests on the wire (the
    collectors admit WORKERS x LIMIT_CONCURRENCY = 8 x 64 = 512 at once), the
    rest wait their turn in arrival order. The time-out covers only connecting
    and the server's reply, never the wait for a free connection. With a total
    time-out instead, a backlog makes queued requests expire before they are
    ever sent; each expiry is re-sent and closes a connection, and in the
    15-minute run (first version) that retry storm stopped the load generator
    delivering any request at all after about 7 minutes while the collectors sat
    idle — a failure of the test client, not of the system under test."""
    return aiohttp.ClientSession(base_url=BASE,
                                 connector=aiohttp.TCPConnector(limit=conns, limit_per_host=conns,
                                                                keepalive_timeout=4.0),
                                 timeout=aiohttp.ClientTimeout(total=None, sock_connect=10, sock_read=60))


# ── packages, generated ahead in worker processes ───────────────────────────
def _chunk(args):
    """Build `count` valid packages in a worker process. Device keys travel as
    their private scalar (cryptography key objects do not pickle)."""
    n_hex, count, k, seed = args
    random.seed(seed)
    pk = bf.make_packages(n_hex, count, k=k, templates=16, procs=1)
    return [(p.uti, p.key.private_numbers().private_value, p.pk_hex, p.k, p.ciphertext, p.proof, p.choice)
            for p in pk]


def _unpack(rows):
    from cryptography.hazmat.primitives.asymmetric import ec
    return [bf.Package(u, ec.derive_private_key(v, ec.SECP256R1()), pkh, k, ct, pr, ch)
            for u, v, pkh, k, ct, pr, ch in rows]


async def n_hex_from_board():
    bb = aioredis.from_url(BULLETIN_URL, decode_responses=True)
    try:
        return await bf.election_n_hex(bb)
    finally:
        await bb.aclose()


async def make_and_seed(count, k, procs=None, chunk=2000):
    """All packages up front (for runs up to a few tens of thousands)."""
    n_hex = await n_hex_from_board()
    procs = procs or os.cpu_count() or 1
    sizes = [min(chunk, count - i) for i in range(0, count, chunk)]
    loop = asyncio.get_running_loop()
    with ProcessPoolExecutor(max_workers=procs) as ex:
        parts = await asyncio.gather(*[loop.run_in_executor(ex, _chunk, (n_hex, s, k, i)) for i, s in enumerate(sizes)])
    pkgs = [p for part in parts for p in _unpack(part)]
    r = aioredis.from_url(REDIS_URL, decode_responses=True)
    await bf.seed_tickets(r, pkgs, ttl=14400)
    await r.aclose()
    return pkgs


class PackageStream:
    """Packages for long runs (90,000+ votes): built in background processes a
    few chunks ahead and seeded just before use, so memory stays bounded."""

    def __init__(self, k, chunk=3000, ahead=3):
        self.k, self.chunk, self.ahead = k, chunk, ahead
        self.queue = asyncio.Queue(maxsize=ahead)
        self.ex = ProcessPoolExecutor(max_workers=2)
        self.task = None

    async def start(self, total):
        self.n_hex = await n_hex_from_board()
        self.redis = aioredis.from_url(REDIS_URL, decode_responses=True)
        self.task = asyncio.create_task(self._fill(total))

    async def _fill(self, total):
        loop = asyncio.get_running_loop()
        made, seed = 0, 0
        while made < total:
            n = min(self.chunk, total - made)
            rows = await loop.run_in_executor(self.ex, _chunk, (self.n_hex, n, self.k, seed))
            pk = _unpack(rows)
            await bf.seed_tickets(self.redis, pk, ttl=14400)
            await self.queue.put(pk)
            made += n
            seed += 1

    async def take(self):
        return await self.queue.get()

    async def close(self):
        if self.task:
            self.task.cancel()
        self.ex.shutdown(cancel_futures=True)
        await self.redis.aclose()


# ── one vote, with or without voter-app retries ─────────────────────────────
class Vote:
    __slots__ = ("t_first", "t_done", "attempts", "first_code", "code", "receipt", "seq", "choice", "timed_out")

    def __init__(self, choice):
        self.t_first = self.t_done = None
        self.attempts, self.first_code, self.code = 0, None, None
        self.receipt = self.seq = None
        self.choice = choice
        self.timed_out = False

    @property
    def accepted(self):
        return self.code in (201, "409-confirmed")

    @property
    def latency(self):
        return None if self.t_done is None else self.t_done - self.t_first


ATTEMPT_CODES = Counter()     # every HTTP status seen, per attempt (0 = no reply / client time-out)
ERROR_BODIES = {}             # first response body seen for each non-201 status, for diagnosis


async def cast(c, pkg, v: Vote, retry=True, max_attempts=12, deadline_s=None):
    """POST one ballot, retrying like the voter app: on no reply or 429/502/503/504,
    back off and resend with a fresh timestamp. Stops after `max_attempts`, or,
    when `deadline_s` is given, once that many seconds have passed since the
    first attempt (the app keeps trying until the vote is in or time is up)."""
    v.t_first = time.perf_counter()
    while True:
        v.attempts += 1
        try:
            async with c.post("/api/v1/vote/cast", json=pkg.body()) as resp:
                code = resp.status
                if code == 201:
                    data = await resp.json(content_type=None)
                else:
                    data = None
                    if code not in ERROR_BODIES:
                        ERROR_BODIES[code] = (await resp.text())[:300]
        except Exception as exc:
            code, data = 0, None
            ERROR_BODIES.setdefault(0, f"{type(exc).__name__}: {exc}"[:300])
        ATTEMPT_CODES[code] += 1
        if v.first_code is None:
            v.first_code = code
        if code == 0:
            v.timed_out = True
        if code == 201:
            v.code, v.t_done = 201, time.perf_counter()
            v.receipt, v.seq = data.get("ballot_hash"), data.get("sequence_no")
            return v
        if code == 409 and v.timed_out:
            # an earlier attempt was accepted but its reply was lost (time-out)
            v.code, v.t_done = "409-confirmed", time.perf_counter()
            return v
        out_of_time = (time.perf_counter() - v.t_first > deadline_s) if deadline_s else v.attempts >= max_attempts
        if not retry or code not in RETRY_CODES or out_of_time:
            v.code, v.t_done = code, time.perf_counter()
            return v
        await asyncio.sleep(min(4.0, 0.25 * 2 ** (v.attempts - 1)) * (0.5 + random.random()))


async def ledger_seq():
    r = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        return int(await r.get("ledger:seq") or 0)
    finally:
        await r.aclose()


async def board_counts():
    bb = aioredis.from_url(BULLETIN_URL, decode_responses=True)
    try:
        p, rc = await bb.get("primary:count"), await bb.get("replica:count")
        return int(p or 0), int(rc or 0)
    finally:
        await bb.aclose()


# ═════════════════════════════════════════════════════════════════════════════
#  READ SIDE
# ═════════════════════════════════════════════════════════════════════════════
def read_pulsar_since(t_start_epoch, expect, timeout_s=120):
    """Read this run's ballots back from the replicated ledger.
    Seeks by publish time so earlier runs on the same topic are skipped."""
    import pulsar
    from app.workers.common import BALLOT_TOPIC
    client = pulsar.Client(PULSAR_URL, operation_timeout_seconds=30)
    reader = client.create_reader(BALLOT_TOPIC, pulsar.MessageId.earliest, receiver_queue_size=1000)
    try:
        reader.seek(int((t_start_epoch - 2) * 1000))
        seek = "publish-time"
    except Exception:
        seek = "scan"
    hashes, scanned = [], 0
    t0 = time.perf_counter()
    deadline = t0 + timeout_s
    while len(hashes) < expect and time.perf_counter() < deadline:
        try:
            msg = reader.read_next(timeout_millis=5000)
        except Exception:
            if not reader.has_message_available():
                break
            continue
        scanned += 1
        if msg.publish_timestamp() < (t_start_epoch - 1) * 1000:
            continue
        hashes.append(hashlib.sha256(msg.data()).hexdigest())
    dt = time.perf_counter() - t0
    reader.close()
    client.close()
    return {"records": len(hashes), "scanned": scanned, "seconds": round(dt, 3),
            "records_per_s": round(len(hashes) / dt, 1) if dt else None, "seek": seek}, hashes


async def read_primary(expect, wait_s=120):
    """Scan the primary vote ledger (PostgreSQL) once it holds this run."""
    from app.workers.common import connect_db
    t_wait = time.perf_counter()
    while time.perf_counter() - t_wait < wait_s:
        conn = await connect_db()
        try:
            n = await conn.fetchval("SELECT count(*) FROM vote_ledger")
        except Exception:
            n = 0
        await conn.close()
        if n >= expect:
            break
        await asyncio.sleep(1)
    conn = await connect_db()
    t0 = time.perf_counter()
    rows = await conn.fetch("SELECT seq, ballot_hash, payload FROM vote_ledger ORDER BY seq")
    dt = time.perf_counter() - t0
    await conn.close()
    nbytes = sum(len(r["payload"]) for r in rows)
    return {"records": len(rows), "seconds": round(dt, 3), "records_per_s": round(len(rows) / dt, 1) if dt else None,
            "MB_per_s": round(nbytes / 1e6 / dt, 1) if dt else None,
            "waited_s": round(t0 - t_wait, 1)}, rows


async def read_receipts(receipts, path="/api/v1/audit/proof/{}", concurrency=50):
    """Voters check their receipts over HTTP (inclusion lookup or full Merkle audit path)."""
    lat, codes, included = [], [], 0
    sem = asyncio.Semaphore(concurrency)
    async with http(concurrency + 10) as c:
        async def one(h):
            nonlocal included
            async with sem:
                t = time.perf_counter()
                try:
                    async with c.get(path.format(h)) as resp:
                        code = resp.status
                        d = await resp.json(content_type=None) if code == 200 else {}
                except Exception:
                    code, d = 0, {}
                lat.append(time.perf_counter() - t)
                codes.append(code)
                included += bool(d.get("included"))
        t0 = time.perf_counter()
        await asyncio.gather(*[one(h) for h in receipts])
        dt = time.perf_counter() - t0
    return {"reads": len(receipts), "ok": codes.count(200), "included": included, "seconds": round(dt, 3),
            "reads_per_s": round(len(receipts) / dt, 1) if dt else None, **lat_stats(lat)}


def load_threshold_key():
    from gmpy2 import mpz
    from app.services import threshold_paillier as tp
    with open(SHARES_PATH) as f:
        d = json.load(f)
    n = mpz(int(d["n"], 16))
    return tp.ThresholdKey(n=n, n2=n * n, K=int(d["K"]), t=int(d["t"]), delta=mpz(math.factorial(int(d["K"]))),
                           shares={int(i): mpz(int(s, 16)) for i, s in d["shares"].items()})


def count_votes(payloads, k):
    """Counting: homomorphic tally of every stored ballot (one core), then
    decryption of the k totals by 3 of the 5 trustees."""
    from gmpy2 import mpz
    from app.services import ballot_proof as bp
    from app.services import threshold_paillier as tp
    key = load_threshold_key()
    t0 = time.perf_counter()
    T = [mpz(1)] * k
    for raw in payloads:
        rec = json.loads(raw)
        cts, _ = bp.decode(rec["ciphertext"], rec["zkp_proof"])
        for i in range(k):
            T[i] = T[i] * cts[i] % key.n2
    t_tally = time.perf_counter() - t0
    trustees = list(range(1, key.t + 1))
    t1 = time.perf_counter()
    totals = tp.decrypt_totals(key, T, trustees)
    t_dec = time.perf_counter() - t1
    return {"ballots": len(payloads), "tally_s": round(t_tally, 3), "decrypt_s": round(t_dec, 3),
            "count_s": round(t_tally + t_dec, 3)}, totals


# ═════════════════════════════════════════════════════════════════════════════
#  wr — two voting modes, write speed and read speed
# ═════════════════════════════════════════════════════════════════════════════
async def run_wr(mode, votes, k, even_s, burst_s):
    pkgs = await make_and_seed(votes, k)
    seq0 = await ledger_seq()
    window = even_s if mode == "even" else burst_s
    gap = window / votes
    vs = [Vote(p.choice) for p in pkgs]
    t_wall0 = time.time()
    async with http(max(200, min(votes, 2000))) as c:
        t0 = time.perf_counter()
        tasks = []
        for i, (p, v) in enumerate(zip(pkgs, vs)):
            d = t0 + i * gap - time.perf_counter()
            if d > 0:
                await asyncio.sleep(d)
            tasks.append(asyncio.create_task(cast(c, p, v)))
        await asyncio.gather(*tasks)
        t_end = max((v.t_done for v in vs if v.t_done), default=time.perf_counter())
    acc = [v for v in vs if v.accepted]
    lat = [v.latency for v in acc]
    write_s = t_end - t0
    durable = await ledger_seq() - seq0
    write = {"offered_rate": round(votes / window, 1), "window_s": window, "votes": votes,
             "accepted": len(acc), "first_attempt_accepted": sum(1 for v in vs if v.first_code == 201),
             "retries": sum(v.attempts - 1 for v in vs), "failed": votes - len(acc),
             "durable_in_ledger": durable, "completion_s": round(write_s, 2),
             "write_votes_per_s": round(len(acc) / write_s, 1) if write_s else None,
             "latency_incl_retries": lat_stats(lat)}

    # READ 1: replicated ledger read-back
    loop = asyncio.get_running_loop()
    pulsar_r, pulsar_hashes = await loop.run_in_executor(None, read_pulsar_since, t_wall0, len(acc))
    receipts = [v.receipt for v in acc if v.receipt]
    pulsar_r["match_receipts"] = len(set(receipts) & set(pulsar_hashes))
    # READ 2: primary ledger scan
    pg_r, rows = await read_primary(len(acc))
    pg_r["match_receipts"] = len(set(receipts) & {r["ballot_hash"] for r in rows})
    # READ 3: voters check their receipts: the inclusion lookup for every vote,
    # and the full Merkle audit path (rebuilt from the stored payloads for each
    # request, so it costs a pass over the bundle) for a random sample
    rc_r = await read_receipts(receipts, "/api/v1/audit/receipt/{}", 50)
    sample = random.sample(receipts, min(len(receipts), PROOF_SAMPLE))
    pf_r = await read_receipts(sample, "/api/v1/audit/proof/{}", 16)
    # READ 4: counting
    cnt, totals = await loop.run_in_executor(None, count_votes, [r["payload"] for r in rows], k)
    truth = [sum(1 for v in acc if v.choice == j) for j in range(k)]
    cnt.update({"totals": totals, "ground_truth": truth, "correct": totals == truth,
                "ballots_per_s": round(len(rows) / cnt["count_s"], 1) if cnt["count_s"] else None})
    return {"mode": mode, "candidates": k, "write": write,
            "read": {"ledger_readback": pulsar_r, "primary_scan": pg_r, "receipt_lookup": rc_r,
                     "merkle_audit_path": pf_r, "counting": cnt}}


def print_wr(r):
    w, rd = r["write"], r["read"]
    L = w["latency_incl_retries"]
    print(f"\n  {r['mode'].upper():<6} {w['votes']:>6,} votes in a {w['window_s']:g} s window (offered {w['offered_rate']}/s)")
    print(f"    WRITE  accepted {w['accepted']:,}/{w['votes']:,} ({w['first_attempt_accepted']:,} first try, {w['retries']:,} retries), "
          f"{w['write_votes_per_s']} votes/s, done in {w['completion_s']} s; latency p50 {L.get('p50_ms')} / p99 {L.get('p99_ms')} ms")
    lr, pg, rc, pf, cn = rd["ledger_readback"], rd["primary_scan"], rd["receipt_lookup"], rd["merkle_audit_path"], rd["counting"]
    print(f"    READ   ledger read-back {lr['records']:,} at {lr['records_per_s']}/s (matches {lr['match_receipts']:,}); "
          f"primary scan {pg['records']:,} at {pg['records_per_s']}/s; "
          f"receipt lookups {rc['reads_per_s']}/s ({rc['included']:,} included); "
          f"audit paths {pf['reads_per_s']}/s (p99 {pf.get('p99_ms')} ms, n={pf['reads']}); "
          f"count {cn['count_s']} s, correct {cn['correct']}")


# ═════════════════════════════════════════════════════════════════════════════
#  window — Razaque Figs. 5, 8, 9: 15-minute voting window, then a tail
# ═════════════════════════════════════════════════════════════════════════════
async def run_window(mode, rate, minutes, tail_min, k, every_s, burst_s):
    total = int(rate * minutes * 60)
    stream = PackageStream(k)
    await stream.start(total)
    seq0 = await ledger_seq()
    samples, vs = [], []
    stop = asyncio.Event()

    diag = []                 # every 10 s: status codes so far, lockdown flag, replica status
    ATTEMPT_CODES.clear(); ERROR_BODIES.clear()

    async def sampler(t0):
        bb = aioredis.from_url(BULLETIN_URL, decode_responses=True)
        i = 0
        while not stop.is_set():
            seq = await ledger_seq()
            p, rc = await board_counts()
            acc = sum(1 for v in vs if v.accepted)
            t = round(time.perf_counter() - t0, 1)
            samples.append((t, len(vs), acc, seq - seq0, p, rc))
            if i % 10 == 0:
                try:
                    alert, rstat = bool(await bb.exists("alert:active")), await bb.get("replica:status")
                except Exception:
                    alert, rstat = None, None
                diag.append({"t": t, "durable": seq - seq0, "codes": dict(ATTEMPT_CODES), "lockdown": alert,
                             "replica_status": rstat, "in_flight": sum(1 for v in vs if v.t_done is None)})
            i += 1
            await asyncio.sleep(1.0)
        await bb.aclose()

    async with http_queued(512) as c:
        buf = await stream.take()
        t0 = time.perf_counter()
        st = asyncio.create_task(sampler(t0))
        tasks = []
        for i in range(total):
            if not buf:
                buf = await stream.take()
            p = buf.pop()
            if mode == "even":
                at = i / rate
            else:
                per = int(rate * every_s)
                at = (i // per) * every_s + (i % per) * (burst_s / per)
            d = t0 + at - time.perf_counter()
            if d > 0:
                await asyncio.sleep(d)
            v = Vote(p.choice)
            vs.append(v)
            tasks.append(asyncio.create_task(cast(c, p, v, deadline_s=600)))
        await asyncio.gather(*tasks)
        t_votes = time.perf_counter() - t0
        while time.perf_counter() - t0 < (minutes + tail_min) * 60:
            await asyncio.sleep(1)
        stop.set()
        await st
    await stream.close()

    def at(sec):
        row = min(samples, key=lambda s: abs(s[0] - sec)) if samples else None
        return row
    marks = []
    for m in range(0, int(minutes + tail_min) + 1, 5):
        row = at(m * 60) if m else (0, 0, 0, 0, 0, 0)
        cast_n = max(row[1], 1)
        marks.append({"minute": m, "submitted": row[1], "accepted": row[2], "durable": row[3],
                      "primary_committed": row[4], "replica_verified": row[5],
                      "durable_pct": round(100 * row[3] / cast_n, 2) if row[1] else None,
                      "verified_pct": round(100 * row[5] / cast_n, 2) if row[1] else None})
    acc = [v for v in vs if v.accepted]
    per_min = []
    for m in range(int(minutes)):
        xs = [v.latency for v in acc if m * 60 <= v.t_first - (vs[0].t_first if vs else 0) < (m + 1) * 60]
        per_min.append({"minute": m + 1, **lat_stats(xs)})
    # how long after the last vote until the replica had verified everything
    t_all = next((s[0] for s in samples if s[5] >= len(acc) and s[0] >= t_votes), None)
    return {"mode": mode, "rate": rate, "minutes": minutes, "tail_minutes": tail_min, "candidates": k,
            "votes": total, "accepted": len(acc), "failed": total - len(acc),
            "retries": sum(v.attempts - 1 for v in vs), "voting_s": round(t_votes, 1),
            "latency_incl_retries": lat_stats([v.latency for v in acc]),
            "replica_verified_all_at_s": t_all,
            "replica_lag_after_last_vote_s": round(t_all - t_votes, 1) if t_all else None,
            "marks": marks, "per_minute": per_min, "samples": samples,
            "final_codes": {str(k): n for k, n in Counter(v.code for v in vs).items()},
            "attempt_codes": {str(k): n for k, n in ATTEMPT_CODES.items()},
            "error_bodies": {str(k): b for k, b in ERROR_BODIES.items()},
            "ledger_last_growth_s": next((samples[i][0] for i in range(len(samples) - 1, 0, -1)
                                          if samples[i][3] > samples[i - 1][3]), None),
            "diagnostics": diag}


def print_window(r):
    print(f"\n  {r['mode'].upper()} {r['rate']}/s for {r['minutes']} min: {r['accepted']:,}/{r['votes']:,} accepted, "
          f"{r['retries']:,} retries; latency p50 {r['latency_incl_retries'].get('p50_ms')} / p99 {r['latency_incl_retries'].get('p99_ms')} ms")
    print(f"  {'min':>4} {'cast':>9} {'durable':>9} {'%':>7} {'verified':>9} {'%':>7}")
    for m in r["marks"]:
        print(f"  {m['minute']:>4} {m['accepted']:>9,} {m['durable']:>9,} {str(m['durable_pct']):>7} {m['replica_verified']:>9,} {str(m['verified_pct']):>7}")
    print(f"  replica had verified every vote {r['replica_lag_after_last_vote_s']} s after the last vote")
    if "final_codes" in r:
        print(f"  final status per vote: {r['final_codes']}")
        print(f"  status per attempt:    {r['attempt_codes']}")
        print(f"  ledger last grew at {r['ledger_last_growth_s']} s")
        for k, b in r["error_bodies"].items():
            print(f"  first {k} reply: {b}")
        for d in r["diagnostics"][::6]:
            print(f"   t={d['t']:>6} s durable {d['durable']:>7,} in flight {d['in_flight']:>6,} lockdown {d['lockdown']} "
                  f"replica {d['replica_status']} codes {d['codes']}")


# ═════════════════════════════════════════════════════════════════════════════
#  rates — Saeed et al. 2022 (Caliper): fixed send rates, 1,000 votes a round
# ═════════════════════════════════════════════════════════════════════════════
async def run_rates(rates, votes, rounds, k):
    pkgs = await make_and_seed(votes * rounds * len(rates), k)
    it = iter(pkgs)
    rows = []
    async with http(2000) as c:
        for rate in rates:
            for rnd in range(1, rounds + 1):
                batch = [next(it) for _ in range(votes)]
                vs = [Vote(p.choice) for p in batch]
                t0 = time.perf_counter()
                tasks = []
                for i, (p, v) in enumerate(zip(batch, vs)):
                    d = t0 + i / rate - time.perf_counter()
                    if d > 0:
                        await asyncio.sleep(d)
                    tasks.append(asyncio.create_task(cast(c, p, v, retry=False)))
                t_sent = time.perf_counter() - t0
                await asyncio.gather(*tasks)
                ok = [v for v in vs if v.code == 201]
                t_last = max(v.t_done for v in vs) - t0
                L = [v.latency for v in ok]
                rows.append({"send_rate": rate, "round": rnd, "succ": len(ok), "fail": votes - len(ok),
                             "achieved_send_rate": round(votes / t_sent, 1) if t_sent else None,
                             "throughput_tps": round(len(ok) / t_last, 1) if t_last else None,
                             "avg_latency_s": round(statistics.fmean(L), 3) if L else None,
                             "min_latency_s": round(min(L), 3) if L else None,
                             "max_latency_s": round(max(L), 3) if L else None,
                             "fail_codes": {str(cd): sum(1 for v in vs if v.code == cd) for cd in {v.code for v in vs if v.code != 201}}})
                print(f"    rate {rate:>4}/s round {rnd}: succ {len(ok):>5} fail {votes - len(ok):>4} "
                      f"tput {rows[-1]['throughput_tps']:>6}/s avg {rows[-1]['avg_latency_s']} s max {rows[-1]['max_latency_s']} s", flush=True)
                await asyncio.sleep(2)
    summ = []
    for rate in rates:
        rs = [r for r in rows if r["send_rate"] == rate]
        summ.append({"send_rate": rate, "succ": sum(r["succ"] for r in rs), "fail": sum(r["fail"] for r in rs),
                     "throughput_tps_mean": round(statistics.fmean(r["throughput_tps"] for r in rs), 1),
                     "avg_latency_s_mean": round(statistics.fmean(r["avg_latency_s"] for r in rs if r["avg_latency_s"] is not None), 3),
                     "max_latency_s": max(r["max_latency_s"] or 0 for r in rs)})
    return {"votes_per_round": votes, "rounds": rounds, "candidates": k, "rows": rows, "summary": summ}


# ═════════════════════════════════════════════════════════════════════════════
#  clients — Khan et al. 2020: sequential clients (1 and 7)
# ═════════════════════════════════════════════════════════════════════════════
async def run_clients(clients, votes, k):
    stream = PackageStream(k, chunk=3000)
    await stream.start(votes)
    q = asyncio.Queue()
    feed_done = asyncio.Event()

    async def feeder():
        left = votes
        while left > 0:
            for p in await stream.take():
                await q.put(p)
                left -= 1
        feed_done.set()
    ft = asyncio.create_task(feeder())
    vs = []
    async with http(clients + 5) as c:
        await asyncio.sleep(0)
        while q.qsize() < min(votes, 1000) and not feed_done.is_set():
            await asyncio.sleep(0.2)
        t0 = time.perf_counter()

        async def client_loop():
            while True:
                if q.empty() and feed_done.is_set():
                    return
                try:
                    p = await asyncio.wait_for(q.get(), timeout=5)
                except asyncio.TimeoutError:
                    continue
                v = Vote(p.choice)
                vs.append(v)
                await cast(c, p, v, retry=True)
        await asyncio.gather(*[client_loop() for _ in range(clients)])
        wall = time.perf_counter() - t0
    await ft
    await stream.close()
    acc = [v for v in vs if v.accepted]
    # throughput per 10 s window (Khan report peak and worst)
    win = {}
    for v in acc:
        win.setdefault(int((v.t_done - t0) // 10), 0)
        win[int((v.t_done - t0) // 10)] += 1
    full = [n / 10 for w, n in win.items() if (w + 1) * 10 <= wall]
    return {"clients": clients, "votes": votes, "accepted": len(acc), "failed": len(vs) - len(acc),
            "wall_s": round(wall, 1), "votes_per_s": round(len(acc) / wall, 1),
            "s_per_vote_per_client": round(statistics.fmean(v.latency for v in acc), 4) if acc else None,
            "peak_10s_votes_per_s": max(full) if full else None, "worst_10s_votes_per_s": min(full) if full else None,
            "latency": lat_stats([v.latency for v in acc])}


# ═════════════════════════════════════════════════════════════════════════════
#  concurrent — ScalEVote: 10,000 votes submitted at once
# ═════════════════════════════════════════════════════════════════════════════
async def run_concurrent(votes, k, max_conns):
    pkgs = await make_and_seed(votes, k)
    vs = [Vote(p.choice) for p in pkgs]
    async with http(max_conns, timeout=60.0) as c:
        t0 = time.perf_counter()
        await asyncio.gather(*[cast(c, p, v, max_attempts=20) for p, v in zip(pkgs, vs)])
        wall = time.perf_counter() - t0
    acc = [v for v in vs if v.accepted]
    L = [v.latency for v in acc]
    return {"votes": votes, "client_connections": max_conns, "accepted": len(acc), "failed": votes - len(acc),
            "first_attempt_accepted": sum(1 for v in vs if v.first_code == 201),
            "retries": sum(v.attempts - 1 for v in vs), "completion_s": round(wall, 1),
            "votes_per_s": round(len(acc) / wall, 1), "latency_incl_retries": lat_stats(L)}


# ═════════════════════════════════════════════════════════════════════════════
#  ledger — Razaque Fig. 7: accuracy versus send rate, 1,000..8,000 per second
# ═════════════════════════════════════════════════════════════════════════════
def run_ledger_rate(rate, seconds, payloads):
    import threading
    import uuid
    import pulsar
    from tools.bench_ledger_stress import drop_topic
    topic = f"lit-acc-{rate}-{uuid.uuid4().hex[:6]}"
    full = f"persistent://public/default/{topic}"
    client = pulsar.Client(PULSAR_URL, operation_timeout_seconds=30)
    producer = client.create_producer(full, batching_enabled=True, batching_max_publish_delay_ms=10,
                                      batching_max_messages=1000, max_pending_messages=20000,
                                      block_if_queue_full=True, compression_type=pulsar.CompressionType.LZ4)
    reader = client.create_reader(full, pulsar.MessageId.earliest)
    n = int(rate * seconds)
    sent_hashes, lat, fails = [], [], [0]
    lock = threading.Lock()
    done = threading.Event()
    acked = [0]

    def cb(res, _mid, t=None):
        with lock:
            if res == pulsar.Result.Ok:
                acked[0] += 1
                if t is not None:
                    lat.append(time.perf_counter() - t)
            else:
                fails[0] += 1
            if acked[0] + fails[0] >= n:
                done.set()
    t0 = time.perf_counter()
    for i in range(n):
        d = t0 + i / rate - time.perf_counter()
        if d > 0:
            time.sleep(d)
        body = payloads[i % len(payloads)].replace(b'"seq":0', b'"seq":%d' % i)
        sent_hashes.append(hashlib.sha256(body).hexdigest())
        t = time.perf_counter() if i % 20 == 0 else None
        producer.send_async(body, lambda r, m, t=t: cb(r, m, t))
    t_send = time.perf_counter() - t0
    producer.flush()
    done.wait(120)
    t_ack = time.perf_counter() - t0
    t1 = time.perf_counter()
    got = []
    while len(got) < n:
        try:
            got.append(hashlib.sha256(reader.read_next(timeout_millis=10000).data()).hexdigest())
        except Exception:
            break
    t_read = time.perf_counter() - t1
    match = sum(1 for a, b in zip(sent_hashes, got) if a == b)
    reader.close()
    producer.close()
    client.close()
    drop_topic(topic)
    return {"offered_rate": rate, "seconds": seconds, "sent": n, "acked": acked[0], "failed": fails[0],
            "achieved_send_rate": round(n / t_send, 1), "acked_per_s": round(acked[0] / t_ack, 1),
            "ack_p50_ms": ms(pct(lat, .5)), "ack_p99_ms": ms(pct(lat, .99)),
            "read_back": len(got), "read_per_s": round(len(got) / t_read, 1) if t_read else None,
            "identical_in_order": match, "accuracy_pct": round(100 * match / n, 3) if n else None}


def make_records(n_hex, k, count=64):
    import uuid
    from app.services import ballot_proof as bp
    from app.services.ledger_service import canonical_ballot_bytes
    pp = bp.PublicParams.from_n(int(n_hex, 16))
    tpls = bf.make_templates(n_hex, k, 8)
    out = []
    for j in range(count):
        uti = os.urandom(32).hex()
        null = hashlib.sha256(uti.encode()).hexdigest()
        ct, pr = bf.instantiate(pp, tpls[j % len(tpls)], f"{bf.ELECTION_ID}|{null}")
        out.append(canonical_ballot_bytes({"ballot_id": str(uuid.uuid4()), "ciphertext": ct, "zkp_proof": pr,
                                           "num_candidates": k, "seq": 0, "ts": time.time(),
                                           "cast_at": "2026-11-18T00:00:00+00:00", "nullifier": null}))
    return out


# ═════════════════════════════════════════════════════════════════════════════
#  crypto — ElectionGuard verifier study, MERGE per-operation, STARK VC tally
# ═════════════════════════════════════════════════════════════════════════════
_PP = None


def _cinit(n_hex):
    global _PP
    from app.services import ballot_proof as bp
    _PP = bp.PublicParams.from_n(int(n_hex, 16))


def _cverify(items):
    from app.services import ballot_proof as bp
    ok = 0
    for ct, pr, ctx in items:
        cts, proof = bp.decode(ct, pr)
        ok += bp.verify_ballot(_PP, cts, proof, ctx)
    return ok


def eg_records(n_hex, ballots, contests, k):
    """`ballots` ballots, each with `contests` single-choice contests of k options."""
    from app.services import ballot_proof as bp
    pp = bp.PublicParams.from_n(int(n_hex, 16))
    tpls = bf.make_templates(n_hex, k, 32)
    rec = []
    for b in range(ballots):
        row = []
        for c in range(contests):
            tpl = tpls[(b * contests + c) % len(tpls)]
            ctx = f"{bf.ELECTION_ID}|eg-{b}-{c}"
            ct, pr = bf.instantiate(pp, tpl, ctx)
            row.append((ct, pr, ctx, tpl["choice"]))
        rec.append(row)
    return rec


def eg_verify(key, ex, rec, contests, k, procs):
    """Verify an election record: every ballot proof, then each contest's
    tally and its 3-of-5 decryption (what a verifier re-does)."""
    from gmpy2 import mpz
    from app.services import ballot_proof as bp
    from app.services import threshold_paillier as tp
    items = [(ct, pr, ctx) for row in rec for ct, pr, ctx, _ in row]
    per = max(1, len(items) // (procs * 4))
    shards = [items[i:i + per] for i in range(0, len(items), per)]
    t0 = time.perf_counter()
    valid = sum(ex.map(_cverify, shards))
    t_proofs = time.perf_counter() - t0
    t1 = time.perf_counter()
    ok = True
    for c in range(contests):
        T = [mpz(1)] * k
        for row in rec:
            cts, _ = bp.decode(row[c][0], row[c][1])
            for i in range(k):
                T[i] = T[i] * cts[i] % key.n2
        got = tp.decrypt_totals(key, T, list(range(1, key.t + 1)))
        ok &= got == [sum(1 for row in rec if row[c][3] == j) for j in range(k)]
    t_tally = time.perf_counter() - t1
    return {"ballots": len(rec), "proofs": len(items), "valid": valid, "proofs_s": round(t_proofs, 3),
            "tally_decrypt_s": round(t_tally, 3), "total_s": round(t_proofs + t_tally, 3), "tally_correct": ok}


def merge_ops(key, n_hex, contests=7, k=4, ballots=10):
    """MERGE Sec. 7 operations on the same ballot shape (7 contests x 4 selections)."""
    from gmpy2 import mpz
    from app.services import ballot_proof as bp
    from app.services import threshold_paillier as tp
    pp = bp.PublicParams.from_n(int(n_hex, 16))
    enc, ver, recs = [], [], []
    for b in range(ballots):
        t = time.perf_counter()
        row = []
        for c in range(contests):
            ch = random.randrange(k)
            cts, rs = bp.encrypt_ballot(pp, ch, k)
            pr = bp.prove_ballot(pp, cts, rs, ch, f"merge-{b}-{c}")
            row.append((cts, pr, f"merge-{b}-{c}"))
        enc.append(time.perf_counter() - t)
        recs.append(row)
    for row in recs:
        t = time.perf_counter()
        assert all(bp.verify_ballot(pp, cts, pr, ctx) for cts, pr, ctx in row)
        ver.append(time.perf_counter() - t)
    cs = [c for row in recs for cts, _, _ in row for c in cts]
    t = time.perf_counter()
    acc = mpz(1)
    for c in cs:
        acc = acc * c % key.n2
    per_mul = (time.perf_counter() - t) / len(cs)
    t = time.perf_counter()
    for c in cs[:20]:
        tp.combine(key, {i: tp.partial_decrypt(key, i, c) for i in (1, 2, 3)})
    per_dec = (time.perf_counter() - t) / 20
    return {"ballot_shape": f"{contests} contests x {k} selections", "ballots": ballots,
            "encrypt_and_prove_ms_per_ballot": round(statistics.fmean(enc) * 1000, 1),
            "verify_ms_per_ballot": round(statistics.fmean(ver) * 1000, 1),
            "homomorphic_tally_ms_per_encryption": round(per_mul * 1000, 4),
            "tally_decryption_ms_per_encryption_3_trustees": round(per_dec * 1000, 2)}


def _stark_child(args):
    """One tally in a fresh process so its peak memory is its own."""
    n_hex, voters, k, shares_path = args
    from gmpy2 import mpz
    from app.services import ballot_proof as bp
    from app.services import threshold_paillier as tp
    os.environ["TRUSTEE_SHARES"] = shares_path
    key = load_threshold_key()
    pp = bp.PublicParams.from_n(int(n_hex, 16))
    choices = [random.randrange(k) for _ in range(voters)]
    ballots = [bp.encrypt_ballot(pp, ch, k)[0] for ch in choices]
    base = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    c0 = time.process_time()
    t0 = time.perf_counter()
    T = [mpz(1)] * k
    for cts in ballots:
        for i in range(k):
            T[i] = T[i] * cts[i] % key.n2
    got = tp.decrypt_totals(key, T, [1, 2, 3])
    wall = time.perf_counter() - t0
    cpu = time.process_time() - c0
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return {"voters": voters, "candidates": k, "tally_and_decrypt_wall_s": round(wall, 4),
            "core_seconds": round(cpu, 4), "core_minutes": round(cpu / 60, 5),
            "peak_rss_MB": round(peak / 1024, 1), "rss_before_tally_MB": round(base / 1024, 1),
            "correct": got == [choices.count(j) for j in range(k)]}


def run_crypto(eg_sizes, eg_contests, eg_k, runs, procs):
    import platform
    n_hex = load_threshold_key_hex()
    key = load_threshold_key()
    out = {"cpu": platform.processor() or platform.machine(), "processes": procs}
    print(f"  ElectionGuard verifier scenario: {eg_contests} contests x {eg_k} options, 3-of-5 trustees, {procs} processes")
    rec = eg_records(n_hex, max(eg_sizes), eg_contests, eg_k)
    eg = []
    ex = ProcessPoolExecutor(max_workers=procs, initializer=_cinit, initargs=(n_hex,))
    list(ex.map(_cverify, [[]] * procs))            # start the workers before timing
    for n in eg_sizes:
        rr = [eg_verify(key, ex, rec[:n], eg_contests, eg_k, procs) for _ in range(runs)]
        row = {"ballots": n, "runs": runs, "total_s_mean": round(statistics.fmean(r["total_s"] for r in rr), 3),
               "total_s_sd": round(statistics.pstdev(r["total_s"] for r in rr), 3),
               "proofs_s_mean": round(statistics.fmean(r["proofs_s"] for r in rr), 3),
               "all_valid": all(r["valid"] == r["proofs"] for r in rr), "tally_correct": all(r["tally_correct"] for r in rr)}
        eg.append(row)
        print(f"    {n:>5} ballots: {row['total_s_mean']} ± {row['total_s_sd']} s  valid {row['all_valid']}  tally {row['tally_correct']}", flush=True)
    ex.shutdown()
    out["electionguard_scenario"] = {"contests": eg_contests, "options": eg_k, "rows": eg}
    print("  MERGE per-operation scenario (7 contests x 4 selections)")
    out["merge_scenario"] = merge_ops(key, n_hex)
    print("   ", out["merge_scenario"])
    print("  STARK vector-commitment scenario (tally of 64 and 1,024 voters)")
    st = []
    with ProcessPoolExecutor(max_workers=1) as ex:
        for v in (64, 1024):
            st.append(ex.submit(_stark_child, (n_hex, v, 4, SHARES_PATH)).result())
            print("   ", st[-1], flush=True)
    out["stark_scenario"] = st
    return out


def load_threshold_key_hex():
    with open(SHARES_PATH) as f:
        return json.load(f)["n"]


# ═════════════════════════════════════════════════════════════════════════════
#  summary — one markdown table per scenario, published value beside ours
# ═════════════════════════════════════════════════════════════════════════════
def _load(name):
    path = os.path.join(OUT_DIR, name)
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)


def write_summary():
    L = ["# Literature-matched benchmarks", "",
         "Published figures are copied from each paper; ours are measured on this machine with every ballot proof "
         "and device signature verified. 'n/a' = not run yet.", ""]
    # 1. two voting modes, write and read speed
    L += ["## Two voting modes: write and read speed (Razaque Sec. 4.2 modes; N as in Razaque Fig. 10 and Patel Table 2)", "",
          "| Mode | Votes | Write votes/s | First try | Write p50 / p99 ms | Ledger read/s | PostgreSQL read/s | Receipt lookups/s | Audit paths/s | Count s | Correct |",
          "|---|---|---|---|---|---|---|---|---|---|---|"]
    for mode in ("even", "burst"):
        for n in (1000, 2000, 3000, 4000, 5000):
            r = _load(f"lit_wr_{mode}_{n}.json")
            if not r:
                continue
            w, rd = r["write"], r["read"]
            lt = w["latency_incl_retries"]
            L.append(f"| {mode} | {n:,} | {w['write_votes_per_s']} | {w['first_attempt_accepted']:,}/{n:,} | {lt.get('p50_ms')} / {lt.get('p99_ms')} | "
                     f"{rd['ledger_readback']['records_per_s']} | {rd['primary_scan']['records_per_s']} | {rd['receipt_lookup']['reads_per_s']} | "
                     f"{rd['merkle_audit_path']['reads_per_s']} | {rd['counting']['count_s']} | {rd['counting']['correct']} |")
    L += ["", "Published: Razaque BCVS counts 1,000-5,000 votes in 4-8 s (Fig. 10; 7.42 s at 5,000 in Table 4; Follow My Vote 8.62 s, "
          "Agora 9.81 s, Votem 9.81 s, Horizon State 11 s). Patel (IBFT, 5 nodes): write 17/31/48/42/40 TPS at 1,000-5,000 "
          "transactions, peak 52 TPS; read (balance query) peak 162 TPS.", ""]
    # 2. 15-minute window
    L += ["## 15-minute voting window (Razaque Figs. 5, 8, 9)", "",
          "| Mode | Minute | Votes cast | Durable in ledger | Verified by replica |", "|---|---|---|---|---|"]
    for mode in ("even", "burst"):
        r = _load(f"lit_window_{mode}.json")
        if not r:
            continue
        for m in r["marks"]:
            L.append(f"| {mode} | {m['minute']} | {m['accepted']:,} | {m['durable']:,} ({m['durable_pct']}%) | {m['replica_verified']:,} ({m['verified_pct']}%) |")
        L.append(f"| {mode} | latency | p50 {r['latency_incl_retries'].get('p50_ms')} ms, p99 {r['latency_incl_retries'].get('p99_ms')} ms | "
                 f"retries {r['retries']:,} | all verified {r['replica_lag_after_last_vote_s']} s after the last vote |")
    L += ["", "Published (votes cast in 15 min): BCVS 2,292; Votem 2,084; Follow My Vote 1,998; Horizon State 1,998; Agora 1,882. "
          "Confirmed transactions within 20 min: BCVS 99.99%, Horizon State 56.89%. Audited/verified votes after 10 h: BCVS 95%.", ""]
    # 3. Saeed rates
    r = _load("lit_rates.json")
    L += ["## Fixed send rates, 1,000 votes x 5 rounds (Saeed et al. 2022, Hyperledger Fabric + Caliper)", "",
          "| Send rate/s | Succ | Fail | Throughput/s | Avg latency s | Max latency s |", "|---|---|---|---|---|---|"]
    for x in (r or {}).get("summary", []):
        L.append(f"| {x['send_rate']:.0f} | {x['succ']:,} | {x['fail']:,} | {x['throughput_tps_mean']} | {x['avg_latency_s_mean']} | {x['max_latency_s']} |")
    L += ["", "Published: peak 97 TPS (block timeout 5 s); 61 TPS peak when varying block size; latency up to 10-13 s at short block timeouts.", ""]
    # 4. Khan clients
    L += ["## Sequential clients (Khan et al. 2020, MultiChain, permissioned)", "",
          "| Clients | Votes | Votes/s | s per vote | Peak / worst 10 s votes/s |", "|---|---|---|---|---|"]
    for cl in (1, 7):
        r = _load(f"lit_clients_{cl}.json")
        if r:
            L.append(f"| {cl} | {r['votes']:,} | {r['votes_per_s']} | {r['s_per_vote_per_client']} | {r['peak_10s_votes_per_s']} / {r['worst_10s_votes_per_s']} |")
    L += ["", "Published: case 1 (one client, ~9,000 tx) peak 23.01 TPS, worst 12.71 TPS, 0.043 s per tx; "
          "case 3 (seven clients, 222,000 tx) about 0.10 s per tx.", ""]
    # 5. ScalEVote
    r = _load("lit_concurrent.json")
    L += ["## 10,000 votes submitted at once (ScalEVote)", ""]
    if r:
        lt = r["latency_incl_retries"]
        L.append(f"Ours: {r['accepted']:,}/{r['votes']:,} accepted ({r['first_attempt_accepted']:,} at the first try), all done in "
                 f"{r['completion_s']} s ({r['votes_per_s']} votes/s); end-to-end latency {lt.get('mean_ms')} +/- {lt.get('sd_ms')} ms (max {lt.get('max_ms')} ms).")
    L += ["", "Published: up to 10,000 concurrent votes with 10 regional servers; average end-to-end latency under 2,300 ms (+/- 1,612 ms).", ""]
    # 6. ledger accuracy
    r = _load("lit_ledger_accuracy.json")
    L += ["## Accuracy versus send rate (Razaque Fig. 7)", "",
          "| Offered/s | Acked/s | Ack p99 ms | Read back/s | Identical, in order |", "|---|---|---|---|---|"]
    for x in (r or {}).get("rows", []):
        L.append(f"| {x['offered_rate']:,} | {x['acked_per_s']} | {x['ack_p99_ms']} | {x['read_per_s']} | {x['accuracy_pct']}% |")
    L += ["", "Published: accuracy falls as the send rate rises from 1,000 to 8,000 tps; BCVS highest (about 95% at 6,000 tps; Table 4: 95.02%).", ""]
    # 7. crypto
    r = _load("lit_crypto.json")
    L += ["## Verifying an election record (ElectionGuard verifier study, College Park shape)", ""]
    if r:
        eg = r["electionguard_scenario"]
        L += [f"Ours: {eg['contests']} contests x {eg['options']} options per ballot, 3-of-5 trustees, {r['processes']} processes.", "",
              "| Ballots | Verify s (mean +/- SD) | All proofs valid | Tally correct |", "|---|---|---|---|"]
        for x in eg["rows"]:
            L.append(f"| {x['ballots']:,} | {x['total_s_mean']} +/- {x['total_s_sd']} | {x['all_valid']} | {x['tally_correct']} |")
        m = r["merge_scenario"]
        L += ["", "Published (1,341 ballots): Go verifier 11.13 s on a 20-core i9, 30.18 s on an 8-core M1; MITRE Julia 74.05 s / 142.70 s.", "",
              "## Per-operation costs (MERGE, 7 contests x 4 selections)", "",
              "| Operation | Ours | MERGE (EC ElGamal, Xeon E5-2680 v3) |", "|---|---|---|",
              f"| Encrypt + ZKP per ballot | {m['encrypt_and_prove_ms_per_ballot']} ms | about 20 ms |",
              f"| Verify per ballot | {m['verify_ms_per_ballot']} ms | about 15 ms |",
              f"| Homomorphic tally per encryption | {m['homomorphic_tally_ms_per_encryption']} ms | 0.22 ms |",
              f"| Tally decryption per encryption, 3 trustees | {m['tally_decryption_ms_per_encryption_3_trustees']} ms | 2.2 ms |",
              "", "## Tally of 64 and 1,024 voters (STARK vector-commitment study)", "",
              "| Voters | Ours: core-minutes | Ours: peak process memory | Published: core-minutes | Published: peak RAM |", "|---|---|---|---|---|"]
        pub = {64: ("1.15", "1.38 GB"), 1024: ("20.8", "11.82 GB (Harrison & Haines: 175.41 GB)")}
        for x in r["stark_scenario"]:
            pc, pm = pub.get(x["voters"], ("-", "-"))
            L.append(f"| {x['voters']:,} | {x['core_minutes']} | {x['peak_rss_MB']} MB | {pc} | {pm} |")
        L += ["", "Not like for like: the published figures include generating a STARK proof that the tally is correct; "
              "ours are the homomorphic tally plus 3-of-5 threshold decryption, whose correctness anyone can re-check by "
              "recomputing the product of the published ciphertexts."]
    L += ["", "Abuidris et al. (PSC-Bchain): >60 TPS and ~27 s latency at 1,000 simulated nodes — node-count simulation, "
          "no matching run on one machine; compare against the throughput and latency rows above.", ""]
    path = os.path.join(OUT_DIR, "lit_results.md")
    with open(path, "w") as f:
        f.write("\n".join(L) + "\n")
    print("\n".join(L))
    print("saved", path)


# ═════════════════════════════════════════════════════════════════════════════
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("wr")
    a.add_argument("--mode", choices=["even", "burst"], required=True)
    a.add_argument("--votes", type=int, nargs="+", default=[1000, 2000, 3000, 4000, 5000])
    a.add_argument("--even-seconds", type=float, default=60.0)
    a.add_argument("--burst-seconds", type=float, default=5.0)
    b = sub.add_parser("window")
    b.add_argument("--mode", choices=["even", "burst"], required=True)
    b.add_argument("--rate", type=float, default=80.0)    # ~85% of the measured capacity (lit-wr burst: 95-97 votes/s)
    b.add_argument("--minutes", type=float, default=15.0)
    b.add_argument("--tail-minutes", type=float, default=5.0)
    b.add_argument("--burst-every", type=float, default=10.0)
    b.add_argument("--burst-seconds", type=float, default=5.0)
    c = sub.add_parser("rates")
    c.add_argument("--rates", type=float, nargs="+", default=[50, 100, 150, 200, 250])
    c.add_argument("--votes", type=int, default=1000)
    c.add_argument("--rounds", type=int, default=5)
    d = sub.add_parser("clients")
    d.add_argument("--clients", type=int, required=True)
    d.add_argument("--votes", type=int, required=True)
    e = sub.add_parser("concurrent")
    e.add_argument("--votes", type=int, default=10000)
    e.add_argument("--connections", type=int, default=10000)
    f = sub.add_parser("ledger")
    f.add_argument("--rates", type=int, nargs="+", default=[1000, 2000, 3000, 4000, 5000, 6000, 7000, 8000])
    f.add_argument("--seconds", type=float, default=2.0)
    g = sub.add_parser("crypto")
    g.add_argument("--eg-sizes", type=int, nargs="+", default=[25, 50, 100, 250, 500, 750, 1000, 1341])
    g.add_argument("--eg-contests", type=int, default=6)
    g.add_argument("--eg-options", type=int, default=3)
    g.add_argument("--runs", type=int, default=3)
    g.add_argument("--procs", type=int, default=os.cpu_count() or 1)
    sub.add_parser("summary")
    for p in (a, b, c, d, e, f):
        p.add_argument("--candidates", type=int, default=4)
    args = ap.parse_args()

    if args.cmd == "wr":
        for n in args.votes:
            r = asyncio.run(run_wr(args.mode, n, args.candidates, args.even_seconds, args.burst_seconds))
            print_wr(r)
            print("  saved", save(f"lit_wr_{args.mode}_{n}.json", r), flush=True)
    elif args.cmd == "window":
        r = asyncio.run(run_window(args.mode, args.rate, args.minutes, args.tail_minutes, args.candidates,
                                   args.burst_every, args.burst_seconds))
        print_window(r)
        print("  saved", save(f"lit_window_{args.mode}.json", r))
    elif args.cmd == "rates":
        r = asyncio.run(run_rates(args.rates, args.votes, args.rounds, args.candidates))
        print(f"\n  {'send rate':>9} {'succ':>6} {'fail':>5} {'tput/s':>8} {'avg lat s':>10} {'max lat s':>10}")
        for s in r["summary"]:
            print(f"  {s['send_rate']:>9.0f} {s['succ']:>6} {s['fail']:>5} {s['throughput_tps_mean']:>8} {s['avg_latency_s_mean']:>10} {s['max_latency_s']:>10}")
        print("  saved", save("lit_rates.json", r))
    elif args.cmd == "clients":
        r = asyncio.run(run_clients(args.clients, args.votes, args.candidates))
        print(f"\n  {args.clients} sequential client(s), {r['votes']:,} votes: {r['accepted']:,} accepted, {r['votes_per_s']} votes/s, "
              f"{r['s_per_vote_per_client']} s per vote; 10 s windows peak {r['peak_10s_votes_per_s']} / worst {r['worst_10s_votes_per_s']} votes/s")
        print("  saved", save(f"lit_clients_{args.clients}.json", r))
    elif args.cmd == "concurrent":
        r = asyncio.run(run_concurrent(args.votes, args.candidates, args.connections))
        L = r["latency_incl_retries"]
        print(f"\n  {r['votes']:,} votes at once: {r['accepted']:,} accepted ({r['first_attempt_accepted']:,} first try), "
              f"done in {r['completion_s']} s; latency mean {L.get('mean_ms')} ± {L.get('sd_ms')} ms, max {L.get('max_ms')} ms")
        print("  saved", save("lit_concurrent.json", r))
    elif args.cmd == "ledger":
        n_hex = asyncio.run(n_hex_from_board())
        recs = make_records(n_hex, args.candidates)
        rows = []
        print(f"  record size {len(recs[0]):,} B ({args.candidates} candidates)")
        for rate in args.rates:
            rows.append(run_ledger_rate(rate, args.seconds, recs))
            x = rows[-1]
            print(f"    offered {rate:>5}/s: acked {x['acked']:,}/{x['sent']:,} at {x['acked_per_s']}/s, ack p99 {x['ack_p99_ms']} ms, "
                  f"read back {x['read_back']:,} at {x['read_per_s']}/s, identical {x['accuracy_pct']}%", flush=True)
        print("  saved", save("lit_ledger_accuracy.json", {"record_bytes": len(recs[0]), "rows": rows}))
    elif args.cmd == "summary":
        write_summary()
    elif args.cmd == "crypto":
        r = run_crypto(args.eg_sizes, args.eg_contests, args.eg_options, args.runs, args.procs)
        print("  saved", save("lit_crypto.json", r))


if __name__ == "__main__":
    main()
