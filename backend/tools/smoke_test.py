#!/usr/bin/env python3
# backend/tools/smoke_test.py
"""
Two-minute functional check of the whole system before the long run.

Casts 300 valid votes, checks a replay and a forged proof are rejected, waits
for the primary and the replica to agree (PASS) and the liveness verdict to be
LIVE, tampers one stored ballot and checks it is detected, localised and
locks ingestion, then restores it. Prints PASS/FAIL per check.
"""
import asyncio
import json
import os
import sys
import time

import asyncpg
import httpx
import redis.asyncio as aioredis

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.services.audit_service import classify_round   # noqa: E402
from app.workers.common import pg_dsn                    # noqa: E402
from tools import ballot_factory as bf                   # noqa: E402

BASE = os.environ.get("LOADTEST_URL", "http://localhost:8000")


async def main():
    r = aioredis.from_url(os.environ.get("REDIS_URL", "redis://redis:6379/0"), decode_responses=True)
    bb = aioredis.from_url(os.environ.get("BULLETIN_URL", "redis://bulletin:6379/0"), decode_responses=True)
    checks = {}
    pk = bf.make_packages(await bf.election_n_hex(bb), 305, k=2)
    await bf.seed_tickets(r, pk)
    async with httpx.AsyncClient(base_url=BASE, timeout=60) as c:
        sem = asyncio.Semaphore(20)

        async def cast(p):
            async with sem:
                return (await c.post("/api/v1/vote/cast", json=p.body())).status_code
        codes = await asyncio.gather(*[cast(p) for p in pk[:300]])
        checks["300 valid votes accepted"] = codes.count(201) == 300
        checks["replay rejected (409)"] = (await c.post("/api/v1/vote/cast", json=pk[0].body())).status_code == 409
        checks["forged proof rejected (422)"] = (await c.post("/api/v1/vote/cast", json=pk[300].body(tamper="proof"))).status_code == 422

        t0 = time.time()
        ok = False
        while time.time() - t0 < 60:
            if (await bb.get("replica:status") == "PASS" and int(await bb.get("replica:count") or 0) >= 300
                    and int(await bb.get("primary:count") or 0) >= 300):
                ok = True
                break
            await asyncio.sleep(0.5)
        checks["primary and replica agree (PASS)"] = ok
        await asyncio.sleep(6)
        latest = int(await bb.get("liveness:latest") or 0)
        verdicts = [classify_round(await bb.hgetall(f"liveness:round:{i}"), time.time()) for i in range(max(1, latest - 3), latest)]
        checks["liveness LIVE"] = bool(verdicts) and all(v in ("LIVE", "PENDING") for v in verdicts) and "LIVE" in verdicts

        conn = await asyncpg.connect(pg_dsn(os.environ["DATABASE_URL"]))
        orig = await conn.fetchval("SELECT payload FROM vote_ledger WHERE seq = 123")
        donor = await conn.fetchval("SELECT payload FROM vote_ledger WHERE seq = 7")
        await conn.execute("UPDATE vote_ledger SET payload = $1 WHERE seq = 123", donor)
        t0 = time.time()
        alert = None
        while time.time() - t0 < 30:
            a = await bb.get("alert:active")
            if a and all(b.get("located") for b in json.loads(a)["bundles"]):
                alert = json.loads(a)
                break
            await asyncio.sleep(0.1)
        checks["tamper detected"] = alert is not None
        checks["tamper localised to ledger position 123"] = bool(alert) and alert["bundles"][0]["located"]["ledger_seq"] == [123]
        resp = await c.post("/api/v1/vote/cast", json=pk[301].body())
        checks["lockdown refuses new votes (503)"] = resp.status_code == 503
        await conn.execute("UPDATE vote_ledger SET payload = $1 WHERE seq = 123", orig)
        await bb.delete("alert:active")
        await conn.close()
        t0 = time.time()
        back = False
        while time.time() - t0 < 30:
            if await bb.get("replica:status") == "PASS" and not await bb.get("alert:active"):
                back = True
                break
            await asyncio.sleep(0.5)
        checks["back to PASS after restore"] = back
        await asyncio.sleep(1)
        checks["voting resumes after lockdown cleared"] = (await c.post("/api/v1/vote/cast", json=pk[302].body())).status_code == 201

    print("\n=== SMOKE TEST ===")
    for k, v in checks.items():
        print(f"  {'PASS' if v else 'FAIL'}  {k}")
    allok = all(checks.values())
    print(f"\nSMOKE TEST {'PASSED — safe to start the full run' if allok else 'FAILED — do not start the full run; send this output'}")
    await r.aclose()
    await bb.aclose()
    return allok


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(main()) else 1)
