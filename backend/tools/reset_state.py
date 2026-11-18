#!/usr/bin/env python3
# backend/tools/reset_state.py
"""
Give an experiment a clean, identical starting state.

Drops the primary vote ledger table, deletes the replica's write-once store,
and empties the ticket store and the bulletin board. Run with the ledger
worker, the integrity service and the replica STOPPED; then publish a fresh
election key (tools.election_setup) and start them again.
"""
import asyncio
import glob
import os

import asyncpg
import redis.asyncio as aioredis

from app.workers.common import pg_dsn


async def main():
    conn = await asyncpg.connect(pg_dsn(os.environ["DATABASE_URL"]))
    await conn.execute("DROP TABLE IF EXISTS vote_ledger")
    await conn.close()
    for f in glob.glob(os.environ.get("REPLICA_DB", "/app/replica_data/replica.db") + "*"):
        os.remove(f)
    for url in (os.environ.get("REDIS_URL", "redis://redis:6379/0"),
                os.environ.get("BULLETIN_URL", "redis://bulletin:6379/0")):
        r = aioredis.from_url(url)
        await r.flushdb()
        await r.aclose()
    print("state reset: vote_ledger dropped, replica store deleted, ticket store and bulletin board emptied")


if __name__ == "__main__":
    asyncio.run(main())
