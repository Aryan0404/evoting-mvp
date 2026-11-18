#!/usr/bin/env python3
# backend/tools/election_setup.py
"""
Election setup: the trustees' threshold key ceremony.

Generates a threshold Paillier key (t of K trustees, default 3 of 5),
publishes the public modulus n on the public bulletin board
(`election:public_n`, plus t and K), and writes the trustees' secret shares to
a local file for the tally step of the experiments. In a real election each
share would go to a different trustee and never be stored together.

Run:  python -m tools.election_setup            (inside the backend container)
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time

import redis.asyncio as aioredis

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.services import threshold_paillier as tp   # noqa: E402

# Trustee shares stay inside the backend container (never in the project folder,
# never visible to the replica). In a real election each share goes to a different trustee.
SHARES_PATH = os.environ.get("TRUSTEE_SHARES", "/tmp/trustee_shares.json")


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--key-bits", type=int, default=2048)
    ap.add_argument("--trustees", type=int, default=5)
    ap.add_argument("--threshold", type=int, default=3)
    ap.add_argument("--reuse", action="store_true",
                    help="republish the key from an earlier ceremony instead of generating a new one")
    ap.add_argument("--candidates", default=None,
                    help="JSON file with the ordered candidate list [{id, name, party, symbol}, ...]; "
                         "slot i of the ballot is candidate i (default: four placeholder candidates)")
    args = ap.parse_args()

    bb = aioredis.from_url(os.environ.get("BULLETIN_URL", "redis://bulletin:6379/0"), decode_responses=True)
    if args.candidates:
        with open(args.candidates) as f:
            cands = json.load(f)
        await bb.set("election:candidates", json.dumps(cands))
        print(f"Candidate list published ({len(cands)} candidates).")
    if args.reuse and os.path.exists(SHARES_PATH):
        with open(SHARES_PATH) as f:
            d = json.load(f)
        await bb.set("election:public_n", d["n"])
        await bb.set("election:trustees", d["K"])
        await bb.set("election:threshold", d["t"])
        print(f"Election key ({d['t']}-of-{d['K']}) republished on the bulletin board.")
        await bb.aclose()
        return

    t0 = time.perf_counter()
    key = tp.keygen(args.key_bits, K=args.trustees, t=args.threshold)
    dt = time.perf_counter() - t0
    await bb.set("election:public_n", format(int(key.n), "x"))
    await bb.set("election:trustees", args.trustees)
    await bb.set("election:threshold", args.threshold)
    os.makedirs(os.path.dirname(SHARES_PATH), exist_ok=True)
    with open(SHARES_PATH, "w") as f:
        json.dump({"n": format(int(key.n), "x"), "K": key.K, "t": key.t,
                   "shares": {str(i): format(int(s), "x") for i, s in key.shares.items()}}, f)
    print(f"Key ceremony: {args.threshold}-of-{args.trustees}, {args.key_bits}-bit, {dt:.1f}s. "
          f"Public key published on the bulletin board.")
    await bb.aclose()


if __name__ == "__main__":
    asyncio.run(main())
