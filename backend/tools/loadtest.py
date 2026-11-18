#!/usr/bin/env python3
# backend/tools/loadtest.py
"""Kept for compatibility: delegates to tools.bench_load (closed loop, fully valid ballots)."""
import argparse
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tools.bench_load import closed   # noqa: E402

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--votes", type=int, default=5000)
    ap.add_argument("--concurrency", type=int, default=100)
    ap.add_argument("--candidates", type=int, default=2)
    a, _ = ap.parse_known_args()
    print(asyncio.run(closed(a.votes, a.concurrency, a.candidates)))
