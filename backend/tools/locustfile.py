# backend/tools/locustfile.py
"""
Section 5.3 — Locust load test exactly as described in the manuscript:
200 concurrent users, ramp 20 users/s, 120 s, every vote a fully valid
Algorithm 1 package (ballot, validity proof bound to its ticket, fresh
timestamp, device signature). Each simulated voter waits 1–2 s between
submissions (≈130 votes/s offered at 200 users).

  locust -f tools/locustfile.py --headless -u 200 -r 20 -t 120s \
         --host http://localhost:8000 --only-summary
"""
import json
import os
import queue
import sys

import redis
from locust import HttpUser, between, events, task

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tools import ballot_factory as bf   # noqa: E402

PACKAGES: "queue.Queue" = queue.Queue()
OUT_DIR = os.environ.get("RESULTS_DIR", "/app/paper/results/docker")


@events.init.add_listener
def prepare(environment, **_kw):
    n = int(os.environ.get("LOCUST_PACKAGES", "30000"))
    bb = redis.from_url(os.environ.get("BULLETIN_URL", "redis://bulletin:6379/0"), decode_responses=True)
    r = redis.from_url(os.environ.get("REDIS_URL", "redis://redis:6379/0"), decode_responses=True)
    pkgs = bf.make_packages(bb.get("election:public_n"), n, k=2, procs=1)
    pipe = r.pipeline(transaction=False)
    for p in pkgs:
        pipe.set(f"ballot_ticket:{p.uti}", p.pk_hex, ex=7200)
        PACKAGES.put(p)
    pipe.execute()
    print(f"prepared {n:,} valid ballot packages")


@events.quitting.add_listener
def summary(environment, **_kw):
    st = environment.stats.total
    out = {"users": environment.parsed_options.num_users if environment.parsed_options else None,
           "requests": st.num_requests, "failures": st.num_failures,
           "throughput_per_s": st.total_rps, "p50_ms": st.get_response_time_percentile(0.5),
           "p95_ms": st.get_response_time_percentile(0.95), "p99_ms": st.get_response_time_percentile(0.99),
           "max_ms": st.max_response_time, "mean_ms": st.avg_response_time}
    out["thresholds"] = {"p95_lt_300ms": out["p95_ms"] < 300, "p99_lt_600ms": out["p99_ms"] < 600,
                         "throughput_gt_100": out["throughput_per_s"] > 100, "no_failures": st.num_failures == 0}
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(os.path.join(OUT_DIR, "locust.json"), "w") as f:
        json.dump(out, f, indent=2)
    print("\n=== SECTION 5.3 — LOCUST (200 users, ramp 20/s, 120 s, full Algorithm 1) ===")
    for k in ("requests", "failures", "throughput_per_s", "p50_ms", "p95_ms", "p99_ms", "max_ms"):
        print(f"  {k:<18} {out[k]:,.1f}" if isinstance(out[k], float) else f"  {k:<18} {out[k]:,}")
    for k, v in out["thresholds"].items():
        print(f"  threshold {k:<18} {'MET' if v else 'NOT MET'}")


class Voter(HttpUser):
    wait_time = between(1, 2)

    @task
    def cast(self):
        try:
            p = PACKAGES.get_nowait()
        except queue.Empty:
            return
        with self.client.post("/api/v1/vote/cast", json=p.body(), name="cast", catch_response=True) as resp:
            if resp.status_code == 201:
                resp.success()
            else:
                resp.failure(f"HTTP {resp.status_code}")
