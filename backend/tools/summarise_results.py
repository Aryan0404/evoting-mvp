#!/usr/bin/env python3
# backend/tools/summarise_results.py
"""
Collect every result file into one report, organised by manuscript section.

Reads the JSON outputs in paper/results/docker/ and writes paper_results.md
(also printed). Missing experiments are marked as such, never filled in.

Run:  python -m tools.summarise_results
"""
from __future__ import annotations

import csv
import glob
import json
import os
import statistics
import sys

OUT_DIR = os.environ.get("RESULTS_DIR", "/app/paper/results/docker")


def load(name):
    p = os.path.join(OUT_DIR, name)
    if not os.path.exists(p):
        return None
    with open(p) as f:
        return json.load(f)


def ms(x, d=1):
    return "—" if x is None else f"{x:.{d}f}"


def msd(vals, d=1):
    vals = [v for v in vals if v is not None]
    if not vals:
        return "—"
    if len(vals) == 1:
        return f"{vals[0]:.{d}f}"
    return f"{statistics.mean(vals):.{d}f} ± {statistics.stdev(vals):.{d}f}"


def main():
    L = []
    w = L.append
    setup = None
    try:
        setup = open(os.path.join(OUT_DIR, "setup.txt")).read().strip()
    except OSError:
        pass
    crypto = load("crypto.json")
    w("# Measured results for the manuscript (Section 5)\n")
    w("Every number below was produced by `./run_paper_experiments.sh`; nothing is simulated or extrapolated.\n")

    w("## 5.1 Experimental setup\n")
    if crypto:
        s = crypto["setup"]
        w(f"- Host: {s.get('host_label')}")
        w(f"- Containers: {s['os']}, Python {s['python']}, {s['logical_cores']} CPUs visible, {s['ram_gb']} GB")
        libs = s["libraries"]
        w(f"- Crypto: phe {libs.get('phe')} (gmpy2 {libs.get('gmpy2')}), ecdsa {libs.get('ecdsa')}, Paillier 2048-bit, "
          f"threshold {crypto['config']['threshold']}-of-{crypto['config']['trustees']}")
    if setup:
        for line in setup.splitlines():
            w(f"- {line}")
    w("- Ledger: Apache Pulsar 3.1.0 broker + 4 BookKeeper storage nodes, ensemble 3 / write quorum 2 / ack quorum 2\n")

    lc = load("locust.json")
    w("## 5.3 Throughput and end-to-end latency (Locust, 200 users, ramp 20/s, 120 s)\n")
    if lc:
        w("| Requests | Failures | Throughput (votes/s) | p50 (ms) | p95 (ms) | p99 (ms) | Max (ms) |")
        w("|---|---|---|---|---|---|---|")
        w(f"| {lc['requests']:,} | {lc['failures']:,} | {lc['throughput_per_s']:.1f} | {ms(lc['p50_ms'],0)} | "
          f"{ms(lc['p95_ms'],0)} | {ms(lc['p99_ms'],0)} | {ms(lc['max_ms'],0)} |")
        w("\nThresholds stated in the manuscript: " + ", ".join(f"{k} {'met' if v else 'NOT met'}" for k, v in lc["thresholds"].items()))
    else:
        w("_not run_")
    closed = [load(f"load_closed_r{i}.json") for i in (1, 2, 3)]
    closed = [c for c in closed if c] or [c for c in [load("load_closed.json")] if c]
    opened = [load(f"load_open_r{i}.json") for i in (1, 2, 3)]
    opened = [o for o in opened if o] or [o for o in [load("load_open.json")] if o]
    if closed:
        w(f"\nCeiling (closed loop, 20,000 votes, concurrency 100, {len(closed)} run(s)): "
          f"{msd([c['throughput_per_s'] for c in closed])} votes/s; p50 {msd([c['p50_ms'] for c in closed])} ms, "
          f"p95 {msd([c['p95_ms'] for c in closed])} ms, p99 {msd([c['p99_ms'] for c in closed])} ms; "
          f"accepted {sum(c['accepted'] for c in closed):,}/{sum(c['attempted'] for c in closed):,}.")
    if opened:
        w(f"\nLatency at a steady 100 votes/s (open loop, 60 s, {len(opened)} run(s)): "
          f"p50 {msd([o['legit']['p50_ms'] for o in opened])} ms, p95 {msd([o['legit']['p95_ms'] for o in opened])} ms, "
          f"p99 {msd([o['legit']['p99_ms'] for o in opened])} ms.")
    w("")

    w("## 5.4 Merkle bundle construction and voter verification\n")
    if crypto:
        S = crypto["summary"]
        w(f"- Root over a 10,000-vote bundle: {msd(S['merkle_build_ms']['values'], 2)} ms (depth 14)")
        w(f"- Voter receipt check (inclusion proof, {S['receipt_hashes']} hashes): {msd(S['receipt_ms']['values'], 4)} ms\n")

    w("## 5.5 Tamper detection, localisation, liveness (live system)\n")
    it = load("integrity_tamper.json")
    if it:
        w(f"Insider overwrites stored ballots in the primary ledger ({it['ledger_ballots']:,} ballots, bundles of 10,000):\n")
        w("| Tampered | Detected | Detection latency (s) | Min–max (s) | Localised exactly | Lockdown enforced | Node comparisons |")
        w("|---|---|---|---|---|---|---|")
        for s in it["summary"]:
            w(f"| {s['tampered']} | {s['detected']}/{s['trials']} | {ms(s['detect_mean_s'],2)} ± {ms(s['detect_sd_s'],2)} | "
              f"{ms(s['detect_min_s'],2)}–{ms(s['detect_max_s'],2)} | {s['located_exact']}/{s['trials']} | "
              f"{s['lockdown_enforced']}/{s['trials']} | {s['mean_comparisons']:.0f} |")
    lv = load("integrity_liveness.json")
    if lv:
        w(f"\nLiveness (cycle {lv['cycle_s']:.0f} s, τ = {lv['tau_s']:.0f} s): replica paused {lv['paused_for_s']:.0f} s → "
          f"reported STALE after {ms(lv['stale_reported_after_pause_s'])} s; LIVE again {ms(lv['live_again_after_resume_s'])} s "
          f"after resuming; DIVERGED verdicts: {lv['diverged_samples']}.")
    w("")

    w("## 5.6 Scalability under increasing load (real, open loop)\n")
    sw = load("load_sweep.json")
    if sw:
        w("| Offered (votes/s) | Achieved (votes/s) | Accepted | Shed by admission control (503) | Other failures | p50 (ms) | p95 (ms) | p99 (ms) |")
        w("|---|---|---|---|---|---|---|---|")
        for r in sw["rows"]:
            g = r["legit"]
            shed = g["status_counts"].get("503", 0)
            w(f"| {r['offered_rate']:.0f} | {g['throughput_per_s']:.1f} | {g['accepted']:,} | {shed:,} | {g['rejected_or_failed'] - shed:,} | "
              f"{ms(g['p50_ms'])} | {ms(g['p95_ms'])} | {ms(g['p99_ms'])} |")
        w("\nLatency percentiles are over accepted votes. A shed request is refused before its ticket is touched, "
          "so the voter's device can simply retry.")
    wk = sorted(glob.glob(os.path.join(OUT_DIR, "load_closed_w*.json")), key=lambda p: int(p.split("_w")[-1].split(".")[0]))
    if wk:
        w("\nHorizontal scaling of stateless vote collectors (API worker processes, closed loop 5,000 votes):\n")
        w("| Workers | Throughput (votes/s) | p50 (ms) | p99 (ms) |")
        w("|---|---|---|---|")
        for p in wk:
            d = json.load(open(p))
            w(f"| {p.split('_w')[-1].split('.')[0]} | {d['throughput_per_s']:.1f} | {ms(d['p50_ms'])} | {ms(d['p99_ms'])} |")
    w("")

    w("## 5.7 Fault tolerance under node failure (4 bookies, E=3/Qw=2/Qa=2)\n")
    ft = load("ft_summary.json")
    if ft:
        for e in ft["events"]:
            w(f"- t = {e['t_rel_s']:.1f} s: {e['event']}")
        w("")
        w(f"- Votes: {ft['accepted_client_view']:,}/{ft['votes_attempted']:,} accepted; failed after retries {ft['failed_after_all_retries']}; "
          f"lost {ft['lost_votes_server_vs_ledger']}; duplicates {ft['ledger_duplicates']}")
        w(f"- Read back from the ledger with the storage node down: {ft['ledger_unique_ballots']:,}; replica identical: "
          f"{ft['replica_matches_ledger_exactly']}; Merkle roots equal: {ft['merkle_roots_equal']}")
        w(f"- Latency p50/p99 (ms): before {ft['latency_p50_p99_ms_before_fault']}, first 10 s after node loss "
          f"{ft['latency_p50_p99_ms_first_10s_after_fault']}, rest {ft['latency_p50_p99_ms_after_recovery']}")
        w(f"- Replica down {ft['replica_downtime_s']} s, back in sync {ft['replica_catch_up_s_after_restart']} s after restart; "
          f"integrity alerts during faults (false positives): {ft['integrity_alerts_during_faults']}; liveness rounds {ft['liveness_rounds']}")
        q = ft.get("quorum_loss")
        if q:
            w(f"- Quorum loss for {q['outage_s']} s: {q['votes_cast_during_outage']} votes cast during the outage, "
              f"{q['eventually_accepted']} eventually accepted, {q['accepted_while_quorum_lost']} accepted while the quorum was lost, "
              f"first acceptance {q['first_acceptance_after_restore_s']} s after restore, max latency {q['max_latency_s']} s")
    ens = os.path.join(OUT_DIR, "ft_ensembles.txt")
    if os.path.exists(ens):
        w(f"- Ledger ensembles: {open(ens).read().strip()}")
    w("")

    w("## 5.8 Proof generation and verification\n")
    z = load("zkp.json")
    if z:
        w(f"{z['samples']['generate']:,} generations / {z['samples']['verify']:,} verifications each:\n")
        w("| Scheme | Generate (ms) | Verify (ms) | Size |")
        w("|---|---|---|---|")
        for key, name in (("ballot_proof_k2", "Ballot validity, k = 2 (incl. encryption)"),
                          ("ballot_proof_k5", "Ballot validity, k = 5 (incl. encryption)")):
            b = z[key]
            w(f"| {name} | {b['generate_incl_encryption_ms']['mean']:.1f} ± {b['generate_incl_encryption_ms']['sd']:.1f} | "
              f"{b['verify_ms']['mean']:.2f} ± {b['verify_ms']['sd']:.2f} | {b['proof_bytes']:,} B |")
        s, e = z["schnorr_p256"], z["ecdsa_p256"]
        w(f"| Schnorr PoK, P-256 (credential) | {s['generate_ms']['mean']:.3f} | {s['verify_ms']['mean']:.3f} | {s['proof_bytes']} B |")
        w(f"| ECDSA P-256 device signature | {e['sign_ms']['mean']:.3f} | {e['verify_ms']['mean']:.3f} | {e['signature_bytes']} B |")
        w("\nVerification capacity (k = 5): " + ", ".join(f"{k} process(es) {v:,.0f}/s" for k, v in z["verify_capacity_per_s_k5"].items()))
    w("")

    w("## 5.9 Homomorphic tallying (k = 5)\n")
    t = load("tally.json")
    if t:
        w("| Ballots | Sequential (s) | Parallel (s) | Speed-up | Ballots/s (seq) | Peak memory seq / par (MB) | Correct |")
        w("|---|---|---|---|---|---|---|")
        by = {(r["m"], r["mode"]): r for r in t["rows"]}
        for m in sorted({r["m"] for r in t["rows"]}):
            a, b = by[(m, "seq")], by[(m, "par")]
            w(f"| {m:,} | {a['seconds']:.2f} | {b['seconds']:.2f} | {a['seconds']/b['seconds']:.2f}× | {a['ballots_per_sec']:,.0f} | "
              f"{a['peak_rss_mb']:.0f} / {b['peak_rss_mb']:.0f} | {a['correct'] and b['correct']} |")
        d = t["rows"][0]
        w(f"\nThreshold decryption ({t['threshold']} of {t['trustees']}) of {t['candidates']} totals: "
          f"{d['decrypt_partial_per_trustee_s']*1000:.1f} ms per trustee (in parallel) + {d['decrypt_combine_s']*1000:.2f} ms to combine. "
          f"Key ceremony (one-off): {t['keygen_ceremony_s']:.1f} s. Parallel runs use {t['procs']} processes.")
    if crypto:
        S = crypto["summary"]
        w(f"\nFull election, {crypto['config']['voters']:,} voters, {crypto['config']['candidates']} candidates "
          f"({crypto['config']['repeats']} runs): device encrypt+prove {msd(S['device_ms']['values'])} ms per voter; "
          f"server verifies all proofs in {msd(S['verify_wall_s']['values'], 2)} s; COUNT (tally + threshold decryption) "
          f"{msd(S['count_sec']['values'], 3)} s; result matches ground truth in every run: {S['all_correct']}.")
    w("")

    w("## 5.10 Adversarial results\n")
    ad = load("adversarial.json")
    if ad:
        rp = ad["replay"]
        w(f"- Replay: {rp['rejected']}/{rp['attempts']} rejected; rejection latency mean {rp['mean_ms']:.2f} ms, p99 {rp['p99_ms']:.2f} ms (HTTP round trip)")
        for k, v in ad["forgeries"].items():
            w(f"- {k.replace('_', ' ')}: {v['rejected']}/{v['sent']} rejected, mean {v['mean_ms']:.2f} ms")
        w(f"- Victims' real tickets still usable afterwards: {ad['victims_could_still_vote']}/100")
        w(f"- 50 simultaneous submissions of one ticket: {ad['double_vote']['accepted']} accepted")
    if crypto:
        S = crypto["summary"]
        w(f"- Offline bisection on 5,000-vote bundles, 1/10/100/1,000 tampered: "
          f"{msd(S['locate_1_ms']['values'],3)} / {msd(S['locate_10_ms']['values'],3)} / {msd(S['locate_100_ms']['values'],3)} / "
          f"{msd(S['locate_1000_ms']['values'],3)} ms; node comparisons {S['bisection_comparisons']}")
    mx = load("load_mix.json")
    if mx:
        base = mx["rows"][0]["legit"]["throughput_per_s"]
        w(f"\nAdversarial load (legitimate votes offered at {mx['rate']:.0f}/s):\n")
        w("| Invalid share | Legit accepted/s | Drop vs no attack | Legit p50 / p99 (ms) | Invalid rejected |")
        w("|---|---|---|---|---|")
        for r in mx["rows"]:
            g = r["legit"]
            inv = r.get("invalid", {})
            sent = sum(v["sent"] for v in inv.values())
            rej = sum(v["rejected"] for v in inv.values())
            drop = (1 - g["throughput_per_s"] / base) * 100 if base else 0
            w(f"| {r['invalid_fraction']:.0%} | {g['throughput_per_s']:.1f} | {drop:.1f}% | {ms(g['p50_ms'])} / {ms(g['p99_ms'])} | "
              f"{f'{rej}/{sent}' if sent else '—'} |")
    w("")

    w("## 5.12 Sustained stress on the replicated ledger\n")
    for name in ("ledger_stress.json", "ledger_stress_sustained.json"):
        st = load(name)
        if st:
            w("| Payload | Bytes | Seconds | Acked | Failed | Mean/s | Min/s | MB/s | Ack p50 (ms) | Ack p99 (ms) |")
            w("|---|---|---|---|---|---|---|---|---|---|")
            for r in st:
                w(f"| {r['payload']} | {r['payload_bytes']:,} | {r['seconds']:.0f} | {r['acked']:,} | {r['failed']} | "
                  f"{r['throughput_mean']:,.0f} | {r['throughput_min']:,} | {r['mb_per_s']:.1f} | {ms(r['ack_p50_ms'])} | {ms(r['ack_p99_ms'])} |")
            w("")
    ds = os.path.join(OUT_DIR, "stress_docker_stats.csv")
    if os.path.exists(ds):
        rows = list(csv.DictReader(open(ds)))
        cpu = [float(r["cpu_total_pct"]) for r in rows if r.get("cpu_total_pct")]
        if cpu:
            w(f"Host CPU during the sustained run (sum over containers, % of one core): mean {statistics.mean(cpu):.0f}%, "
              f"peak {max(cpu):.0f}%.")
    text = "\n".join(L) + "\n"
    with open(os.path.join(OUT_DIR, "paper_results.md"), "w") as f:
        f.write(text)
    print(text)


if __name__ == "__main__":
    main()
