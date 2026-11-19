# Measured results for the manuscript (Section 5)

Every number below was produced by `./run_paper_experiments.sh`; nothing is simulated or extrapolated.

## 5.1 Experimental setup

- Host: Apple M2, 16 GB RAM; Docker allocation: 8 CPUs, 11.8 GB
- Containers: Linux 7.0.14-linuxkit, Python 3.11.18, 8 CPUs visible, 11.8 GB
- Crypto: phe 1.5.0 (gmpy2 2.3.2), ecdsa 0.19.2, Paillier 2048-bit, threshold 3-of-5
- date_utc: 2026-11-18T14:33:36Z
- git_commit: 0969324
- docker: 29.9.3; compose: 5.7.0
- Ledger: Apache Pulsar 3.1.0 broker + 4 BookKeeper storage nodes, ensemble 3 / write quorum 2 / ack quorum 2

## 5.3 Throughput and end-to-end latency (Locust, 200 users, ramp 20/s, 120 s)

| Requests | Failures | Throughput (votes/s) | p50 (ms) | p95 (ms) | p99 (ms) | Max (ms) |
|---|---|---|---|---|---|---|
| 12,596 | 0 | 104.9 | 200 | 1000 | 1900 | 2886 |

Thresholds stated in the manuscript: p95_lt_300ms NOT met, p99_lt_600ms NOT met, throughput_gt_100 met, no_failures met

Ceiling (closed loop, 20,000 votes, concurrency 100, 3 run(s)): 137.6 ± 6.3 votes/s; p50 380.2 ± 54.0 ms, p95 2177.6 ± 95.5 ms, p99 2728.2 ± 151.8 ms; accepted 59,915/60,000.

Latency at a steady 100 votes/s (open loop, 60 s, 3 run(s)): p50 50.5 ± 1.5 ms, p95 105.6 ± 17.4 ms, p99 162.5 ± 48.8 ms.

## 5.4 Merkle bundle construction and voter verification

- Root over a 10,000-vote bundle: 6.51 ± 0.44 ms (depth 14)
- Voter receipt check (inclusion proof, 14 hashes): 0.0109 ± 0.0006 ms

## 5.5 Tamper detection, localisation, liveness (live system)

Insider overwrites stored ballots in the primary ledger (23,615 ballots, bundles of 10,000):

| Tampered | Detected | Detection latency (s) | Min–max (s) | Localised exactly | Lockdown enforced | Node comparisons |
|---|---|---|---|---|---|---|
| 1 | 5/5 | 3.86 ± 0.08 | 3.74–3.96 | 5/5 | 5/5 | 29 |
| 10 | 5/5 | 3.86 ± 0.06 | 3.78–3.91 | 5/5 | 5/5 | 229 |
| 100 | 5/5 | 3.83 ± 0.10 | 3.69–3.96 | 5/5 | 5/5 | 1595 |
| 1000 | 5/5 | 3.48 ± 0.06 | 3.39–3.54 | 5/5 | 5/5 | 9603 |

Liveness (cycle 5 s, τ = 15 s): replica paused 30 s → reported STALE after 17.5 s; LIVE again 0.3 s after resuming; DIVERGED verdicts: 0.

## 5.6 Scalability under increasing load (real, open loop)

| Offered (votes/s) | Achieved (votes/s) | Accepted | Shed by admission control (503) | Other failures | p50 (ms) | p95 (ms) | p99 (ms) |
|---|---|---|---|---|---|---|---|
| 50 | 49.9 | 1,500 | 0 | 0 | 36.3 | 44.1 | 52.2 |
| 100 | 99.8 | 3,000 | 0 | 0 | 58.2 | 187.1 | 389.6 |
| 150 | 146.6 | 4,500 | 0 | 0 | 958.0 | 1810.5 | 2095.1 |
| 200 | 145.0 | 4,596 | 1,404 | 0 | 3190.0 | 5543.4 | 6290.5 |
| 250 | 143.9 | 4,577 | 2,923 | 0 | 3326.1 | 14038.4 | 16150.5 |
| 300 | 146.4 | 5,643 | 3,357 | 0 | 5482.5 | 21850.6 | 24291.3 |
| 400 | 109.3 | 6,613 | 1,998 | 3,389 | 12261.3 | 24971.1 | 29084.0 |

Latency percentiles are over accepted votes. A shed request is refused before its ticket is touched, so the voter's device can simply retry.

Horizontal scaling of stateless vote collectors (API worker processes, closed loop 5,000 votes):

| Workers | Throughput (votes/s) | p50 (ms) | p99 (ms) |
|---|---|---|---|
| 1 | 49.4 | 2023.7 | 2575.4 |
| 2 | 86.6 | 720.6 | 2963.3 |
| 4 | 104.5 | 1128.9 | 1845.7 |
| 8 | 150.4 | 358.9 | 2811.3 |

## 5.7 Fault tolerance under node failure (4 bookies, E=3/Qw=2/Qa=2)

- t = -11.6 s: run_started
- t = 18.4 s: kill_bookie evoting_bookie2 (SIGKILL; stays down)
- t = 49.2 s: kill_replica (SIGKILL)
- t = 64.5 s: restart_replica
- t = 97.1 s: kill_quorum evoting_bookie3 (SIGKILL; storage now below the ensemble size)
- t = 113.1 s: restore_quorum evoting_bookie3
- t = 113.5 s: quorum_registered evoting_bookie3

- Votes: 15,000/15,000 accepted; failed after retries 0; lost 0; duplicates 0
- Read back from the ledger with the storage node down: 15,000; replica identical: True; Merkle roots equal: True
- Latency p50/p99 (ms): before [50.4, 161.9], first 10 s after node loss [74.6, 2784.2], rest [761.3, 67636.6]
- Replica down 15.3 s, back in sync 2.5 s after restart; integrity alerts during faults (false positives): 0; liveness rounds {'LIVE': 30, 'STALE': 0, 'DIVERGED': 0, 'PENDING': 0, 'UNKNOWN': 0}
- Quorum loss for 16.0 s: 1601 votes cast during the outage, 1601 eventually accepted, 0 accepted while the quorum was lost, first acceptance 3.17 s after restore, max latency 75.05 s
- Ledger ensembles: ledger 2: ensembles={0=[bookie3:3181, bookie4:3181, bookie1:3181]}
ledger 13: ensembles={0=[bookie4:3181, bookie1:3181, bookie3:3181]}
ledger 18: ensembles={0=[bookie1:3181, bookie3:3181, bookie4:3181]}

## 5.8 Proof generation and verification

1,000 generations / 2,000 verifications each:

| Scheme | Generate (ms) | Verify (ms) | Size |
|---|---|---|---|
| Ballot validity, k = 2 (incl. encryption) | 71.2 ± 0.3 | 18.57 ± 0.13 | 3,902 B |
| Ballot validity, k = 5 (incl. encryption) | 162.7 ± 0.7 | 29.05 ± 0.18 | 8,605 B |
| Schnorr PoK, P-256 (credential) | 0.283 | 1.199 | 65 B |
| ECDSA P-256 device signature | 0.038 | 0.096 | 72 B |

Verification capacity (k = 5): 1 process(es) 34/s, 2 process(es) 68/s, 4 process(es) 107/s, 8 process(es) 127/s

## 5.9 Homomorphic tallying (k = 5)

| Ballots | Sequential (s) | Parallel (s) | Speed-up | Ballots/s (seq) | Peak memory seq / par (MB) | Correct |
|---|---|---|---|---|---|---|
| 100,000 | 3.12 | 0.62 | 5.00× | 32,073 | 35 / 311 | True |
| 1,000,000 | 38.54 | 8.12 | 4.74× | 25,947 | 35 / 310 | True |
| 10,000,000 | 307.70 | 73.61 | 4.18× | 32,499 | 35 / 309 | True |

Threshold decryption (3 of 5) of 5 totals: 97.3 ms per trustee (in parallel) + 1.27 ms to combine. Key ceremony (one-off): 22.8 s. Parallel runs use 8 processes.

Full election, 5,000 voters, 4 candidates (5 runs): device encrypt+prove 323.4 ± 35.5 ms per voter; server verifies all proofs in 39.08 ± 4.11 s; COUNT (tally + threshold decryption) 0.213 ± 0.002 s; result matches ground truth in every run: True.

## 5.10 Adversarial results

- Replay: 1000/1000 rejected; rejection latency mean 0.95 ms, p99 1.35 ms (HTTP round trip)
- unknown ticket: 100/100 rejected, mean 0.94 ms
- proof for other ticket: 100/100 rejected, mean 1.16 ms
- tampered proof: 100/100 rejected, mean 4.03 ms
- wrong device key: 100/100 rejected, mean 20.33 ms
- stale timestamp: 100/100 rejected, mean 0.81 ms
- Victims' real tickets still usable afterwards: 100/100
- 50 simultaneous submissions of one ticket: 1 accepted
- Offline bisection on 5,000-vote bundles, 1/10/100/1,000 tampered: 0.019 ± 0.003 / 0.040 ± 0.004 / 0.186 ± 0.019 / 0.824 ± 0.063 ms; node comparisons {'1': 27, '10': 183, '100': 1105, '1000': 5613}

Adversarial load (legitimate votes offered at 100/s):

| Invalid share | Legit accepted/s | Drop vs no attack | Legit p50 / p99 (ms) | Invalid rejected |
|---|---|---|---|---|
| 0% | 99.8 | 0.0% | 55.4 / 318.9 | — |
| 10% | 99.2 | 0.6% | 65.2 / 838.6 | 333/333 |
| 50% | 99.4 | 0.4% | 347.8 / 1931.5 | 3000/3000 |

## 5.12 Sustained stress on the replicated ledger

| Payload | Bytes | Seconds | Acked | Failed | Mean/s | Min/s | MB/s | Ack p50 (ms) | Ack p99 (ms) |
|---|---|---|---|---|---|---|---|---|---|
| tiny | 400 | 20 | 749,672 | 0 | 37,241 | 29,339 | 14.9 | 192.1 | 548.2 |
| k2 | 10,300 | 20 | 153,660 | 0 | 7,069 | 792 | 75.4 | 746.0 | 2107.2 |
| k5 | 23,013 | 20 | 71,459 | 0 | 2,861 | 465 | 68.3 | 2011.4 | 4275.6 |

| Payload | Bytes | Seconds | Acked | Failed | Mean/s | Min/s | MB/s | Ack p50 (ms) | Ack p99 (ms) |
|---|---|---|---|---|---|---|---|---|---|
| k2 | 10,297 | 60 | 354,189 | 0 | 5,574 | 153 | 54.7 | 3316.2 | 6698.3 |

Host CPU during the sustained run (sum over containers, % of one core): mean 309%, peak 698%.
