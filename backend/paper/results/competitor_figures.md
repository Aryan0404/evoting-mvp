# Competitor / state-of-the-art figures — verification & attribution

For a Q1 paper every comparison number must carry a correct attribution. This
file records, for each figure we cite, **what the number is, where it actually
comes from, and how confident we are.** Cite each one exactly as written in the
"Cite as" column — do not present a reported-by-X figure as system X's own claim.

## A. Verified against the original paper (safe to cite directly)

### Abuidris et al. (2021) — ETRI Journal — VERIFIED ✔
- Title: "Secure large-scale E-voting system based on blockchain contract using a
  hybrid consensus model combined with sharding", ETRI Journal, 2021;43(2):357–370.
- Authors: Yousif Abuidris, Rajesh Kumar, Ting Yang, Joseph Onginjo.
- Setup: network scaled 200 → 1,000 nodes; shard size = 10; throughput measured
  over ten blocks (Section 5.2, Figure 7, repeated in the Conclusion).
- Figures (stated in the text; Figure 7 values are not given numerically):
  - PSC-Bchain with sharding (their proposed): **"exceeded 60 Tps"** at 1,000 nodes.
  - Proof of Work (PoW): **~5 Tps**.
  - Proof of Stake (PoS): **~25 Tps**.
- Cite as: *"Abuidris et al. report their sharded hybrid-consensus scheme exceeds
  60 TPS at 1,000 nodes, versus ~5 TPS (PoW) and ~25 TPS (PoS) [ref]."*
- Note: this is the strongest throughput in the blockchain-voting literature we
  surveyed, so it is the right "best-case blockchain" anchor for our comparison.

## B. Reproduced from the reference paper's own comparison table (attribute to it)

### Razaque et al. (2026) — Blockchain: Research and Applications 7 (2026) 100348 — our baseline
Their Table 4 reports these figures for prior voting systems. **These are
Razaque et al.'s measurements/compilation, NOT each vendor's own published
claim**, and must be attributed to Razaque Table 4.

What each Table 4 column means, per the paper's own text:
- "Number of casting votes vs. time" = votes cast **within 15 minutes** (Sec. 4.5.1).
- "Time vs. number of vote count (Max: 5000)" = time to **count up to 5,000 votes**,
  defined as authenticate + record on blockchain + tally (Sec. 4.5.6).
- "Audited/verified votes" = share verified **after 10 hours of voting** (Sec. 4.5.5).
- Gas (Sec. 4.5.7 / Fig. 11) is in **GWei** for the **vote-counting operation**.

| System (Razaque Table 4) | Votes cast in 15 min | ≈ rate (votes ÷ 900 s, our arithmetic) | Count time (≤5,000) | Audited (10 h) | Accuracy | Gas, vote counting (GWei) |
|---|---|---|---|---|---|---|
| Follow My Vote | 1998 | 2.2/s | 8.62 s | 80% | 93.12% | 22,819 |
| Horizon State  | 1998 | 2.2/s | 11 s   | 90% | 85.09% | 24,108 |
| Agora          | 1882 | 2.1/s | 9.81 s | 85% | 88.09% | 23,109 |
| Votem          | 2084 | 2.3/s | 9.81 s | 76% | 92.01% | — |
| BCVS           | 2292 | 2.5/s | 7.42 s | 95% | 95.02% | 20,265 |

- Cite as: *"as reported in Razaque et al., Table 4 [ref]."* Say the per-second
  rate is derived by dividing by 900 s.
- Razaque's text and Table 4 disagree in places (text: BCVS 2,298 votes and
  7.32 s, Agora 1,778 votes, Votem 9.2 s). **Use the Table 4 values** throughout,
  and if a reviewer asks, say so.
- Our like-for-like comparisons (Apple M2, see benchmark_run.json):
  - Count 5,000 votes: ours 0.33 s (tally 0.320 s + decrypt 0.011 s, one core)
    vs BCVS 7.42 s → ≈22×. Caveat: their count time also includes per-vote
    authentication and on-chain recording, which our design does at ingest.
  - Casting rate: ours ≈250 votes/s end-to-end on one laptop (limited by the test
    environment) vs BCVS ≈2.5/s → ≈100×.
  - Do NOT use the election-simulation "count" (0.055 s) as the headline: there the
    per-ballot additions happen inside the parallel workers, so 0.055 s covers only
    merging 8 partial tallies + decrypting. The sequential 0.33 s is the honest figure.

## C. Read but report no throughput (safe to state as "not benchmarked")

- Emami et al. — reviewed; reports no throughput/TPS figure. Cite as related work only.
- Venugopalan et al. (BBB-Voting / similar) — reviewed; no comparable TPS figure.
  Cite as related work only.

## D. Paywalled — no numbers available (do NOT cite specific figures)

- Tanwar et al. — full text paywalled; no throughput figure obtained. List as related work only.
- Adeniyi et al. — paywalled; no figure obtained. Related work only.
- Pereira et al. — paywalled; no figure obtained. Related work only.

---
### Honest framing rule for the paper
Headline claims, each with the two numbers being divided and the machine:
- ≈22× faster counting: 0.33 s (ours, M2, one core) vs 7.42 s (BCVS, Table 4).
- ≈100× casting rate: ≈250 votes/s (ours, end-to-end, one laptop) vs ≈2.5 votes/s (BCVS).
- ≈4× the best verified blockchain throughput: ≈250 votes/s vs >60 TPS (Abuidris, 1,000 nodes).
- ≈760× is ONLY the ledger-component ceiling (≈46,000 writes/s, Pulsar, live stack)
  vs 60 TPS. Always call it a ceiling/headroom figure, never end-to-end throughput.
