#!/usr/bin/env bash
# Section 5.7 — fault tolerance on the replicated ledger (storage node, replica
# and quorum loss). See run_paper_experiments.sh for all options.
cd "$(dirname "$0")" && exec ./run_paper_experiments.sh fault summary
