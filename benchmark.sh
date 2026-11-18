#!/usr/bin/env bash
# Performance and cryptography experiments (everything except the integrity and
# fault-tolerance runs). See run_paper_experiments.sh for all options.
cd "$(dirname "$0")" && exec ./run_paper_experiments.sh smoke crypto zkp tally load locust adversarial stress summary
