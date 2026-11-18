# Superseded: earlier simulation harness

This folder contains the project's **earlier, simulation-based test harness**
(a mock BookKeeper cluster with an extrapolation factor, a mock 500K TPS stress
test, and similar). **None of its outputs are reported in the manuscript.**

All results in the paper are real measurements produced by
`./run_paper_experiments.sh` at the repository root, using the code in
`backend/tools/` against the running system. Their outputs are written to
`backend/paper/results/docker/`, summarised in `paper_results.md`.

This folder is kept only for the project's history and can be deleted.
