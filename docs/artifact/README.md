# Artifact Verification Data

This directory contains reviewer-facing verification inputs used by
`docs/Makefile`.

## Files

- `verify_results.py`: recomputes or checks the paper-facing RQ1-RQ5 numbers.
- `rq2-qwen-primary/selected_runner_results.txt`: selected primary Qwen result
  list for RQ2.
- `rq2-qwen-primary/results/`: selected raw runner outputs and matching
  llama.cpp judge JSON files for the primary Qwen RQ2 table.
- `rq4_octobench_ledger.json`: selected OctoBench task/policy ledger.
- `rq4_octobench_summary.json`: frozen OctoBench RQ4 summary.
- `rq5_openagentsafety_ledger.json`: OpenAgentSafety task/policy ledger.
- `rq5_openagentsafety_summary.json`: frozen OpenAgentSafety RQ5 summary.

## Usage

From the repository root:

```bash
make -C docs artifact-check
```

The default checks do not regenerate policies or run models. They verify the
tracked artifact inputs and fail if a required file is missing or a reported
number drifts.

RQ4 and RQ5 ledgers are task/policy ledgers, not complete raw run logs. Their
per-task reward/outcome fields are deliberately marked unavailable because the
artifact branch verifies those two RQs from frozen aggregate summaries plus
manifest and policy inventory checks.
