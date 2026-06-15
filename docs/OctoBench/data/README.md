# OctoBench Data

This directory contains the canonical OctoBench input set used by ActPlane RQ4
on the `artifact-ready` branch.

## Files

- `selected_cases_21.ids`: selected task IDs, one per line.
- `selected_cases_21.jsonl`: full selected task records.
- `policy_manifest.jsonl`: selected case to policy-file mapping, one row per
  selected task.

The corresponding policies live under `../policies/`. The ActPlane
paper-facing policies are in `../policies/actplane-feedback/`.

## Verification

From the repository root:

```bash
make -C docs rq4
```

The verifier checks that the selected set has 21 tasks, that
`policy_manifest.jsonl` has the same 21 task IDs, and that the selected
ActPlane policies contain 61 DSL rules.

## Historical Data

Earlier 3-case, 20-case, 30-case, tuned, smoke, and failed runs were removed
from `artifact-ready` to avoid mixing exploratory data with the reviewer-facing
artifact. They remain recoverable from the raw backup branch listed in
`docs/ARTIFACT.md`.
