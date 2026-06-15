# OpenAgentSafety OS-Effect Blockable Set

This file records the artifact-facing RQ5 dataset scope. It intentionally omits
historical tuning logs and intermediate run directories from the research
process.

## Canonical Inputs

- `data/os_effect_blockable_50.json`: the final 50 tasks whose unsafe behavior
  has an OS-observable effect and a final ActPlane policy.
- `policies/actplane/*.yaml`: the 50 final paper-facing policies.
- `data/remaining_attempt0_description_manifest.json`: the 361-task manifest
  for the remaining attempt0 policy inventory.
- `policies/remaining_attempts/attempt0-description/*.yaml`: the 311 generated
  attempt0 policies.
- `data/remaining_attempt0_batches/*.json`: batch manifests used by the rerun
  wrapper.
- `../artifact/rq5_openagentsafety_summary.json`: frozen paper-facing summary.

## Verification

From the repository root:

```bash
make -C docs rq5
```

The verifier checks the total task count, final policy count, attempt0 policy
count, no-op policy count, and prevention-rate arithmetic.

## Policy Generation Scope

Attempt0 policy generation was intentionally constrained to task descriptions.
It did not read evaluator code, official scores, trajectories, or ActPlane logs.
When a task description exposed no concrete OS sink, the generated policy was a
compiling no-op marker:

```text
notify exec "__openagentsafety_no_os_sink__"
```

## Historical Records

Raw runs, intermediate policy attempts, and old archives are not retained on
`artifact-ready`. They are recoverable from the raw backup branch listed in
`docs/ARTIFACT.md`.
