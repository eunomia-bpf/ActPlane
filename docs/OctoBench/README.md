# OctoBench Artifact Workspace

This directory contains the paper-facing OctoBench assets for ActPlane RQ4.
It keeps only the selected task set, policies, runner scripts, and summary
metadata needed to verify or rerun the reported result.

## Provenance

- Official harness: `MiniMax-AI/mini-vela`
- ActPlane fork: `https://github.com/eunomia-bpf/mini-vela`
- Fork branch: `actplane`
- Pinned submodule path: `docs/OctoBench/mini-vela`

The submodule is required only for full reruns. The default artifact checks do
not require it.

## Canonical Files

- `data/selected_cases_21.ids`: selected task IDs.
- `data/selected_cases_21.jsonl`: full selected task records.
- `data/policy_manifest.jsonl`: selected case to policy mapping.
- `policies/actplane-feedback/<case_id>.yaml`: ActPlane policies used for the
  paper-facing condition.
- `policies/tool-regex/<case_id>.json`: tool-hook baseline policies.
- `configs/litellm_llama_cpp.yaml`: local LiteLLM routing to llama.cpp.
- `run_cases.py`: runner for `baseline`, `tool-regex`, `actplane`, and
  `actplane-feedback`.
- `evaluate_with_llama.py`: judge wrapper.
- `extract_actplane_metrics.py`: OS-evidence extraction helper.
- `../artifact/rq4_octobench_ledger.json`: selected task/policy ledger.
- `../artifact/rq4_octobench_summary.json`: frozen paper-facing summary.

Generated run outputs belong under ignored `results/` and are not committed on
`artifact-ready`.

## Verify

From the repository root:

```bash
make -C docs rq4
```

This verifies:

- the selected task count is 21,
- `data/selected_cases_21.jsonl` has 21 records,
- `data/policy_manifest.jsonl` matches the selected task IDs,
- every selected task has an ActPlane feedback policy,
- the selected policies contain 61 DSL rules, and
- `../artifact/rq4_octobench_ledger.json` matches the selected policies,
- the frozen summary reports the paper-facing rewards.

## Rerun

Full reruns require the OctoBench submodule, Docker/runtime support from the
upstream harness, ActPlane's release binary, and local model serving.
Set `LLAMA_SERVER_BIN` and `LLAMA_MODEL`, or put `llama-server` on `PATH` and
use the default model path documented in `docs/eval_scripts/README.md`.

```bash
git submodule update --init --recursive docs/OctoBench/mini-vela
cargo build --release --manifest-path collector/Cargo.toml
cd docs/OctoBench
python3 run_cases.py --condition baseline --managed-llama
python3 run_cases.py --condition tool-regex --managed-llama
python3 run_cases.py --condition actplane-feedback --managed-llama
```

The runner defaults to `data/selected_cases_21.jsonl`. Use `--dataset` only for
deliberate sensitivity experiments.

## Scope

RQ4 evaluates whether ActPlane's OS-level feedback can improve compliance on
OctoBench tasks with policy-relevant OS effects. The 21-task subset is the
paper-facing set. Historical 3-case, 20-case, 30-case, smoke, and tuning outputs
are not retained here. They remain recoverable from the raw backup branch listed
in `docs/ARTIFACT.md`.
