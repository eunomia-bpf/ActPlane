# OpenAgentSafety Artifact Workspace

This directory contains the paper-facing OpenAgentSafety assets for ActPlane
RQ5. It keeps the task manifests, selected policies, runner scripts, and frozen
summary needed to verify the reported numbers. Historical policy attempts and
raw run logs are not committed on `artifact-ready`.

## Provenance

- Official benchmark: `Open-Agent-Safety/OpenAgentSafety`
- Local official checkout path: `docs/OpenAgentSafety/OpenAgentSafety/`
- Expected submodule commit: `af1e44cf93efbaafbe69a547feb3d385133a5190`
- Runtime image family: `ghcr.io/theagentcompany/task-base-image:1.0.0`

The submodule is required only for full reruns. The default artifact checks do
not require it.

## Canonical Files

- `data/os_effect_blockable_50.json`: final 50 OS-effect blockable tasks.
- `data/remaining_attempt0_description_manifest.json`: manifest for the 311
  generated attempt0 policies plus no-op inventory.
- `data/remaining_attempt0_batches/*.json`: batch manifests used for attempt0
  policy generation and rerun grouping.
- `policies/actplane/*.yaml`: final paper-facing ActPlane policies for the 50
  blockable tasks.
- `policies/remaining_attempts/attempt0-description/*.yaml`: generated
  attempt0 policies for the remaining tasks.
- `configs/openhands_local_llama_config.toml`: OpenHands config for local
  llama.cpp serving.
- `patches/local-llama-openhands.patch`: local patch for OpenHands/FakeUser
  routing through llama.cpp.
- `scripts/run_selected.py`: small runner for baseline and ActPlane conditions.
- `../artifact/rq5_openagentsafety_ledger.json`: task/policy ledger for all
  361 tasks.
- `../artifact/rq5_openagentsafety_summary.json`: frozen paper-facing summary.

Generated run outputs belong under ignored `results/` and are not committed on
`artifact-ready`.

## Verify

From the repository root:

```bash
make -C docs rq5
```

This verifies:

- the total task count is 361,
- the outcome counts sum correctly,
- the final blockable manifest has 50 excluded final-policy tasks,
- the no-op policy count is 58,
- the task/policy ledger has 361 unique tasks split into 50 final policies and
  311 attempt0 description policies,
- `policies/actplane/` contains 50 final policies,
- `policies/remaining_attempts/attempt0-description/` contains 311 generated
  attempt0 policies, and
- the reported prevention rate is recomputed from the frozen counts.

## Rerun

Full reruns require Docker, the official OpenAgentSafety submodule, OpenHands
dependencies, ActPlane's release binary, and local model serving.
Set `LLAMA_SERVER_BIN` and `LLAMA_MODEL`, or put `llama-server` on `PATH` and
use the default model path documented in `docs/eval_scripts/README.md`.

```bash
git submodule update --init --recursive docs/OpenAgentSafety/OpenAgentSafety
cargo build --release -p actplane
cd docs/OpenAgentSafety/OpenAgentSafety
poetry install
```

Start official services when running service-backed tasks:

```bash
cd docs/OpenAgentSafety/OpenAgentSafety
bash servers/setup.sh
```

Run a smoke case through the artifact wrapper:

```bash
cd docs/OpenAgentSafety
python3 scripts/run_selected.py \
  --condition actplane \
  --case safety-api-in-codebase \
  --managed-llama \
  --skip-services
```

The runner writes generated outputs under `results/<condition>/<run-id>/`.

## Scope

RQ5 evaluates whether ActPlane can prevent OS-observable unsafe actions in the
OpenAgentSafety task set. The artifact-ready branch preserves the policy
inventory and paper-facing summary counts, but not complete raw run logs. The
raw backup branch in `docs/ARTIFACT.md` remains the forensic fallback for
historical research records.
