# ActPlane Artifact Layout

This document records how ActPlane keeps product code, paper artifacts, and raw
experiment history separate. It is intentionally an index, not an experiment
result directory.

## Branch Roles

ActPlane uses three long-lived artifact refs:

| Ref | Purpose | Contents |
| --- | --- | --- |
| `master` | Open-source product branch | ActPlane source, product docs, tests, this artifact index, and minimal benchmark scripts under `docs/`. It should not contain raw experiment outputs, tuning logs, Docker workspaces, or paper-only datasets. |
| `artifact-ready` | Reviewer-facing paper artifact | Reproducible scripts, frozen inputs, selected policies, canonical summaries, and the smallest result files needed to verify paper claims. This branch should exclude scratch runs and raw logs unless the artifact README explicitly marks them as required. |
| `backup/2026-06-14-master` | Raw historical backup | Full historical docs, experiments, intermediate runs, raw data, and local research records as they existed before cleanup. Use this branch for forensic recovery, not for paper claims. |

The current raw backup is already pushed:

```text
ActPlane remote: https://github.com/eunomia-bpf/ActPlane
Raw backup ref: refs/heads/backup/2026-06-14-master
Raw backup commit: cceaee6be878eeff4b42caf9a069d535699ecf69
```

OpenAgentSafety's nested checkout was backed up separately:

```text
OpenAgentSafety remote: https://github.com/eunomia-bpf/OpenAgentSafety.git
Raw backup ref: refs/heads/backup/2026-06-14-actplane-submodule
Raw backup commit: 8cb4131211435a933d44942479e79418972f8f9b
```

## Restore Raw History

Inspect the ActPlane raw branch without changing the current checkout:

```bash
git fetch origin backup/2026-06-14-master
git show origin/backup/2026-06-14-master --stat
```

Restore the nested OpenAgentSafety checkout if needed:

```bash
rm -rf docs/OpenAgentSafety/OpenAgentSafety
git clone --branch backup/2026-06-14-actplane-submodule \
  https://github.com/eunomia-bpf/OpenAgentSafety.git \
  docs/OpenAgentSafety/OpenAgentSafety
git -C docs/OpenAgentSafety/OpenAgentSafety rev-parse HEAD
```

Expected nested checkout commit:

```text
8cb4131211435a933d44942479e79418972f8f9b
```

## Main Branch Policy

The `master` branch should keep only assets that help users build, test, or
understand ActPlane as a policy engine.

Keep in `master`:

- ActPlane source code and tests.
- Product documentation.
- Paper draft and paper-writing assets under `docs/papers/`.
- Working research notes under `docs/tmp/`.
- `docs/ARTIFACT.md`.
- Minimal benchmark scripts under `docs/`, currently `docs/rq2-performance/`.
- Benchmark READMEs and `.gitignore` files that explain how to regenerate
  results.

Keep out of `master`:

- `docs/eval_runs/`
- `docs/corpus/`
- `docs/corpus-raw-full/`
- `docs/corpus-test/`
- `docs/corpus-evaluated/`
- `docs/OctoBench/`
- `docs/OpenAgentSafety/`
- Raw logs, Docker mounts, generated workspaces, model server logs, and
  historical tuning runs outside the retained paper draft and `docs/tmp/`
  working-note areas.

`docs/tmp/` is retained only on the product branch as a working note area. It is
not part of the reviewer-facing `artifact-ready` branch.

## Benchmark Scripts Kept Under Docs

Performance benchmark scripts should stay under `docs/`, not at repository root.
The current planned product-facing path is:

```text
docs/rq2-performance/
```

This directory may keep:

- `README.md`
- `run_perf.py`
- `run_macro.py`
- `plot_rq2.py`
- `syscall_microbench.c`
- `agent_trace_replay.py`
- `linux_build_once.py`
- `.gitignore`

It should not keep generated results in `master`. Result directories belong in
`artifact-ready` if they are canonical and small, or in the raw backup branch if
they are historical, large, or not paper-facing.

## Artifact-Ready Policy

The `artifact-ready` branch should be enough for an artifact evaluator to
understand and rerun the paper's main claims without pulling the full raw
history.

Keep in `artifact-ready`:

- A top-level artifact README under `docs/`.
- Frozen input manifests and selected policies.
- Minimal scripts for each reported RQ.
- Canonical result summaries and metadata.
- Exact commands, commit IDs, model/backend settings, kernel information, and
  environment assumptions.

The artifact entrypoint is `docs/Makefile`:

```bash
make -C docs rq1
make -C docs rq2
make -C docs rq3
make -C docs rq4
make -C docs rq5
make -C docs artifact-check
```

The default `rq*` targets verify frozen summaries, manifests, selected raw
results, and policies. They do not regenerate policies and they do not require
submodules, Docker, or local model weights. Rerun targets are separate and may
require local model weights, Docker, benchmark images, and a kernel
configuration that supports the ActPlane eBPF hooks.

Do not keep in `artifact-ready`:

- `one_trace_tuning` directories.
- smoke/debug runs.
- old failed runs.
- raw model server logs.
- Docker runtime workspaces or mount directories.
- result directories that are not cited or explicitly marked as historical.

## Canonical Artifact Inputs

These are the paper-facing inputs and summaries preserved on `artifact-ready`:

| Claim area | Candidate path | Notes |
| --- | --- | --- |
| RQ1 expressiveness | `docs/eval_runs/rq1-expressiveness/full-607-subagents/` | Full 607-directive compile result. |
| RQ2 compliance, primary Qwen setting | `docs/artifact/rq2-qwen-primary/selected_runner_results.txt` and `docs/artifact/rq2-qwen-primary/results/` | Primary 190-trace table across five systems, recomputed from selected raw result/judge files. |
| RQ2 compliance, DeepSeek replication | `docs/eval_runs/full/deepseek_rq1_20260607T193612Z_v4_pro/` | 190 trace-conditioned replication across five systems. |
| RQ2 one-shot FN repair | `docs/eval_runs/policy_revision/20260609T-rq1-fn-llamacpp-grouped/` | Reruns the 28 ActPlane FN traces and records a 26/28 strict lower-bound recovery. |
| Performance microbench | `docs/rq2-performance/results/rq2-micro-2026-06-02T-osdi/` | Small aggregate and metadata files. Metadata records a dirty git tree, so rerun on a clean commit if this becomes the final paper artifact. |
| Performance macrobench | `docs/rq2-performance/results/rq2-macro-2026-06-02T-osdi-v2/` | Small aggregate and metadata files. Metadata records a dirty git tree, so rerun on a clean commit if this becomes the final paper artifact. |
| RQ4 OctoBench | `docs/OctoBench/data/selected_cases_21.*`, `docs/OctoBench/data/policy_manifest.jsonl`, `docs/OctoBench/policies/actplane-feedback/`, `docs/artifact/rq4_octobench_ledger.json`, `docs/artifact/rq4_octobench_summary.json` | Verifies the selected 21 tasks, 61 DSL rules, task/policy ledger, and paper-facing reward summary. Full generated run directories are not tracked. |
| RQ5 OpenAgentSafety | `docs/OpenAgentSafety/data/os_effect_blockable_50.json`, `docs/OpenAgentSafety/data/remaining_attempt0_description_manifest.json`, `docs/OpenAgentSafety/policies/`, `docs/artifact/rq5_openagentsafety_ledger.json`, `docs/artifact/rq5_openagentsafety_summary.json` | Verifies task/policy ledger, policy inventory, and paper-facing summary counts. Full generated run logs are not tracked. |

Any other result directory should be treated as historical until explicitly
promoted in this file or in the benchmark-local README.

## Known Artifact Limits

The RQ3 performance result directories preserve their original 2026-06-02
metadata. Those metadata files record the pre-cleanup script path
`docs/corpus-test/perf/` and a dirty git status from the experiment host. The
current rerun entrypoint is `make -C docs rq3-rerun`, which uses
`docs/rq2-performance/` and will generate fresh metadata.

The RQ4 and RQ5 targets are summary, manifest, and task/policy ledger checks,
not full reruns. Their full benchmark outputs were written under ignored
`results/` directories during experimentation and are not part of the tracked
artifact-ready branch. The raw backup branch preserves tracked historical notes
and manifests, but it does not replace a clean final rerun if the paper needs
fully audit-grade raw logs for these two RQs.

The current RQ5 figure script uses `197` safe/refused ActPlane outcomes so the
stacked counts sum to 361 tasks. If prose elsewhere states a different safe
count, reconcile the paper text before submission.

## Non-Cite Rule

If an experiment output does not have all of the following, it should not appear
in the paper or artifact-ready branch as a result:

- Fixed command line or script entrypoint.
- Commit ID.
- Input manifest.
- Environment metadata.
- Result summary.
- Clear status: canonical, exploratory, failed, or historical.

Exploratory data can stay in the raw backup branch, but it should not remain in
`master` where users or reviewers could mistake it for a maintained result.
