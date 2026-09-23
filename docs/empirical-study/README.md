# ActPlane Empirical Study

This directory keeps the curated empirical-study artifacts that are useful to
understand why ActPlane's policy language targets process, file, network, and
temporal agent behavior. Scratch notes, raw model runs, tuning logs, and full
corpus workspaces stay on the artifact or backup refs described in
`docs/ARTIFACT.md`.

## Snapshot

The study analyzed agent instruction files (`CLAUDE.md` and `AGENTS.md`) from
popular AI-agent code repositories. The retained product-branch artifacts are
aggregate outputs, not the full raw corpus.

| Metric | Value |
| --- | ---: |
| In-corpus repositories | 144 |
| Instruction files | 228 |
| Instruction-file text | 39,803 lines |
| Candidate normative lines | 3,762 |
| ActPlane-related candidate lines | 529 |
| Repositories with at least one ActPlane-related candidate | 101 |

The last three rows are reproducible from the committed
`candidate_rules_144.tsv`: 3,762 is its data-row count, 529 is the count of rows
carrying a non-`unclassified` `category_guess`, and 101 is the number of
distinct repositories holding at least one such row. The repository, file, and
line counts above them come from the full raw corpus, which is retained on an
artifact ref, so the committed TSV alone reproduces the candidate-line figures
but not the corpus totals.

The candidate-line counts are keyword/category extraction results and should be
read as aggregate evidence for prevalence, not as a hand-labeled ground truth.
The product branch keeps the aggregate study outputs that are independent of
compiler syntax. DSL-specific ruleset artifacts should live only on artifact
refs after they have been regenerated and validated against the current
compiler.

## Main Findings

- Agent instruction files frequently contain operational guardrails that are
  below the tool layer: VCS gates, secrets handling, test-before-commit rules,
  workspace boundaries, destructive-operation guards, network egress limits, and
  mediation through project tools.
- These guardrails map to ActPlane primitives: exec argument matching, labeled
  file and endpoint sources, source-to-sink label flow, `after` ordering,
  lineage gates, target scoping, and declassification.
- Style and code-quality instructions are common in the broader corpus but are
  intentionally outside ActPlane's enforcement scope unless they correspond to a
  concrete OS-observable action.

## Retained Artifacts

- `candidate_rules_144.tsv`: aggregate candidate-line extraction with repo,
  file family, line number, category guess, and source text.
- `figures/`: generated summary figures for the empirical study.

The raw corpus, raw traces, intermediate coding notes, old evaluation drafts,
and exploratory scripts are intentionally not kept in the product branch.

### RQ2 and long-session results (exploratory)

Results supporting the RQ2 reviewer evaluation (`rq2-lowering-eval.md`) and the
long-session over-taint experiment (`rq2-reviewer-audit-plan.md`). Each directory
is self-contained and carries the command, inputs, environment, and summary the
artifact Non-Cite Rule requires:

- `results/rq2-fp-current-lowering/replay.json`: host-side compiler replay, with a
  `status` and a `provenance` block naming the compiler binary hash, the input
  `fp_rows` hash, and a per-row `rule.yaml` digest manifest.
- `results/rq2-path-lowering-divergence/divergence.json`: the static
  historical-vs-current lowering divergences over the frozen rules, with the input
  coordinate under `provenance`.
- `results/rq2-fn-lowering-exposure/exposure.json`: the static audit of which
  frozen false negatives were exposed to the repo-relative `**/dir/**` miss.
- `results/rq2-except-probe-vm/`: the **pre-fix** live 6.8 guest probe.
- `results/rq2-except-probe-vm-postfix/`: the same probe after the fix, with
  `metadata.tsv` recording the guest kernel, both binaries' hashes, and the policy
  hashes.
- `results/rq2-except-probe-vm-pr44-engine/`: that probe re-run with a
  lower-budget engine so its six suffix write-rule rows become measurable;
  `metadata.tsv` names the engine source and the reason for the swap.
- `results/rq2-probe-prebuilt-object/`: the probe outcome with the then-committed
  (stale) prebuilt object, kept as the evidence for that finding.
- `results/rq2-engine-budget-crossval/`: the 6.8 verifier's 1M-instruction budget
  measured against three engine objects, described in `rq2-engine-budget-crossval.md`.
- `results/long-session-overtaint-vm/`: the long-session over-taint experiment
  re-run under TCG (`counts.tsv` matches the preregistered row set, `metadata.tsv`
  records the kernel, acceleration, and the three input hashes). The runner needed
  a longer loader wait than its original KVM run, so this is also the record that
  the TCG path works.
- `results/engine-install-smoke-vm/`: the pinned-engine install smoke
  (`run_engine_install_smoke_vm.sh`), which boots a 6.8 guest and requires
  `actplane run` to install the engine for a policy that names no `recv`. It
  reproduces the release-blocking summed-stack install failure on demand: the same
  smoke against a binary built from `origin/master` fails with
  `combined stack size of 6 calls is 608. Too large`. Like the other `run_*_vm.sh`
  runners it is run by hand, not by CI, because the failure only reproduces on a
  kernel that performs the combined-stack walk.

All are **exploratory** evidence for the reviewer response, not promoted paper
results. The DSL-specific frozen corpus and raw model runs still live only on the
artifact ref.
