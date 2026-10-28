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

## Experiment Evidence on `experiments/mlsys27`

This branch collects the reviewer-driven experiments for the MLSys 2027
resubmission. They are kept on a branch rather than opened as pull requests,
because experiment outputs do not belong on `master`. Each item was copied from
its source branch at the commit listed. Several runners need engine fixes that
are only on their source branch so far (for example, the Linux 6.8 verifier stack
fixes), so rerun them from that commit until those fixes land on `master`.

| Experiment | Files | Source |
| --- | --- | --- |
| Policy authority boundary, 7 cases on a Linux 6.8 KVM guest | `policy-authority-boundary-plan.md`, `run_policy_authority_boundary_vm.sh`, `results/policy-authority-boundary-vm/` | `experiments/noncoding-baseline-audit-20260910` @ `4ace335f` (#41) |
| OpenAgentSafety policy firing audit, 18 cases, plus verifier statistics on a 6.8 guest | `openagentsafety-policy-firing-audit.md`, `run_oas_firing_audit_vm.sh`, `run_oas_verifier_stats_vm.sh`, `results/oas-firing-audit-vm-k68b/`, `results/oas-firing-audit-vm-k68d/`, `results/oas-verifier-stats-vm-k68/` | `experiments/oas-firing-audit-20260915` @ `8b9eb3d1` (#44) |
| RQ2 lowering and false-positive attribution, long-session over-taint, BPF-LSM block smoke, wildcard-literal probe, OpenAgentSafety compile audit | `rq2-lowering-eval.md`, `rq2-fp-attribution.md`, `rq2-reviewer-audit-plan.md`, `openagentsafety-policy-compile-audit.md`, `replay_fp_lowering.py`, `audit_*.py`, `verify_results.py`, the matching `run_*_vm.sh`, and `results/{rq2-fp-current-lowering,rq2-path-lowering-divergence,rq2-fn-lowering-exposure,rq2-except-probe-vm,rq2-except-probe-vm-postfix,long-session-overtaint-vm,lsm-block-smoke-vm,rq2-wildcard-literal-vm}/` | `experiments/rq2-lowering-eval-20260915` @ `bcbcdbc2` (#45) |
| RQ2 verdict audit | `audit_rq2_verdicts.js` | `experiments/rq2-path-baseline-audit-20260910` @ `1c2ed261` |

The earlier versions of `rq2-reviewer-audit-plan.md` and
`run_long_session_overtaint_vm.sh` (#39), and of the OpenAgentSafety audit script
and notes (`experiments/openagentsafety-policy-audit-20260910`), are superseded by
the newer copies above. The verifier-budget debugging logs from #45
(`engine-install-smoke-vm*`, `rq2-engine-budget-crossval`,
`rq2-probe-prebuilt-object`, `rq2-except-probe-vm-pr44-engine`) are engineering
evidence for the engine fixes, not paper evidence; they remain on their source
branch.
