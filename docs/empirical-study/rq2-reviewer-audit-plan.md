# RQ2 Reviewer-to-Evidence Audit

Status: in progress, 2026-09-09. This plan does not modify the staged rebuttal draft.

## Decision and hypothesis

Reviewer D interprets Table 2 as an enforcement confusion matrix and asks why
ActPlane with feedback has 18 false positives while the opaque ablation has one,
even though both use the same kernel mechanism. The paper currently defines the
labels end to end, but then attributes 17 of 18 false positives to broad policy
translation without publishing trace-level evidence.

The primary hypothesis is that Table 2 mixes distinct stages: policy translation,
kernel rule matching, feedback delivery, and agent recovery. The 18 false positives
are therefore not measurements of kernel soundness or completeness. For every one
of the 190 traces, the audit will separately record ground truth, compiled-policy
intervention, intervention effect, feedback visibility, and final trajectory judge
label. The 18 false positives will then be manually attributed using the original
directive, frozen policy, trace, feedback, tool result, and judge rationale.

A positive result means the paper should replace “kernel FP/FN” language with an
end-to-end decomposition and report the dominant translation or harness failure
modes. A negative result, where intervention records disagree with actual effects,
would instead identify an engine or runner defect. A mixed result requires both
categories and representative negative examples to remain visible.

## One comparison matrix

| Unit | Frozen input | Kernel observation | End-to-end observation | Comparison |
| --- | --- | --- | --- | --- |
| 190 trace-system pairs per system | directive, policy, trace, expected compliance | rule fired, kill/notify, target, feedback | TP/TN/FP/FN, recovery tools, final error | within-system stage decomposition |
| 190 matched ActPlane pairs | identical task identity and trace family | ActPlane versus opaque trigger/effect | ActPlane versus opaque judgment | feedback ablation, not an independent baseline |
| 18 ActPlane FP traces | full evidence above | observed intervention and target | judge rationale and recovery | manual causal attribution with failures retained |

The audit treats prompt-filter and tool-regex as weak controls, FIDES/tool-IFC as
the independent research baseline, and ActPlane-opaque only as a feedback ablation.
It does not describe the 26/28 repaired false negatives as held-out generalization.

## Existing evidence first

The canonical Qwen artifact is on `origin/artifact-ready` at
`docs/artifact/rq2-qwen-primary/`. It contains 950 runner results and 950 judge
files selected by a frozen manifest. The historical full DeepSeek run remains on
`origin/backup/2026-06-14-master`. The paper-facing verifier is
`docs/artifact/verify_results.py` on the artifact ref.

Read-only extraction and audit command:

```bash
tmpdir=$(mktemp -d /tmp/actplane-rq2.XXXXXX)
git archive origin/artifact-ready \
  docs/artifact/rq2-qwen-primary docs/corpus-test \
  | tar -x -C "$tmpdir"
node docs/empirical-study/audit_rq2_verdicts.js "$tmpdir" \
  "$tmpdir/rq2-verdict-audit.json"
```

Raw paths remain the artifact manifest, its referenced runner JSON files, matching
`trajectory_judges_llama_cpp_guardrail_response/*.judge.json`, and each selected
`docs/corpus-test/*/*/rule.yaml` and trace JSONL. Generated audit output is
exploratory until manually reviewed and is not committed as a paper result.

## Initial reproducible result

Running the command above on the frozen Qwen artifact recomputes all 950 labels
and exactly matches the paper table. Of the 18 ActPlane end-to-end false
positives, 17 contain a setup-phase intervention and the remaining trace contains
a recovery-phase kill, so all 18 have an observed intervention. Three setup
interventions kill and 14 notify. In the paired opaque runs, 15 of the same 18
traces also record a setup trigger, but only one receives an end-to-end FP label.

This resolves Reviewer D's numerical paradox. The 18-to-1 difference does not
show that enabling feedback changed the kernel policy into one that matched 17
additional compliant traces. It mostly shows that the trajectory metric counts
visible corrective feedback as intervention, while a matching opaque notify is
hidden from the agent and can remain a TN. The paired runs are separate agent
executions, so the remaining trigger differences cannot be assigned to feedback
without comparing their exact executed effects.

The stage cross-tab further confirms that the labels are not kernel verdicts.
Among ActPlane rows, observed intervention occurs on 86/86 TP, 2/28 FN, 18/18
FP, and 2/58 TN trajectories. Thus intervention is necessary for the published
TP definition but is neither sufficient for TP nor exclusive to FP. Across all
190 matched ActPlane/opaque pairs, setup triggers occur in both runs for 83,
only ActPlane for 14, only opaque for zero, and neither for 93. This comparison
describes recorded executions, not paired deterministic trials, because feedback
can change later actions within a multi-step setup trajectory.

The raw rules already show heterogeneous candidate causes, including deliberately
broad translations (notify on every write), semantic conditions unavailable to a
path-only rule (dependency content or release intent), generated helper processes
that execute Python on behalf of file tools, and path or lineage mismatches. A
causal count remains pending trace-by-trace review. Until that review is complete,
the evidence supports an end-to-end metric clarification, not the stronger claim
that policy translation alone caused 17 of 18 false positives.

## New experiment gate

Only after this audit fixes the outcome semantics should new execution start. The
next experiment must address evidence that reuse cannot answer: either (1) freeze
high-authority policies before exposure to unseen, non-coding task content and
compare with an independent official baseline, or (2) measure security and benign
utility over session length after a sensitive read. Choice depends on available
official benchmark runners and whether policies are truly frozen before task and
injection exposure. Build success, smoke tests, and active processes are not
research outcomes.
