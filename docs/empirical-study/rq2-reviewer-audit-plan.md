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

## Selected new experiment: long-session over-tainting

Reviewer B predicts label explosion in long sessions, and Reviewer D asks whether
reading `.env` prevents all later network use. Existing E1 proves one secret-read
to connect flow and E8 proves explicit declassification, but neither measures how
intervention burden grows or where process-scope boundaries reset it.

The hypothesis is that a sensitive label remains monotonic within a process lineage,
so every later benign connect matches even when it does not use sensitive content.
Safety should remain constant while intervention burden grows linearly with the
number of later connects. A negative result would show lost persistence or missing
connect observation. A mixed result would locate a process or descendant boundary
and narrow the paper's “session” claim.

| Case | Label at start | Later relationship | Benign connects | Predicted matches |
| --- | --- | --- | ---: | ---: |
| clean control | no | same seeded lineage | 5 | 0 |
| length 1 | yes | same process | 1 | 1 |
| length 5 | yes | same process | 5 | 5 |
| length 20 | yes | same process | 20 | 20 |
| labeled process exits | child only | clean sibling | 5 | 0 |
| nested descendant | yes | one extra fork generation | 5 | 5 |

The first run isolated persistence by seeding the frozen `SECRET` bit at the
process boundary. It established the propagation control but did not answer the
reviewer's actual file-read premise. After moving update matching and rename-flow
state off the BPF stack, the follow-up uses `source SECRET = file
"/session.env"`. Each sensitive case opens and reads that file before connecting.
The sibling case confines the read to a child that exits. The policy uses
`notify`, not `kill`, so all scheduled connects execute and the count measures
burden rather than early termination. Destinations are closed loopback ports, and
no payload is sent.

The privileged VM runner is
`docs/empirical-study/run_long_session_overtaint_vm.sh`. On Ubuntu 6.8 under KVM,
the seeded control and the real-read follow-up both observed 0, 1, 5, 20, 0, and
5, exactly matching the preregistered rows. Every sensitive violation in those
six rows records provenance `op:1` and target `/session.env`. Thus the control's propagation result
survives real label acquisition: intervention burden grows linearly inside the
labeled lineage, including one more fork generation, while a clean sibling remains
untainted after the reader exits. This supports Reviewer B's over-taint concern
within one lineage, but not process-tree-global label explosion.

A seventh engineering validation renames `/session.env` to `/renamed.env`, reads
the renamed inode, and then connects. It observes the one predicted violation,
which validates label-state propagation through the new rename exit path. Its
provenance is null, however, so label provenance does not currently survive this
materialization-and-rename path. This retained negative result does not affect the
six-row over-taint comparison, and it identifies a separate feedback-explanation
gap rather than claiming full rename equivalence.

Raw evidence is under
`/workspaces/.agent-state/actplane-research/raw/file-read-long-session-20260910T0124Z/`.
`counts.tsv` is derived from `console.clean.log`, which retains every
`TAINT_VIOLATION`, and `metadata.tsv` records commit, kernels, acceleration, and
policy hash. The container runner
`docs/empirical-study/run_long_session_overtaint.sh` could not load BPF because
the container lacks `CAP_BPF` and `CAP_SYS_ADMIN`. The original Ubuntu 6.8
file-source attempt failed at `trace_openat_exit` with combined call-stack size
544 bytes. Raw failed attempts remain under `raw/file-read-stack-fix-attempt*`.
After the open path loaded, the same limit surfaced in the generic rename-rule
path, so source-only policies now autoload a propagation-only rename exit program
while write-rule policies retain the full sink evaluator. These failures are
engineering evidence, not experimental observations. Build success and loader
readiness remain prerequisites, not results.
