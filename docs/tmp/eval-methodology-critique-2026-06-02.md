# ActPlane Eval Methodology Critique

Date: 2026-06-02. Written before any experiments are run.

Based on: main.tex (actual paper), 05-evaluation.tex (actual eval section),
eval.md (detailed eval plan). Incorporates all discussion conclusions.

---

## 1. What the Paper Claims (main.tex abstract)

> "ActPlane **improves policy compliance by XX%** over existing enforcement
> mechanisms and **end-to-end task completion by XX pp**, with **<X µs**
> per-syscall overhead."

Three claims, each needs a different kind of evidence:

| Claim | Type | Requires |
|---|---|---|
| C1: improves policy compliance by XX% | End-to-end effectiveness | System comparison on same workload |
| C2: end-to-end task completion by XX pp | End-to-end effectiveness | Live agent benchmark |
| C3: <X µs per-syscall overhead | Performance | Microbenchmark + macrobenchmark |

---

## 2. What the Paper Designs (05-evaluation.tex)

| RQ | Question | Method |
|---|---|---|
| RQ1 | DSL expressiveness | Coverage of 607 directives |
| RQ2 | Translation correctness | LLM translates → human review |
| RQ3 | System correctness + bypass | Violation/compliant traces × 4 systems, match rate |
| RQ4 | Overhead | Per-syscall latency |
| RQ5 | Feedback effectiveness | Terminal-Bench × 3 conditions (B1 nothing, B2 bare EPERM, B3 feedback) |

---

## 3. What eval.md Designs (Detailed Plan)

| RQ | Question | Method |
|---|---|---|
| RQ1 | Policy compliance | 607 directives × 2 traces × 7 systems × trace replay + 1 LLM decision |
| RQ2 | Overhead | Microbenchmark + macrobenchmark |
| RQ3 | Feedback effectiveness | Terminal-Bench × 2 conditions (B1 nothing, B2 full ActPlane) |

---

## 4. Core Insight: Why End-to-End Is the Only Correct Methodology

### The pipeline is not separable

```
NL directive → [LLM translation] → DSL rule → [kernel detection] → feedback → [LLM recovery] → compliance
```

Every stage involves LLM judgment. You cannot isolate "ActPlane
correctness" from "translation correctness" because:

- **Rule correctness is ambiguous.** "Don't commit without testing" has
  many valid DSL translations depending on project context (pytest vs
  go test vs make test, block commit vs push, etc.). There is no
  context-free standard for "correct rule."

- **Detection depends on translation.** Whether ActPlane fires on a
  bypass path depends on whether the LLM-generated rule pattern matches
  the bypassed command. Kernel architectural guarantee (all syscalls
  pass through eBPF) ≠ rule matching correctness.

- **Recovery depends on detection + feedback quality.** Whether the
  agent complies depends on whether it received useful feedback, which
  depends on what rule fired, which depends on translation.

### What this means for evaluation

**Component-level testing is circular or uninformative:**

| Component test | Problem |
|---|---|
| "DSL can express N/607 directives" (RQ1) | Tautological — DSL was designed for these directives |
| "LLM translates with X% precision" (RQ2) | No ground truth — "correct" depends on project context |
| "ActPlane fires on violation traces" (RQ3) | Predetermined by architecture — if rule matches pattern, eBPF fires; this is an integration test, not a research question |

**End-to-end testing is the only non-circular approach:**

- Ground truth is defined at the directive + scenario level (not the rule level)
- Translation errors manifest as FP/FN in the end-to-end metric
- Translation errors are shared noise — all systems use the same LLM-translated rule
- Differences between systems = system capability differences, not translation differences

### Implication for 05-evaluation.tex

RQ1 (expressiveness) and RQ3 (detection correctness) produce
predetermined results. Their content should be **design validation**
(one paragraph in §Setup), not evaluation RQs.

RQ2 (translation correctness) cannot be rigorously scored because
"correct" has no objective standard for ambiguous directives.

The informative experiments are RQ4 (overhead, quantitative unknown)
and RQ5 (feedback effectiveness, quantitative unknown). eval.md's RQ1
(end-to-end compliance with LLM decision) should replace
05-evaluation.tex's RQ3.

---

## 5. What OSDI Expects

Systems conferences expect evaluation to answer:

1. **How fast is it?** — Per-operation overhead, end-to-end on real
   workloads, scaling with problem size, comparison with existing systems.

2. **Does it actually help?** — End-to-end measurement on realistic
   workload proving the claimed benefit. With ablation (which component
   contributes what).

3. **How does it compare?** — Apples-to-apples comparison with
   alternative approaches on the same workload.

Design guarantees (e.g., bypass-free enforcement from kernel
architecture) are proven with architecture arguments in §Design, not
with large-scale experiments. Implementation correctness is validated
with test suites, mentioned in one sentence in §Setup. Only
**quantitative unknowns** deserve full evaluation RQs.

For ActPlane, the quantitative unknowns are:
- Overhead (implementation-dependent)
- Feedback effectiveness (LLM-behavior-dependent)
- Policy compliance improvement over alternatives (depends on both)
- FP rate on real workloads (IFC model precision, not predictable from design)

---

## 6. Claim-by-Claim Gap Analysis (Based on Actual Paper)

### C1: "improves policy compliance by XX% over existing enforcement mechanisms"

**What it needs:** End-to-end compliance rates across multiple systems on
the same rules and scenarios.

**eval.md approach:** 607 directives × 2 traces × 7 systems × trace
replay + 1 LLM decision step. Score compliance vs ground truth.

**This is conceptually correct.** The LLM decision step is essential —
without it, you only measure detection (which doesn't distinguish Kernel
IFC from ActPlane, since they use the same engine). With the LLM step,
the compliance difference comes from feedback quality.

**05-evaluation.tex approach (RQ3):** Violation/compliant traces × 4
systems, report match rate.

**This is insufficient.** Match rate = detection, not compliance. Kernel
IFC and ActPlane have identical detection but different compliance
(because feedback differs). RQ3 cannot show a difference between them.

**Remaining issues with eval.md's approach:**

1. **Scoring not operationalized.** "Compare agent final action against
   ground truth" — but agent final action is free text. Need a concrete
   scoring protocol:

   ```
   Layer 1 (deterministic, ~80% of cases):
     - ActPlane fired + agent response contains remediation → CORRECT
     - ActPlane fired + agent response contains prohibited action → INCORRECT
     - ActPlane didn't fire + ground_truth=compliant → TN
     - ActPlane fired + ground_truth=compliant → FP

   Layer 2 (LLM judge, ~20% edge cases):
     - 2+ judges, majority vote, report agreement rate
     - Clear rubric provided
   ```

2. **Single tested model.** Only 1 weak model planned. Need at least 3
   (small/mid/frontier) to show generalization. ODCV-Bench found safety
   is non-monotonic across model sizes — results on one model don't
   generalize.

3. **Ground truth subjectivity.** "Is this a violation given this prompt?"
   is a judgment call for some directives. Need inter-annotator agreement
   on a sample (100 traces × 2+ annotators).

4. **Error decomposition missing.** End-to-end FP/FN conflates translation
   error, detection error, and recovery error. Should decompose as
   post-hoc analysis (not separate RQ, just analysis of same data):

   ```
   For each FN case:
     - Was the rule wrong? (translation error)
     - Did ActPlane fail to fire? (detection error — shouldn't happen)
     - Did agent ignore feedback? (recovery error)
   ```

5. **No pressure/conflict scenarios.** Traces are either "violation" or
   "compliant" — neither has task pressure. Should add a "pressure"
   variant for a subset (e.g., 50 directives) where the prompt creates
   tension with the policy. This tests the "cooperative-but-forgetful"
   threat model.

6. **"7 systems" — are they really 7 independent systems?** Three of
   them are ActPlane with features disabled (per-event eBPF = --no-labels,
   Kernel IFC = --no-feedback, ActPlane = full). Two are Python scripts
   you wrote (TL-1, TL-N, App-IFC). Only Prompt-only is truly external.
   A reviewer might question whether this is a fair comparison. Mitigation:
   clearly state that the Python baselines faithfully implement the
   published approach (cite AgentSpec/Progent/FIDES/CaMeL) and that
   ActPlane variants isolate specific design decisions (ablation).

### C2: "end-to-end task completion by XX pp"

**What it needs:** Live agent benchmark showing B3 (AP+feedback) > B1 (nothing).

**05-evaluation.tex RQ5:** 3 conditions (B1 nothing, B2 bare EPERM,
B3 feedback). This is well-designed.

**eval.md RQ3:** Only 2 conditions (B1, B2=full ActPlane). Missing B2
(bare EPERM). **eval.md is weaker than 05-evaluation.tex here.**

05-evaluation.tex's 3-condition design is correct because:
- B1 vs B3 = total system value
- B2 vs B3 = feedback contribution (the load-bearing claim)
- B1 vs B2 = enforcement-only value

**Remaining issues:**

1. **Only 1 weak model.** Same as C1. Need 2+ models.

2. **RQ3 rules are LLM-generated, unvalidated.** Strong model generates
   rules for 89 tasks. No human audit of rule quality. Should audit a
   sample (20/89) and report "reasonable rule" rate.

3. **Rule adaptation (3 rounds) is interesting but under-specified.** What
   counts as "refinement"? How much does the strong model change between
   rounds? Report diff between round 1 and round 3 rules.

### C3: "<X µs per-syscall overhead"

**Both eval.md (RQ2) and 05-evaluation.tex (RQ4)** cover this well.

**One addition:** Include Tetragon as a head-to-head comparison. Tetragon
is open-source, widely used, does per-event eBPF enforcement. Running it
on the same microbenchmarks gives an apples-to-apples overhead comparison
that OSDI reviewers will expect.

---

## 7. Recommended Eval Structure (OSDI-Aligned)

Based on all discussion conclusions:

```
§5.1 Setup
  Hardware, kernel, agent versions.
  Validation: "We validated detection correctness on all N rules
  across K execution paths, confirming all violation traces trigger
  and no compliant traces false-match." (one paragraph, not an RQ)

§5.2 End-to-End Policy Compliance (main result for C1)
  From eval.md RQ1: 607 directives × 7 systems × trace replay
  + LLM decision.
  Replaces 05-evaluation.tex RQ3 (which only tests detection).
  Key: includes LLM decision step, making it a compliance test.
  Scoring: 2-layer deterministic + LLM judge.
  Models: 3 (small / mid / frontier).
  Report: compliance rate by system × enforcement level.
  Analysis: error decomposition (translation / detection / recovery).

§5.3 Overhead (C3)
  From eval.md RQ2 / 05-evaluation.tex RQ4.
  Per-syscall latency, macrobenchmark, memory, scaling.
  Include Tetragon comparison.

§5.4 Feedback Effectiveness on Live Tasks (C2)
  From 05-evaluation.tex RQ5 (3 conditions, not eval.md's 2).
  Terminal-Bench × 3 conditions (nothing / bare EPERM / feedback).
  Models: 2 (small / mid).
  Report: task completion rate, guided completion rate.
  Adaptation: 3 rounds of rule refinement.

§5.5 FP Under Real Workloads (supplementary)
  Replay known-good Terminal-Bench traces under ActPlane.
  Report spurious rule matches.
  Cheap (no LLM), directly supports deployability claim.
```

What was removed vs 05-evaluation.tex:
- RQ1 (DSL expressiveness) → §Design, one paragraph
- RQ2 (translation correctness) → subsumed into §5.2 error analysis
- RQ3 (detection) → replaced by §5.2 (compliance, strictly stronger)

What was added vs 05-evaluation.tex:
- LLM decision step in system comparison (from eval.md)
- Multiple models
- Error decomposition analysis
- FP on real workloads
- Tetragon overhead comparison

---

## 8. Remaining Issues in eval.md (Under Strict Standards)

Even after incorporating the above fixes, these issues remain:

### 8.1 Ecological validity of trace replay

Trace replay + 1 LLM decision tests "can the agent interpret feedback
in a controlled context?" Multi-step recovery (agent tries something,
fails again, tries a different approach) is only tested in RQ5
(Terminal-Bench). This is acceptable if clearly stated as a limitation.

### 8.2 Baseline violation rate not established

We don't measure "how often do agents naturally violate these policies
without enforcement?" This is the motivation question. However, we can
cite published numbers (OpenAgentSafety: 49-73% unsafe on OS-level
tools; ODCV-Bench: 0-56% constraint violation under pressure) instead
of running our own experiment. See baseline-violation-rates.md.

### 8.3 No adversarial evaluation

Threat model is "cooperative-but-forgetful." No test of adversarial
bypass attempts (agent deliberately trying to circumvent ActPlane).
This is fine for the claimed threat model but should be stated as
part of the stated evaluation scope.

### 8.4 Notify mode not evaluated

The paper claims progressive deployment (notify → block → kill).
Only block/kill are tested. Notify mode (observe without blocking)
is part of the design but not evaluated. Should at least mention in
the eval.

### 8.5 Cross-event vs per-event not broken out consistently

The paper's key architectural contribution is cross-event IFC. All
tables should break out results by per-event vs cross-event enforcement
level, showing that the IFC contribution matters. Current tables have
this but it should be a first-class analysis dimension throughout.

### 8.6 Real deployment case study

OSDI papers typically include 1-2 case studies showing the system in
realistic use. A 1-page case study of ActPlane running on a real
project (e.g., this repo, with the no-git-branch rule) would strengthen
the paper significantly. This is not a gap in the formal evaluation but
a gap in the paper's persuasiveness.

---

## 9. New Eval Harness: agent_sdk_eval.py (2026-06-02)

Implemented a new eval harness that addresses the core methodology
issues identified above.

### Architecture

```
run_eval_isolated.sh (overlay on workspace — host untouched)
  └─ agent_sdk_eval.py (outer driver)
      └─ sudo actplane run --policy rule.yaml (per scenario)
          └─ agent_sdk_eval.py --inner (overlay on real repo from corpus-evaluated/)
              └─ OpenAI Agents SDK (Runner.run, multi-step agent loop)
                  ├─ llama.cpp (local Qwen 27B) via HTTP
                  └─ bash_tool / read_file / write_file → real subprocess → eBPF → ActPlane
```

### Key improvements over replay_agent.py

| Issue | Old (replay_agent.py) | New (agent_sdk_eval.py) |
|---|---|---|
| Agent runtime | Manual: 1 LLM call, prose output | OpenAI Agents SDK: structured tool calls, multi-step loop |
| Tool execution | Fake tools (stub scripts) | Real subprocess (eBPF hooks fire on real exec/open/write) |
| Workdir | Empty tmpdir | Overlay on real repo (corpus-evaluated/), with real .git, real files |
| Recovery | None — record text, never execute | Multi-step: agent tries → ActPlane responds → agent retries |
| Compliance scoring | Text matching / LLM judge | Deterministic: ActPlane fires again during recovery → not compliant |
| Isolation | None | Double overlay: inner (per-repo) + outer (workspace) |

### Preliminary Results (10 repos × violation + compliant = 20 scenarios)

First run with real repos showed ActPlane correctly firing on
violation traces where trace setup leads to policy-relevant operations
(e.g., git commit without tests). Agent receives semantic feedback and
attempts recovery, but often fails because required tools (uv, prek,
project-specific test commands) are not installed in the eval
environment.

Key finding: **compliance testing requires a realistic tool
environment, not just realistic file state.** The real repo overlay
provides the right file state, but the agent also needs the project's
toolchain to actually perform the remediation (e.g., run tests).
This is an inherent limitation of testing across diverse projects
without per-project Docker environments (like Terminal-Bench provides).

### Remaining work

1. Per-project tool installation (or Terminal-Bench-style Docker)
2. Multiple models (currently only Qwen 27B)
3. Multiple systems (prompt-only, kernel-ifc, actplane) comparison
4. Statistical analysis of results

---

## 10. Critical Discussion Conclusions (Late-Session Insights)

### 10.1 Trace Replay Is Wrong for This Paper

**Problem:** AgentSpec (ICSE '26) and Progent (2026) — the two closest
comparison systems — both use free agent runs on existing benchmarks.
Trace replay is unique to ActPlane's eval and looks weak in comparison.

**But the deeper problem is threat model mismatch:**
- AgentSpec/Progent test SAFETY (adversarial attacks) → injecting
  attacks to test enforcement is methodologically correct
- ActPlane tests COMPLIANCE (cooperative-but-forgetful) → injecting
  forgetfulness via traces is methodologically wrong. You claim agents
  naturally forget; you should OBSERVE natural forgetfulness, not
  manufacture it.

**Solution:** Free agent runs on normal coding tasks. Agent works in real
repos with real policies. Observe natural policy violations. Measure
how ActPlane reduces them.

### 10.2 "Natural Forgetfulness Rate" IS Measured in Literature

Previous claim that "no one measured this" was wrong. Key papers:

- **McMillan et al. (2605.10039):** CLAUDE.md compliance decays 5.6% per
  generation step; refactoring tasks = 45% compliance
- **OctoBench (2601.10343):** End-to-end multi-rule compliance = 10-28%
  (even though per-rule compliance is 80%+)
- **AGENTIF (2505.16944):** Tool constraint compliance = 10-27% (lowest
  category)
- **Guardrails Beat Guidance (2604.11088):** Rules work through context
  priming, not actual instruction following; negative constraints
  ("don't X") are the only beneficial type

These numbers can be cited as baseline motivation. ActPlane's eval
should show it IMPROVES these rates through runtime enforcement.

### 10.3 Correct Eval Methodology (Final)

The paper should use the same methodology as AgentSpec/Progent but
adapted for the compliance (not safety) threat model:

```
Experiment:
  N tasks × M repos (each with CLAUDE.md policies)
  Agent runs freely on normal coding tasks (not designed to trigger violations)
  
  Condition A: No ActPlane     → measure natural violation rate
  Condition B: ActPlane (full) → measure enforced violation rate
  Condition C: ActPlane (bare EPERM, no feedback) → isolate feedback contribution

  Metrics:
    - Policy compliance rate (A vs B vs C)
    - Task completion rate (utility preservation)
    - Recovery rate after enforcement (B vs C)
    
  Compliance is measured by:
    - ActPlane detection (for enforcement conditions)
    - Post-hoc audit (for no-enforcement condition)
```

This is methodologically identical to AgentSpec/Progent but:
- Threat model: compliance, not safety
- Policies: from real CLAUDE.md files, not synthesized safety rules
- Benchmark: real coding tasks in real repos, not safety benchmarks

### 10.4 What ActPlane's Eval Adds to the Literature

| Existing measurement | What ActPlane adds |
|---|---|
| McMillan: CLAUDE.md compliance = 45-71% | Does enforcement improve this? |
| OctoBench: multi-rule end-to-end = 10-28% | Does kernel-level enforcement help with multi-rule? |
| AGENTIF: tool constraints = 10-27% | Does OS-level enforcement specifically help tool constraints? |
| Guardrails BG: negative constraints help | Does ENFORCING negative constraints help more than just stating them? |

The unique contribution is: **from measurement to intervention.** Everyone
else measures the problem; ActPlane measures the solution.

### 10.5 Papers to Cite

**For motivation (baseline violation rates):**
- McMillan et al. 2025 (CLAUDE.md compliance decay) — most directly relevant
- OctoBench 2026 (scissors gap: per-rule vs end-to-end)
- AGENTIF 2025 (tool constraints are worst category)
- OA-Safety 2026 (49-73% unsafe on OS-level tools)
- ODCV-Bench 2025 (0-56% misalignment under pressure)

**For methodology comparison:**
- AgentSpec, ICSE 2026 (free agent run, tool-layer enforcement)
- Progent, 2026 (free agent run on AgentDojo/ASB)
- Guardrails Beat Guidance, 2026 (rules affect performance, not compliance)
- Lulla et al. ICSE JAWs 2026 (AGENTS.md affects efficiency, not compliance)

**For system comparison:**
- CamQuery, CCS 2018 (kernel IFC, closest system ancestor)
- Tetragon (per-event eBPF enforcement)
- FIDES / CaMeL (app-level IFC)
