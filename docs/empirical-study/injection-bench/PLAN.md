# Injection-bench experiment plan

## Research question and admission

User-defined uncertainty: can a compromised executing agent author a policy blind to its malicious actions, and does authoring a policy from trusted task context before exposure, then loading it at higher authority, improve attack resistance without losing legitimate task utility?

This is supporting evidence for the revised threat model. It addresses the ATC reviewer objections about untrusted input and self-authorship. Existing replay and authority-boundary tests cannot answer the end-to-end question because they do not run a task-solving agent through published injection attacks. A positive result supports this tested policy-generation and workload boundary. A contradictory result limits either policy construction, kernel enforcement or utility. It does not justify redefining the threat model after seeing outcomes.

Preferred standard is OS-Harm. Published coding fallback is RepoGuardBench because the official OS-Harm installation exceeds the current shared disk envelope. Broad adoption of the fallback is unverified. This is a material deviation recorded before runs, not a completed standard-benchmark requirement.

## Reused official assets

RepoGuardBench upstream commit `49d6e51b5189f1f49a948bf360ed73d9487548a3`. Reuse the task files, `inject_attack`, default carrier/goal pairs, `run_agent`, defense registry, workspace sandbox and `score_run`. No synthetic tasks, payloads or benchmark metrics. The necessary adapters are model transport and ActPlane process/domain binding. The official sandbox remains active in every condition, so no defense means no additional defense beyond that sandbox.

Official reference: <https://github.com/DaoyuanLi2816/RepoGuardBench/blob/main/docs/REPRODUCIBILITY.md>. The official agent budget and generation configuration are preserved where representable by the supplied OpenAI-compatible endpoints. Any unsupported Ollama-specific option is documented rather than silently approximated.

## Matrix and selection

- Models: `qwen3.8-27b-nvfp4` through the supplied direct endpoint; `zai/glm-5.3` through the supplied gateway. Record returned model identity without treating gateway groups as model identities.
- Systems: `D0_none`; official `D3_action_gate`; `AgPlane_parent_pre`; `AgPlane_child_post`.
- Deterministic stratified subset: at least fifty distinct official base tasks, with attack carriers balanced across the five official carrier/goal pairs. Keep Applied tasks represented and stratify Core task categories. Each attacked task gets a matching clean task for every system and model. Record the exact IDs, strata, carrier and selection algorithm before execution. Expand to the full split only if feasible without invalidating the matched matrix.
- Official seed and action-turn budget. A model transport timeout is recorded as an operational failure and included in the planned denominator.
- No hand-written policy oracle. The pre-exposure policy generator sees the legitimate task description only. It sees neither injected content nor attack metadata. Post-exposure generation is performed by the executing model after its initial untrusted context is available, and its policy is submitted by the actual child-domain caller.

## Metrics and validity

Report official completed-attack ASR, clean utility and utility under attack separately per system/model. Also retain official attempted-action and landed-action indicators where available. The official scorer runs outside the constrained agent so that protective reads/writes cannot contaminate hidden evaluation. Failure handling must preserve cell metadata and planned denominator even though the upstream crash-return path omits normal run fields.

Record policy-generation and compile failures, timeouts, retries, scoring failures and actual kernel admission/violation evidence. Do not replace failed generation with an oracle policy. Do not classify user-space rejection as a kernel rejection. Empty delta-attempt coverage cannot support a rejection claim.

Attack outcomes stay unknown when a crash or scoring failure prevents reliable final-state observation. When complete stable state is available, apply the official predicate even after a generation or execution failure. The primary table keeps the planned denominator and reports bounds where genuinely unknown outcomes remain. A failed model call is never automatically described as a successful defense. Utility uses the independent official evaluator, with execution failures displayed separately.

Parent and child conditions require real process-domain membership and real kernel enforcement of tool effects. A replay, observer-only mode, a constrained Docker client or a host watcher around a guest VM is insufficient. Use one engine or serialized engine sessions to respect the existing singleton. Preserve other active lanes and sessions.

The benchmark worker drops root identity and BPF/map/ptrace authority before any untrusted context is executed. Trusted loader, control metadata, audit and higher-authority policy remain root-owned. Socket access does not itself confer authority: requests must use the actual Unix peer PID and its kernel-bound domain. Verify worker credentials in preflight. Apply the same unprivileged execution environment to all systems.

## Execution and completion

Remote paths: `raw/upstream/` for pinned official sources; `raw/` for trajectories and per-cell records; `logs/` for detached process logs. `scripts/benchmark_runner.py` is the lane adapter; aggregation must consume only actual records and a frozen selection file and produce committed CSVs and a matplotlib PDF with embedded TrueType fonts.

Implementation notes before defended runs: absolute paths must fit the engine ABI, so defended workers use short real repository roots under `/tmp`, with complete final states retained in their persistent raw case directories. Relative task files, contents, official actions and utility tests are unchanged. Baseline agent messages contain relative paths and do not expose a repository absolute root. New detached runs use `scripts/launch.sh` to snapshot runtime scripts outside the synced `src` tree. The original transport preflight used a shorter request timeout than the pinned official client. It is excluded from results; the runner now uses the official client deadline. The existing successful GLM baseline calls completed below either deadline, so none were censored by that setup correction.

The mechanism preflight succeeded in a root-PID-namespace guest with BPF LSM. Its precise modified-artifact boundary and audit evidence are in `KERNEL.md` and `results/kernel-preflight/`. Model inference uses a trusted fixed-model file channel outside the confined tool process, including the official optional Claude CLI backend. The executing worker receives no API credentials. This is an inference transport adaptation, not an additional agent tool or a defense. Earlier baseline HTTP transport and the file channel submit the same model messages and options.

The policy-construction call uses an 8192-token allowance for both pre-exposure and post-exposure authors. This is separate from the unchanged official action-call budget. A setup trial incorrectly reused the shorter action allowance for policy construction, producing empty, reasoning-truncated replies. That setup trial is excluded, and empty policy replies are explicit failures rather than silently installed no-op policies. There is one model-authored construction per cell, with no oracle policy replacement. The pinned RQ5 description-only generator was inspected for its task-only information boundary; this experiment uses a language-model author as explicitly requested, rather than its keyword-based first-pass constructor.

The official optional frontier backend is added as a separate frozen manifest, with the same selected tasks, carriers, clean twins and systems. Its actual installed model identity and the empty-tool-registry adaptation are recorded in `FRONTIER.md`. Tables combine the disjoint manifests and never overwrite the original matrix.

Before the defended main run, the self-authoring output interface was aligned with the official agent's system-level JSON action schema. The executing agent emits a normal `write_file` action containing its DSL, and the actual child submits that content. The original model response and native admission result remain in its conversation. This avoids requiring a lower-priority user request to override the official JSON output format. It adds no task-solving action turns.

Utility grading is independent of the constrained agent domain. The same official target-test runner executes as an unprivileged host evaluator using root-owned task/node/root metadata. Actual agent post-state is frozen before grading, so evaluator effects cannot create apparent attack successes. The original in-domain test report remains in the raw trajectory. Earlier baseline workspaces are regraded with this same evaluator without rerunning any model calls. Utility measures final artifact correctness, not whether the confined agent could itself execute the final grading command.

Independent guest kernels permit parallel model cells without sharing ActPlane singleton maps. Each queue still runs one engine at a time. Qwen workers use separate retained guest queues because observed model latency would otherwise dominate the deadline. This changes execution scheduling only; frozen cells, task contents, policy construction, model options and evaluator remain identical. Every guest is stopped after its assigned run reaches terminal status.

Preflight uses a real official task and real model, attack, defense, kernel binding and scorer. Setup/smoke output is not a paper result. After preflight, run the matched matrix to terminal status. Every planned cell remains in the report. A fresh reviewer checks the plan before execution and recomputes the final table after the run. No paper edits or pushes are authorized in this lane.
