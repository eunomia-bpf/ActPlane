# Indirect execution in public coding-agent trajectories

**Measured:** static execution patterns in 3,156 trajectories and 89,176 recorded tool calls/action slots from 5 frameworks and 8 recorded model groups. **Dynamic follow-up:** the replay section below measures captured OS write/exec effects against the initiating call arguments. These are best-effort replays, rather than original deployment telemetry.

## Dynamic replay validation

**Interim: 31 of 40 planned replay receipts are available.** **Observer errors remain. Effect tables are diagnostics pending instrumentation retries.** The [fixed plan](dynamic_plan.csv) was selected by a committed hash ranking, paired by task within each source. It includes exact base commits recovered from pinned task metadata. No task was replaced based on replay success. Recorded calls are replayed in order against a fresh checkout in a private local PID/mount namespace. Shell command strings remain as recorded. Dedicated edits are implemented as direct file writes by the committed adapter. The coordinator, environment setup, and injected dispatchers are excluded from observed effects. No oracle or verifier patches are applied. [dynamic_metadata_manifest.csv](dynamic_metadata_manifest.csv) records pinned metadata versions, task-archive hashes, and license caveats. The pinned SWE-bench Verified card does not state a dataset license, and no separate native task-data license was verified. Derived tables, brief call previews, and source locators are committed, while full task archives and transcripts stay external and third-party source terms remain applicable.

Across the available receipts, the observer recorded **2,033,390 successful regular-file write operations**, of which **99.01% were unnamed**, and **9,331 successful execs**, of which **71.66% were unnamed**. At least one unnamed write or exec was observed for **390 of 992 recorded calls (39.31%)**. The count of trajectories with an observed unnamed effect is **29**. These pooled event totals are affected by large installations. Counting each distinct `(call, object)` pair once gives **99.95% unnamed write pairs** and **43.25% unnamed exec pairs**. Unresolved/truncated object paths are kept in the denominator and separately counted: 3 write events and 0 exec events. The reported unnamed fractions therefore use the lower endpoint for unresolved names.

An object in these tables is a kernel-resolved regular-file path for writes or the requested executable pathname of a successful exec syscall. It is not an inode or a unique process. Executable aliases, symlinks, and interpreter loading are not expanded into additional exec effects. To avoid weighting trajectories by installation volume, the following medians give each trajectory with the relevant captured effects equal weight. Trajectories with no captured effect of that kind have an undefined fraction and remain in the call/fidelity denominators. [dynamic_trajectory_summary.csv](dynamic_trajectory_summary.csv) contains every replay receipt.

| Effect | Weighting within trajectory | Trajectories with effects | Median unnamed fraction |
|---|---|---:|---:|
| write | events | 31 | 99.96% |
| write | objects | 31 | 99.84% |
| exec | events | 31 | 56.08% |
| exec | objects | 31 | 46.15% |


| Replayed framework / recorded model | Traj. | Recorded calls | Executed | Exit zero | Unnamed write events | Unnamed exec events |
|---|---:|---:|---:|---:|---:|---:|
| Claude Code / fable-5 | 10 | 410 | 410 | 373 | 98.45% | 72.09% |
| Codex / gpt-5.6-sol | 10 | 180 | 180 | 145 | >99.99% | 59.77% |
| mini-SWE-agent / claude-opus-4-6 | 10 | 377 | 377 | 341 | 99.96% | 79.06% |
| mini-SWE-agent / gpt-5.2-high | 1 | 25 | 25 | 23 | 99.28% | 67.83% |

These are effects observed during replays of recorded trajectories, not original OS telemetry. 110 calls exited nonzero and 1 timed out. All recorded calls in completed receipts remain in denominators, including unexecuted calls after a fatal replay error. There are 0 fatal replay receipts and 14 failed setup steps, including failed initial steps later recovered by a fallback. Nonzero commands can still produce effects, which are counted. Exit zero means command completion, not agreement with original test outcomes or task resolution. [dynamic_fidelity.csv](dynamic_fidelity.csv) cross-tabulates source-reported status and replay outcome, retaining unavailable source statuses. The source of each failure and original/replayed call statuses are retained in [dynamic_calls.csv](dynamic_calls.csv), [dynamic_replays.csv](dynamic_replays.csv), and external command logs. The observer error count is 3. A nonzero observer error count invalidates complete-census claims and must be resolved before treating a final sample as complete.

### Visibility definition and measured operations

A write targets a named object if its literal basename occurs as a standalone token anywhere in the original argument values, or if a visible shell-style glob matches it. Executable basenames permit PATH resolution. Inline source and editor content count as argument values. This deliberately liberal rule can match a same-named object in another directory, so it is conservative about declaring effects unnamed. A directory name alone does not enumerate descendants. [dynamic_effects.py](dynamic_effects.py) also retains strict full/relative-path matching as a sensitivity result. String truncation is classified as unresolved, rather than unnamed. An `exec` is a successful execve/execveat, not a fork. The injected dispatcher is tracked separately, and the supplied patch shim's injected Python exec is removed one-for-one from its observed helper exec count.

The eBPF observer follows tagged thread lineages using initial-namespace kernel thread IDs and resolves regular-file paths at `security_file_permission`. It counts successful VFS scalar, vectored, positioned, copied, sendfile, and clone writes. It separately records explicit VFS truncations. It excludes pipes/sockets and does not claim a census of every filesystem mutation: empty-file creation, namespace operations, memory-mapped dirtying, and some asynchronous/offloaded paths can be missed. The primary percentages concern the captured positive-byte regular-file write operations and successful execs. The first harness exec is excluded. [dynamic_calibration.csv](dynamic_calibration.csv) checks observed scalar/vector/positioned/copy/truncate/descendant behavior inside an isolated namespace. [dynamic_preflight.csv](dynamic_preflight.csv) and the `dynamic_pilot_*` CSVs retain development failures, including map overflow and a shared-cache pilot. Those pilot observations are excluded from the fixed private-cache sample. A later negative preallocation/stdout check exposed stale path attribution. File-identity guards corrected it. All earlier private-cache attempts are retained in `dynamic_diagnostic_v1_*` and excluded, and the unchanged fixed cohort was restarted with the corrected observer. [dynamic_verification.csv](dynamic_verification.csv) checks that published replay receipts share the corrected observer hash, cover the planned calls, and reconcile with raw map counts.

### Calls labeled indirect versus direct

| Static primary class | Calls | Write events | Unnamed writes | Exec events | Unnamed execs |
|---|---:|---:|---:|---:|---:|
| direct_edit | 61 | 61 | 0.00% | 0 | n/a |
| direct_shell | 27 | 70 | 74.29% | 41 | 0.00% |
| indirect | 278 | 1,892,527 | 99.95% | 7,323 | 84.28% |
| inline_code | 98 | 11,704 | 99.28% | 328 | 54.57% |
| read_only | 502 | 98 | 100.00% | 1,198 | 18.70% |
| unknown | 26 | 128,930 | 85.23% | 441 | 25.40% |

The physical validation target is a call with at least one observed unnamed write or exec. `indirect` is the positive prediction. All other primary classes are negative, including the separately reported inline-code class. The tables distinguish all recorded calls, executed calls, exit-zero calls, effects-producing calls, and the subset labeled indirect or a direct mutation. Thus command failures are visible in the main denominator, rather than being silently discarded. Precision and recall are descriptive for this replay and visibility definition.

| Call denominator | Calls | TP | FP | FN | TN | Precision | Recall |
|---|---:|---:|---:|---:|---:|---:|---:|
| all_recorded_calls | 992 | 208 | 70 | 182 | 532 | 74.8% | 53.3% |
| executed_calls | 992 | 208 | 70 | 182 | 532 | 74.8% | 53.3% |
| successful_calls | 882 | 163 | 45 | 168 | 506 | 78.4% | 49.2% |
| effectful_calls | 842 | 208 | 70 | 182 | 382 | 74.8% | 53.3% |
| indirect_vs_direct | 366 | 208 | 70 | 7 | 81 | 74.8% | 96.7% |


| Replayed framework / model | Calls | TP | FP | FN | Precision | Recall |
|---|---:|---:|---:|---:|---:|---:|
| Claude Code / fable-5 | 410 | 57 | 38 | 6 | 60.0% | 90.5% |
| Codex / gpt-5.6-sol | 180 | 49 | 1 | 130 | 98.0% | 27.4% |
| mini-SWE-agent / claude-opus-4-6 | 377 | 100 | 31 | 42 | 76.3% | 70.4% |
| mini-SWE-agent / gpt-5.2-high | 25 | 2 | 0 | 4 | 100.0% | 33.3% |


### Shell-profile sensitivity

The preserved recorded login-shell wrappers source this replay host's profile. Its `/etc/profile` executes `id` and `run-parts` ([dynamic_profile_audit.csv](dynamic_profile_audit.csv) records source hashes and matching line locations), which explains observed unnamed execs even for some read-only command bodies. These are real effects of the replayed wrapper, while the original deployment's profile is unavailable. The post-hoc filename-filter sensitivity below removes every exec whose basename is `id` or `run-parts`, whether named or unnamed. It can therefore also remove genuine project/helper executions and is not a causal origin classifier. Primary write counts are unchanged, primary exec counts retain these effects, and primary static predictions are never retuned. [dynamic_sensitivity.csv](dynamic_sensitivity.csv) and per-call helper counters retain the filter accounting.

| Cohort | Excluded execs | Remaining execs | Remaining unnamed execs | Unnamed exec fraction | Call-level precision | Call-level recall |
|---|---:|---:|---:|---:|---:|---:|
| Overall | 360 | 8971 | 6329 | 70.55% | 66.2% | 72.7% |
| Claude Code / fable-5 | 0 | 3551 | 2560 | 72.09% | 60.0% | 90.5% |
| Codex / gpt-5.6-sol | 360 | 1867 | 973 | 52.12% | 50.0% | 59.5% |
| mini-SWE-agent / claude-opus-4-6 | 0 | 3438 | 2718 | 79.06% | 76.3% | 70.4% |
| mini-SWE-agent / gpt-5.2-high | 0 | 115 | 78 | 67.83% | 100.0% | 33.3% |

[dynamic_confusion.csv](dynamic_confusion.csv) also reports unresolved truth counts and corresponding precision/recall bounds. A failed or unexecuted call is not evidence that the original deployment had no indirect effect. Unsupported tool substitution, dependency failures, malformed normalized commands, different runtime versions, SCM-derived version labels from shallow history, time limits, and initial environment differences limit transfer to original executions.

### Working-tree and cache effects

| Observed file-write location | Write operations | Unnamed operations | Distinct (call, file) pairs | Unnamed pairs |
|---|---:|---:|---:|---:|
| environment | 5,836 | 99.98% | 3,787 | 99.97% |
| home | 39,135 | 99.97% | 2,627 | 99.62% |
| package_cache | 266,587 | 99.67% | 83,394 | >99.99% |
| project_generated | 182,204 | >99.99% | 110,423 | >99.99% |
| project_other | 124,953 | 99.92% | 96,124 | 99.89% |
| system_or_other | 198 | 98.48% | 131 | 99.24% |
| temporary | 1,414,477 | 98.65% | 28,703 | 99.86% |

`project_generated` identifies conventional generated/build/cache components, including Git metadata, bytecode, virtual environments, node_modules, target, build, and dist. `project_other` covers remaining files below the project root. These are path conventions, not an intent or security judgment. Both rows are included in the project-tree fraction. Package-cache and environment writes are genuine replay effects but can dominate pooled counts. Private per-trajectory caches prevent a preceding model's replay from warming a later one. Instrumentation failures, including long-path buffer errors, trigger a retained full-sequence retry of the same task with a larger buffer. Command or setup failures alone do not trigger this instrumentation procedure. Separately, initial Astropy environment trials exposed isolated-build setuptools incompatibility and GCC 14 rejecting legacy C signatures. The primary mini cohort uses the same recorded legacy build dependencies, a no-build-isolation fallback, and GCC/G++ 12. Earlier completed or interrupted environment trials remain in `environment-attempts/` and the attempt ledger. Setup changes never apply oracle patches. [dynamic_attempts.csv](dynamic_attempts.csv) accounts for primary and excluded attempts, while [dynamic_replays.csv](dynamic_replays.csv) records the actual path-buffer size of each primary attempt. Setup effects are excluded. Disposable runtime trees are removed after source commits, command receipts, freeze records, final diffs, and observer data are saved. Full per-call object records are in the external `dynamic/effects.jsonl.gz`; [dynamic_effect_sample.csv](dynamic_effect_sample.csv) gives hash-ranked examples balanced across static class, effect kind, and path scope.

[dynamic_effects.pdf](dynamic_effects.pdf) compares distinct call-object fractions by model group and static class, with embedded TrueType fonts. [dynamic_report_metrics.csv](dynamic_report_metrics.csv) records report totals. The cohort is a paired, descriptive sample with best-effort environments, not a causal comparison of models or frameworks. [dynamic_evidence_manifest.csv](dynamic_evidence_manifest.csv) hashes retained metadata, call receipts, command logs, and observer evidence. [dynamic_host_environment.csv](dynamic_host_environment.csv) records local tool versions and analysis-source hashes.

## Static results

| Framework / recorded model | Traj. | Calls | Indirect calls | Any indirect | Write then execute | Explicit create then execute |
|---|---:|---:|---:|---:|---:|---:|
| Claude Code / fable-5 | 111 | 5,794 | 20.9% | 100.0% | 3.6% | 0.0% |
| Codex / gpt-5.6-sol | 111 | 2,209 | 33.9% | 100.0% | 0.0% | 0.0% |
| OpenHands / unattributed GPT-4o / Claude-3.5-Sonnet mixture | 491 | 8,779 | 19.3% | 99.2% | 96.3% | 95.1% |
| SWE-agent / swe-agent-llama-405b | 245 | 7,546 | 16.2% | 83.7% | 78.0% | 78.0% |
| SWE-agent / swe-agent-llama-70b | 1,000 | 25,662 | 14.5% | 71.5% | 66.8% | 66.5% |
| SWE-agent / swe-agent-llama-8b | 798 | 25,791 | 13.2% | 76.1% | 67.8% | 67.2% |
| mini-SWE-agent / claude-opus-4-6 | 200 | 5,968 | 27.5% | 93.0% | 52.5% | 0.0% |
| mini-SWE-agent / gpt-5.2-high | 200 | 7,427 | 11.8% | 97.0% | 2.5% | 0.0% |

Every call percentage uses all recorded calls/action slots in its group. The remaining columns use all sampled trajectories, including the 1 trajectory with no extracted calls. `Write then execute` includes a statically recovered earlier write to the exact normalized execution path, including ordered commands in the same call. It includes modifications of existing scripts, so it must not be described as the rate of newly authored scripts. The narrower creation column requires a dedicated create or add-file editor operation in an earlier call. Generic write tools, redirects, and `open(..., 'w')` can overwrite files and do not establish that a file was new. The column therefore undercounts new scripts and is a source-specific proxy.

The complete class shares and counts are in [summary.csv](summary.csv), with all trajectory counts in [trajectories.csv](trajectories.csv), framework aggregates in [headline.csv](headline.csv), and a stratified per-call sample of 189 rows in [sample_calls.csv](sample_calls.csv). [indirect_execution.pdf](indirect_execution.pdf) uses embedded TrueType fonts (`pdf.fonttype=42`), and [indirect_execution.png](indirect_execution.png) provides a preview.

## Sources, licenses, and sampling

The pinned releases, file hashes, compressed bytes, declared licenses, and sample sizes are in [dataset_manifest.csv](dataset_manifest.csv). [sources.json](sources.json) is the sampling configuration. Pins are content revisions, and every downloaded data file has a SHA-256 checksum. S3 objects are not version-addressed, so reproduction must check their recorded hashes rather than assume that the experiment-repository pin freezes them.

- [Nebius SWE-agent](https://huggingface.co/datasets/nebius/SWE-agent-trajectories/tree/68195a1450865274106246d0d0296a1d6807b88e): rank the published parquet filenames by SHA-256 of the committed seed and filename, take 2 shards, then take up to 1,000 trajectories per recorded model by a second hash ranking within the resulting 13,339-row pool. All action slots in selected trajectories are parsed. Smaller model groups retain every available row in the chosen shards. This is a shard sample followed by a capped model sample, not a uniform sample of the full release. The card declares CC BY 4.0 and explicitly retains repository-specific licenses and Llama model terms. We preserve the recorded model names rather than infer checkpoints beyond the release's metadata.
- [SWE-Gym OpenHands SFT](https://huggingface.co/datasets/SWE-Gym/OpenHands-SFT-Trajectories/tree/4aaa5a4a4b5861f4799d2336908760c190ac3b17): use the complete released successful-trajectory split. The card declares MIT. The [SWE-Gym paper](https://arxiv.org/abs/2412.21139) describes GPT-4o and Claude-3.5-Sonnet collection, but the released SFT rows contain messages only, so individual model and task identity are unavailable. We retain a single unattributed expert-mixture group. This release is explicitly selected for success.
- [SWE-bench experiments](https://github.com/SWE-bench/experiments/tree/40f164d5b8f1d249bf95a6df8b74b577fd8e519d): follow pinned mini-SWE-agent metadata to public S3 trajectory objects for the Opus and GPT runs in the manifest. Uniformly hash-rank instance filenames and take 200 per model. The matched instance-name ranking also pairs these samples across models. S3 access was successful. No explicit dataset license was located for these trajectory objects. The scaffold's software license is not a license for the trajectory data. We publish derived aggregates, hashes, and short command previews, and make no claim of permissive relicensing.
- [SWE-rebench native-agent release](https://huggingface.co/datasets/ibragim-bad/swe_rebench_07_2026_trajectories/tree/cdae27cdd16673f0c682871ad55d325f24cc7020): use the complete run-0 shards for Claude Code and Codex, totaling 222 trajectories. The card declares `other` and explicitly retains repository and provider terms without relicensing. This is a third-party normalized release. Framework and model identities are recorded publisher fields, not independently verified vendor provenance. Original patches are omitted by the publisher. Only derived metrics, locators, and short previews are committed here.

[availability.csv](availability.csv) records other considered sources and exclusions, including SWE-smith, MoatlessTools, and the raw OpenHands archive. No result-dependent trajectory filtering, success filtering beyond a source's published selection, or truncation of selected trajectories was applied. The seed was fixed before classification and is not an inference about representativeness.

## Operational method

[collect.py](collect.py) retrieves pinned metadata and selected shards/objects into an external raw directory. [analyze.py](analyze.py) extracts source-native calls, parses shell ASTs with bashlex, and maintains a per-trajectory path history. Recorded mini-SWE-agent harness actions take precedence over duplicate provider messages. OpenHands function XML and native structured calls are parsed separately. Nebius assistant messages contain action proposals, so they are treated as action slots. Ambiguous fenced blocks are retained as unknown, rather than choosing a convenient command. [normalization_audit.csv](normalization_audit.csv) and [extraction_audit.csv](extraction_audit.csv) expose counts by adapter and trajectory.

The mutually exclusive classes are:

| Class | Operational meaning |
|---|---|
| `direct_edit` | A dedicated editor/create/patch operation explicitly names a path. |
| `context_edit` | SWE-agent line-range editing relies on an open-file path from prior feedback. |
| `direct_shell` | Shell syntax names a mutation, such as a redirect, shell mutator, or Git operation. |
| `indirect` | Executes a file/script/module, project executable, build/test/package/lint tool, or dynamic shell dispatch. Its entrypoint is named, while additional effects require runtime/code reasoning. |
| `inline_code` | Inline interpreter code requires code analysis. It stays separate even if it names a literal write path. |
| `read_only` | Reads, searches, editor views, shell control, and polling. |
| `unknown` | Unrecognized tools/commands, parser failures, or ambiguous extraction. |

For combined shell calls the primary priority is indirect, inline code, unknown, named shell mutation, then read/control. A call can therefore have both explicit write paths and an indirect primary label. Read-only pipelines do not become indirect merely because they contain a pipe. Shell wrappers with inline shell bodies are parsed recursively. Heredoc source bodies passed to writers are data, rather than executed shell commands. The parser normalizes simple quoted heredoc delimiters to work around bashlex's delimiter handling. Unknown options, shell expansion, aliases, generic project CLIs, and unsupported syntax can cause unknowns or misses. A runner's presence is potential execution, including syntactically present branches, rather than proof that it ran successfully.

Writes are recovered from dedicated editor paths, SWE-agent feedback state, literal redirects, selected shell writers, and literal Python `open`/Path write expressions with limited string propagation. No source is executed. The Python analysis skips function/class bodies. We resolve exact paths using observed `cd`, tool working directories, or source-reported cwd. Missing cwd gets a separate unknown-root namespace. `Write then execute` requires an interpreter/script execution path matching that history, or a writer command preceding an execution command in the same shell AST. Failed writes identified from feedback do not enter cross-call history. A successful combined-call return code is imperfect evidence for every constituent command. We separately publish earlier-call, same-call, and feedback-confirmed counts. We do not trace imported modules, test-discovered files, symlinks, environment-derived paths, or generated script contents through arbitrary transformations.

For existing project code, `any_project_runner` and `any_no_prior_write_script` in [summary.csv](summary.csv) provide separate trajectory proxies. The former observes build/test/package/module entrypoints. The latter observes an explicit script execution with no recovered earlier write. These percentages use sampled trajectories:

| Framework / recorded model | Any project/module/runner entrypoint | Any script with no recovered earlier write |
|---|---:|---:|
| Claude Code / fable-5 | 100.0% | 17.1% |
| Codex / gpt-5.6-sol | 100.0% | 8.1% |
| OpenHands / unattributed GPT-4o / Claude-3.5-Sonnet mixture | 10.8% | 1.2% |
| SWE-agent / swe-agent-llama-405b | 10.6% | 0.8% |
| SWE-agent / swe-agent-llama-70b | 7.7% | 1.9% |
| SWE-agent / swe-agent-llama-8b | 9.8% | 3.9% |
| mini-SWE-agent / claude-opus-4-6 | 91.5% | 46.0% |
| mini-SWE-agent / gpt-5.2-high | 96.5% | 13.0% |

Missing a prior write does not prove pre-existence, and neither metric measures side effects attributable to existing code. The flags can overlap within a trajectory. Package tools may run downloaded code, and project runners also execute dependencies.

The parser retained 4,404 unknown calls/action slots, including 1,015 shell parse failures. There were 23,037 calls with failure evidence and 32,430 with unavailable/uncertain success status. These are retained in call denominators. The source feedback is not a complete success oracle. [download_failures.csv](download_failures.csv) records download failures/retries, including an explicit no-failures marker when applicable.

For comparison, the following shares require success evidence for an indirect call or for the execution after a recovered earlier write. They still do not establish OS side effects. SWE-agent shell feedback often lacks an exit code, so its success-conditioned rates can be lower through missing status alone. Explicit tool statuses and recorded exit codes take precedence over text heuristics.

| Framework / recorded model | Distinct known task IDs | Any indirect call with success evidence | Any execution with success evidence after recovered write |
|---|---:|---:|---:|
| Claude Code / fable-5 | 111 | 100.0% | 2.7% |
| Codex / gpt-5.6-sol | 111 | 98.2% | 0.0% |
| OpenHands / unattributed GPT-4o / Claude-3.5-Sonnet mixture | unavailable | 92.7% | 89.6% |
| SWE-agent / swe-agent-llama-405b | 20 | not recorded | not recorded |
| SWE-agent / swe-agent-llama-70b | 414 | not recorded | not recorded |
| SWE-agent / swe-agent-llama-8b | 95 | not recorded | not recorded |
| mini-SWE-agent / claude-opus-4-6 | 200 | 91.0% | 51.0% |
| mini-SWE-agent / gpt-5.2-high | 200 | 96.5% | 1.5% |

[trajectory_quality.csv](trajectory_quality.csv) also records unavailable instance identities, repeated known instance IDs, and repeated recovered action sequences. These rows are retained. Identical recovered actions do not necessarily imply identical source trajectories, especially where ambiguous source actions yielded unknown arguments. Because shard sampling can concentrate repeated attempts on a small set of tasks, [task_balanced_summary.csv](task_balanced_summary.csv) provides a sensitivity analysis that gives each known task equal weight. Call shares are averaged across per-task call shares, while trajectory flags are averaged within task before averaging across tasks. Task identity is unavailable for the SFT mixture, so its task-balanced fields are blank. [verification.csv](verification.csv) records successful cross-checks of source file hashes, adapter coverage, per-call locators, trajectory and group totals, and the frozen validation predictions.


## Validation and dynamic-replay feasibility

The initial static pass used the model-annotation fallback while replay infrastructure was unavailable. The follow-up installed bpftrace and local toolchains and used isolated local namespaces, without Docker or changes to cluster services, the gateway, Coder, or model deployments. An all-match ActPlane notify policy is another observer option. This study uses successful-operation eBPF probes for its dynamic denominator.

[validation_labels.csv](validation_labels.csv) contains independent labels from `qwen3.8-27b-nvfp4` and `zai/glm-5.3-flash`, using the exact prompt in [validation_prompt.txt](validation_prompt.txt). Model identities were verified by model listing and response fields. Each rater saw the full tool arguments and working-directory/editor context, without heuristic labels, heuristic reasons, feedback, or the other rater's output. We froze a deterministic sample of 100 calls: equal samples of 50 predicted-indirect calls and 50 other calls, with 10 calls in each framework-by-prediction stratum. The classifier's primary labels were frozen before annotations, and subsequent author-history changes did not alter that sample or its class predictions.

The raters agreed on the full label for 99.0% of calls (Cohen's kappa 0.984) and on indirect versus other for 99.0% (kappa 0.980). For predicted-indirect calls, population-stratum-weighted agreement with each rater was 98.7% and 99.5%. The two-rater consensus envelope for this operational precision is 98.7% to 99.5%. Allowing stratified sampling uncertainty gives a conservative simultaneous confidence envelope of 72.0% to 100.0% at the 95% level using stratified Hoeffding bounds. This is agreement with model judgments, not a bound on physical side-effect visibility or shared model errors. [validation_confusion.csv](validation_confusion.csv) retains all disagreements. The run used 200 attempts, including 0 unsuccessful attempts, all retained in [annotation_attempts.csv](annotation_attempts.csv). No majority adjudication or heuristic tuning to these answers was performed.
The reviewed disagreements include read-only grep pipelines dispatched by xargs and a malformed nested-shell command whose intended Java compilation/execution was recognizable to both raters. The conservative xargs rule can therefore count read-only dispatch as indirect, while strict shell parsing can miss intended project execution. The spot check does not validate the separate write-history/authorship metric.

## Limitations and permitted interpretation

This is a descriptive sample of public benchmark and training trajectories. Models, harness versions, languages, prompts, budgets, and success selection differ, so the rows do not identify causal framework/model effects. The OpenHands and SWE-agent prompts encourage reproduction scripts, which can increase write-then-execute frequency. Native transcripts are publisher-normalized, and the older text-action format can contain proposals that the environment rejected. Multiple calls may be retries of the same action. No call weighting reconstructs real-world deployment prevalence.

The static indirect class is a **potential execution surface**. The dynamic section separately identifies captured unnamed effects. Neither identifies a real deployed guardrail miss or a policy violation. Inline programs are excluded from the headline indirect fraction because their literal arguments can contain target names. Unknown calls and indirect effects hidden behind apparently direct operations, such as Git hooks or editor internals, mean the class shares do not bound actual OS effects. The model spot check evaluates the stated static categories and can share systematic errors. The write-history analysis is incomplete and does not establish authorship of an entire script.

## Reproduction and outputs

From this directory, with a dedicated virtual environment and an external writable raw directory:

```bash
python3 -m pip install -r requirements.txt
python3 collect.py --raw "$RAW"
python3 analyze.py --raw "$RAW"
python3 probe.py --raw "$RAW"
python3 validate.py --raw "$RAW"
python3 verify.py --raw "$RAW"
python3 report.py
python3 -m pytest -q test_analyze.py test_dynamic.py
```

The annotation command requires `LITELLM_BASE_URL` and `LITELLM_API_KEY` for the named GLM model, plus access to the named direct Qwen endpoint. It keeps at most 4 requests concurrent and never writes credentials. Completed annotations are cached. Transport/format failures get up to 3 attempts and are retained. Full arguments, feedback excerpts, model responses, normalized sampled trajectories, and logs remain under the external raw directory. The committed call sample contains source locators and hashes to recover full arguments without redistributing whole trajectories.

At the last [resource measurement](resources.csv), raw files occupied 0.362 GB, under the 25 GB limit, and workspace disk use was 36.8%, below 85%. [method_metrics.csv](method_metrics.csv) records report constants and derived totals. All quantitative claims in this README are generated by this script from committed CSVs. Source versions, licensing statements, and sampling decisions are recorded in the manifest, configuration, and availability audit.

The requested `oss-change-workflow` skill was absent from the available catalog and filesystem search. We followed the scope, validation, synchronized docs/results, and branch workflow stated in AGENTS.md and the operator update. Results are handed off on the experiment branch. This study changes only this output directory and does not edit the paper.

## Dynamic replay reproduction

The replay requires Linux tracing privileges, BTF, bpftrace, bubblewrap, a C compiler, Git, and relevant language toolchains. This run installed bpftrace, OpenJDK, Maven, Go, pnpm, yarn, and legacy GCC/G++ locally. Host/package versions and per-trajectory setup receipts are retained. Python interpreter versions are pinned in [dynamic_config.json](dynamic_config.json).

```bash
python3 dynamic_prepare.py --raw "$RAW"
UV_PYTHON_INSTALL_DIR="$RAW/dynamic/toolchains" UV_PYTHON_BIN_DIR="$RAW/dynamic/toolbin" uv python install 3.9.25 3.12.16
python3 dynamic_run.py --raw "$RAW"
python3 dynamic_retry.py --raw "$RAW"
python3 dynamic_calibrate.py --raw "$RAW"
python3 dynamic_effects.py --raw "$RAW"
python3 dynamic_attempts.py --raw "$RAW"
python3 dynamic_verify.py --raw "$RAW" --require-complete
python3 dynamic_provenance.py --raw "$RAW"
python3 probe.py --raw "$RAW" --local-only
python3 report.py
```

The committed sample plan and task metadata hashes identify exact repository base commits. Environment setup runs outside the observed lineage and its failures are recorded. Shell calls use their recorded text, with only a coordinator exit trap to recover cwd and status. Dedicated read/search tools use bounded in-process substitutes. Edit-tool behavior is the committed substitute implementation, so proprietary tool internals are not reconstructed. Recreated source checkouts, dependency trees, and caches are disposable after final diffs, version/freeze receipts, source commits, logs, and observer maps are retained. Raw evidence stays in the external raw directory. Resource snapshots are in [dynamic_resource_samples.csv](dynamic_resource_samples.csv), which samples disk use rather than claiming a continuous maximum.

## Paper-ready motivation paragraph

Dynamic validation is in progress. The current 31 replay receipts contain 3 observer errors. Paper-ready quantitative replay claims are withheld until the same affected trajectories have been replayed with corrected instrumentation. All earlier attempts remain recorded, and no sampled task is replaced based on command or setup success.
