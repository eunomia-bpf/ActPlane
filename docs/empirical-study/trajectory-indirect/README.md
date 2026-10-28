# Indirect execution in public coding-agent trajectories

**Measured:** static execution patterns in 3,156 trajectories and 89,176 recorded tool calls/action slots from 5 frameworks and 8 recorded model groups. **Not measured:** the fraction of actual file mutations or process executions whose targets are missing from tool arguments. There was no dynamic replay, so this study cannot supply that OS-event denominator.

## Results

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

[probe.py](probe.py) records that the installed Docker client cannot reach a daemon, and that bpftrace is unavailable. No replay environment was provisioned and no service or deployment was changed. Without task images and a replay sandbox, an OS-effect fraction cannot be measured here. The ActPlane policy engine's match-only event stream would also require extra instrumentation for an all-writes/all-execs denominator. We used the requested model-annotation fallback instead.

[validation_labels.csv](validation_labels.csv) contains independent labels from `qwen3.8-27b-nvfp4` and `zai/glm-5.3-flash`, using the exact prompt in [validation_prompt.txt](validation_prompt.txt). Model identities were verified by model listing and response fields. Each rater saw the full tool arguments and working-directory/editor context, without heuristic labels, heuristic reasons, feedback, or the other rater's output. We froze a deterministic sample of 100 calls: equal samples of 50 predicted-indirect calls and 50 other calls, with 10 calls in each framework-by-prediction stratum. The classifier's primary labels were frozen before annotations, and subsequent author-history changes did not alter that sample or its class predictions.

The raters agreed on the full label for 99.0% of calls (Cohen's kappa 0.984) and on indirect versus other for 99.0% (kappa 0.980). For predicted-indirect calls, population-stratum-weighted agreement with each rater was 98.7% and 99.5%. The two-rater consensus envelope for this operational precision is 98.7% to 99.5%. Allowing stratified sampling uncertainty gives a conservative simultaneous confidence envelope of 72.0% to 100.0% at the 95% level using stratified Hoeffding bounds. This is agreement with model judgments, not a bound on physical side-effect visibility or shared model errors. [validation_confusion.csv](validation_confusion.csv) retains all disagreements. The run used 200 attempts, including 0 unsuccessful attempts, all retained in [annotation_attempts.csv](annotation_attempts.csv). No majority adjudication or heuristic tuning to these answers was performed.
The reviewed disagreements include read-only grep pipelines dispatched by xargs and a malformed nested-shell command whose intended Java compilation/execution was recognizable to both raters. The conservative xargs rule can therefore count read-only dispatch as indirect, while strict shell parsing can miss intended project execution. The spot check does not validate the separate write-history/authorship metric.

## Limitations and permitted interpretation

This is a descriptive sample of public benchmark and training trajectories. Models, harness versions, languages, prompts, budgets, and success selection differ, so the rows do not identify causal framework/model effects. The OpenHands and SWE-agent prompts encourage reproduction scripts, which can increase write-then-execute frequency. Native transcripts are publisher-normalized, and the older text-action format can contain proposals that the environment rejected. Multiple calls may be retries of the same action. No call weighting reconstructs real-world deployment prevalence.

The indirect class is a **potential execution surface**, not a finding that a mutation occurred, that a specific object was unnamed, or that a real guardrail missed it. Inline programs are excluded from the headline indirect fraction because their literal arguments can contain target names. Unknown calls and indirect effects hidden behind apparently direct operations, such as Git hooks or editor internals, mean the class shares do not bound actual OS effects. The model spot check evaluates the stated static categories and can share systematic errors. The write-history analysis is incomplete and does not establish authorship of an entire script.

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
python3 -m pytest -q test_analyze.py
```

The annotation command requires `LITELLM_BASE_URL` and `LITELLM_API_KEY` for the named GLM model, plus access to the named direct Qwen endpoint. It keeps at most 4 requests concurrent and never writes credentials. Completed annotations are cached. Transport/format failures get up to 3 attempts and are retained. Full arguments, feedback excerpts, model responses, normalized sampled trajectories, and logs remain under the external raw directory. The committed call sample contains source locators and hashes to recover full arguments without redistributing whole trajectories.

At the last [resource measurement](resources.csv), raw files occupied 0.362 GB, under the 25 GB limit, and workspace disk use was 36.8%, below 85%. [method_metrics.csv](method_metrics.csv) records report constants and derived totals. All quantitative claims in this README are generated by this script from committed CSVs. Source versions, licensing statements, and sampling decisions are recorded in the manifest, configuration, and availability audit.

The requested `oss-change-workflow` skill was absent from the available catalog and filesystem search. We followed the scope, validation, synchronized docs/results, and branch workflow stated in AGENTS.md and the operator update. Results are handed off on the experiment branch. This study changes only this output directory and does not edit the paper.

## Paper-ready motivation paragraph

Indirect execution is common in public coding-agent trajectories. In a reproducible sample of 3,156 trajectories from 5 frameworks covering 8 recorded model groups, static analysis identified script, module, build, test, or package execution in 71.5% to 100.0% of trajectories per group. These calls account for 11.8% to 33.9% of recorded calls within a group, excluding inline programs from the indirect category. We also observed agents executing files they had written earlier, including within a combined shell call. Such calls expose an entrypoint without enumerating the objects that its execution may affect, motivating enforcement at the operating-system boundary. These measurements characterize recorded execution patterns, rather than the fraction of actual file writes or process creations whose targets are absent from tool arguments.
