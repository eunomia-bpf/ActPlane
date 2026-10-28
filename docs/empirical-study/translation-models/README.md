# Policy translation across models

Results on branch `experiments/translation-models-20261028`. The operator will
consolidate lane branches. No pull request is created or updated by this lane.

The planned scope is 7 accessible model configurations, 38
behavioral policies with 190 traces (114 violation, 76
compliant), and a separate 607-policy compilation corpus. Counts in
the table are completed trials, so partial rows must not be read as full-corpus
rates. Detection, false-trigger rate, and F1 remain unavailable unless every planned
trace has an outcome. The reference row is a supplied translation, not a new
model-generation trial. The behavioral sample covers
15 repositories, while compilation covers
62. The corpora share
10 repository/statement identifiers and
1 exact directive texts. They are not disjoint
held-out sets, and no semantic deduplication is claimed.

| Model | Sample compile@1 / @3 | Corpus compile@1 / @3 | Detection | False trigger | F1 | Access failures (sample / corpus) | Sample USD/policy |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Paper reference | 38 / 38 of 38 | not generated | 70.2% | 17.1% | 0.773 | 0 / 0 | n/a |
| qwen3.8-27b-nvfp4 | 15 / 26 of 38 | 0 / 0 of 0 | 40.4% | 10.5% | 0.548 | 0 / 0 | n/a |
| zai/glm-5.3 | 34 / 38 of 38 | 0 / 0 of 0 | 43.0% | 13.2% | 0.566 | 0 / 0 | $0.0327 |
| zai/glm-5.3-flash | 33 / 38 of 38 | 0 / 0 of 0 | 48.2% | 15.8% | 0.608 | 0 / 0 | $0.0040 |
| zai/glm-4.7-flash | 10 / 13 of 38 | 0 / 0 of 0 | unavailable | unavailable | unavailable | 25 / 0 | $0.0000 |
| zai/glm-4.5-air | 33 / 38 of 38 | 0 / 0 of 0 | 50.9% | 13.2% | 0.637 | 0 / 0 | $0.0066 |
| gpt-6-astra | 27 / 38 of 38 | 0 / 0 of 0 | 43.0% | 18.4% | 0.554 | 0 / 0 | $0.3112 |
| claude-opus-4-6 | 30 / 38 of 38 | 0 / 0 of 0 | unavailable | unavailable | unavailable | 0 / 0 | $0.1384 |

| Model | Direct detected / replayed | Script detected / replayed | Hidden detected / replayed | Replay errors | Tool-error traces |
| --- | --- | --- | --- | --- | --- |
| Paper reference | 27 / 38 | 27 / 38 | 26 / 38 | 0 | 2 |
| qwen3.8-27b-nvfp4 | 15 / 38 | 16 / 38 | 15 / 38 | 0 | 1 |
| zai/glm-5.3 | 16 / 38 | 18 / 38 | 15 / 38 | 0 | 2 |
| zai/glm-5.3-flash | 18 / 38 | 19 / 38 | 18 / 38 | 0 | 2 |
| zai/glm-4.7-flash | 9 / 13 | 9 / 13 | 9 / 13 | 0 | 0 |
| zai/glm-4.5-air | 19 / 38 | 20 / 38 | 19 / 38 | 0 | 2 |
| gpt-6-astra | 17 / 38 | 16 / 38 | 16 / 38 | 0 | 2 |
| claude-opus-4-6 | 0 / 0 | 0 / 0 | 0 / 0 | 0 | 0 |

| Model | Usable outcomes / planned | Compiled-rule traces | Compiled-only detection | Compiled-only false trigger | Compiled-only F1 |
| --- | --- | --- | --- | --- | --- |
| Paper reference | 190 / 190 | 190 | 70.2% | 17.1% | 0.773 |
| qwen3.8-27b-nvfp4 | 190 / 190 | 130 | 59.0% | 15.4% | 0.697 |
| zai/glm-5.3 | 190 / 190 | 190 | 43.0% | 13.2% | 0.566 |
| zai/glm-5.3-flash | 190 / 190 | 190 | 48.2% | 15.8% | 0.608 |
| zai/glm-4.7-flash | 65 / 190 | 65 | 69.2% | 38.5% | 0.711 |
| zai/glm-4.5-air | 190 / 190 | 190 | 50.9% | 13.2% | 0.637 |
| gpt-6-astra | 190 / 190 | 190 | 43.0% | 18.4% | 0.554 |
| claude-opus-4-6 | 0 / 190 | 0 | unavailable | unavailable | unavailable |

| Model | Sample policies with reported cutoff | Corpus policies with reported cutoff | Sample terminal output-limit failures | Corpus terminal output-limit failures |
| --- | --- | --- | --- | --- |
| qwen3.8-27b-nvfp4 | 22 | 0 | 12 | 0 |
| zai/glm-5.3 | 0 | 0 | 0 | 0 |
| zai/glm-5.3-flash | 2 | 0 | 0 | 0 |
| zai/glm-4.7-flash | 1 | 0 | 0 | 0 |
| zai/glm-4.5-air | 2 | 0 | 0 | 0 |
| gpt-6-astra | 0 | 0 | 0 | 0 |
| claude-opus-4-6 | 0 | 0 | 0 | 0 |

API output is capped at 8192 tokens, including reported reasoning.
This budget constrains these deployment configurations. Reported cutoffs
are separated from other compiler failures. CLI stop reasons are not always
reported, so a zero known cutoff count does not establish absence of truncation.
The results do not measure unconstrained model capability.

Compiled-only scores use successfully compiled and replayed policies. This
selection can bias comparisons. Coverage-conditioned end-to-end scores are
also retained in the CSV. Headline end-to-end scores require complete outcomes.
A final compiler failure supplies no policy and is an end-to-end nondetection.
An API/identity failure or failed kernel load has an unknown behavioral outcome.

The reference replay currently has 190 usable outcomes
and 0 engine/replay errors. Among comparable artifact
outcomes, 156 of 190 agree with
the original RQ2 artifact's `setup_fired`. This comparison uses kernel detections,
not the artifact's recovery scores or trajectory judges. Per-policy agreement and
every disagreement appear in `reference-validation-policies.csv` and
`reference-disagreements.csv`. Differences can arise from recovered fixtures, the
current compiler, and the experimental backend, so replay does not perfectly
isolate backend fidelity. All 190 of
190 trace snapshots match the original result records.
Among script-family disagreements, 21
had a nonzero tool return code in the original setup and none in this replay.
The execution audit records these environment differences without inferring
why an original command failed. The original artifact's
reference detections were themselves imperfect against the trace labels:
66 of 114
violations detected, 17 of
76 compliant traces triggered, and
F1 0.670. Those preserved outcomes appear in
`artifact-reference-detections.csv` and are not a new model-comparison row.

## Method

`prepare.py` exports frozen inputs without checking out artifact branches.
The artifact commit is `63db86945c9b8618a46aa68c8de214bc4b8343d9`. The DSL reference is
`origin/master:docs/rule-language.md`, SHA-256 `497d717a33d1343338984cd3c80c769d42fb0d5001881768b1ef1a7aec694e95`. Its artifact
counterpart has SHA-256 `0c6f00d81a4438a0a54903bdb5acdd1199b7a07f178e3d199b51f68551f92536`. The current CLI was
built from master commit `bb89c77bcb29cfa81ba1fb212b5634c353c7352b`. Binary hashes
are in `provenance.csv`.

`translate.py` supplies the directive, source evidence, complete root instruction
files available in the artifact, and DSL reference. It never supplies reference
rules, traces, labels, or judge outputs. Each policy gets one initial returned translation response
and up to two compiler-feedback revisions. Only a surrounding Markdown fence is
removed. There is no syntax repair, policy tuning against traces, agent recovery,
or LLM judge. Every response must identify the requested model. Gateway identifiers
are response assertions, not independent verification of deployed weights.
API calls use deterministic temperature and an output-token cap. CLI wrapper
defaults differ and add context overhead. Claude uses a pinned model with tools,
skills, hooks, and MCP disabled. The OpenAI row uses response-verified GPT-6 Astra
through `codex exec`, selected as the strongest served model after checking the
account model catalog and probing. The paper's original RQ1 translator was
GPT-5.5, which this account rejects. This substitution follows the operator update.
Codex identity comes from incoming server `response.model` fields captured by
protocol-only tracing. Warmup responses with `generate=false` are excluded from
inference counts. A scored call must contain exactly one inference and no tool
outputs. Raw transport frames are discarded to avoid retaining session state.

Compiler acceptance requires an emitted blob and a nonempty rule set. Compile
yield uses all attempted policies as its denominator, including access failures.
Response-only acceptance rates and identity failures are separate CSV fields,
so provider availability is not presented as a syntax failure. Terminal
failure categories in `failure-counts.csv` use explicit model-declared
unobservability, provider-reported output truncation, or compiler-message heuristics.
Output truncation counts are also retained per attempt and per policy. They are not semantic judgments. The CLI's
blob and JSON-report modes are called separately. Provider overload retries are
recorded separately from compiler revisions. Each model has a bounded transport
retry budget for missing responses. API calls use parallel workers per model,
with local endpoint concurrency within the operator limit. Latency is observed
under shared serving load and the recorded scripts' worker limits, rather than
an isolated model-speed benchmark. Per-policy wall time includes observed
attempts and scheduled transport backoff, excluding interruption gaps. Token counts include all completed
model responses, including reasoning and compiler revisions. `prices.csv` records
the [ZAI list prices](https://docs.z.ai/guides/overview/pricing) and
[Claude list prices](https://platform.claude.com/docs/en/about-claude/pricing), and
[OpenAI list prices](https://developers.openai.com/api/docs/models/gpt-6-astra).
Dollar values are uncached API equivalents, including for the subscription CLI,
not bills. Local infrastructure cost is unmeasured. Transport failures without
usage cannot be assigned an inferred token charge. Reported token and dollar
means cover recorded usage only, with missing-usage transport counts in the CSV.
These are incomplete accounting values when requests time out.

`replay.py` starts a fresh kernel engine and independent repository copy per
trace. Tool effects follow the artifact's passive replay implementations for
Read, Write, Edit, and Bash. Effects become notify so the complete trace can run.
Predicates, labels, conditions, and reasons remain fixed. The root receives the
same AGENT/COMMAND label convention as the CLI. Each worker has private network
and mount namespaces, a short `/tmp/repo` bind mount, artifact safety shims, and
an environment without credentials. Relative Bash and file-changing tool paths
are preserved. Read uses an absolute path, as in the original harness.
Selected fixture archives are hash-recorded in `fixture-packs.csv` and unpacked
into fresh guest-local tmpfs checkouts. Earlier shared-filesystem replays are
diagnostics. All scored rows use the same guest-local fixture filesystem.
Harness tool-result logs are buffered and flushed only after the engine stops,
using a pipe completion handshake. Actual tool subprocess stdout is preserved.
Earlier smoke runs with monitored harness logging are diagnostic only.

Host replay is invalid because userspace PID seeding and kernel-visible PIDs
differ in this container. The recorded Linux guest avoids that mismatch. The
unmodified current engine also exceeds verifier limits on corpus path matchers.
`build_loader.py` builds an experiment-only engine copy with bounded suffix and
substring matchers and inlined file-source wrappers. It leaves repository product
code and the ABI unchanged. Native checks compare the actual experimental matcher
branch against the original predicates with simulated BPF helpers:
400000 cases, 0 mismatches. These checks are not a
whole-engine equivalence proof. Expanded guest controls pass 9 of
9, including positive/negative write checks and read-before-write
label propagation. Parallel controls pass 9 of
9 with separate simultaneous engine instances. All scored models and references use this same engine build.
Per-trace loader and fixture hashes identify the actual configuration.

Original evaluated source checkout SHAs are absent from the artifact. Candidate
sources are recorded instruction-file commits, commits before the artifact date,
and explicitly recorded extra candidates. `select_fixtures.py` selects per-policy
sources by Read/Edit preconditions, never detection outcomes or labels. The
selected fixtures satisfy 28 of 28 Edit literal preconditions and
118 of 118 Read path preconditions. No trace is rewritten. Tool
errors remain visible because successful command invocation does not imply that
the intended forbidden side effect occurred.

## Exclusions and limitations

* `glm-5.3-flash-nvfp4`: {"error":"Unauthorized"}
* `qwen3.8-flash-next-nvfp4`: {"error":"Unauthorized"}
* `opencode-go/gpt-5.6-luna`: {"error":{"message":"litellm.AuthenticationError: AuthenticationError: OpenAIException - This API key has expired. Create a new API key in OpenCode Console and replace it in your client or secret store. Signing in again will not renew this key.. Received Model Group=opencode-go/gpt-5.6-luna\nAvailable Model Group Fallbacks=None","type":null,"param":null,"code":"401"}}
* `opencode-go/grok-4.6`: {"error":{"message":"litellm.AuthenticationError: AuthenticationError: OpenAIException - This API key has expired. Create a new API key in OpenCode Console and replace it in your client or secret store. Signing in again will not renew this key.. Received Model Group=opencode-go/grok-4.6\nAvailable Model Group Fallbacks=None","type":null,"param":null,"code":"401"}}
* `gpt-5.5`: {"type":"error","status":400,"error":{"type":"invalid_request_error","message":"The 'gpt-5.5' model is not supported when using Codex with a ChatGPT account.","code":"model_not_found"}}

The preserved `invalid-protocol-calls.csv` audits an interrupted preliminary run
whose compiler invocation combined incompatible CLI flags. Those calls are not
model failures or scored trials. Raw responses remain in `invalid-protocol/`.
Interrupted requests with unknown usage are preserved in `interrupted-requests.csv`.
Kernel smoke failures are retained separately as diagnostics. Failed engine loads
are never counted as true negatives. The behavioral sample is small, constructed,
and selected for OS observability. It is not a held-out natural policy population.
Prior paper translators can have corpus familiarity. Recovered fixtures, notify
effects, compiler approximations, syscall visibility, wrapper behavior, and model
serving defaults limit causal claims about translation quality alone. Compilation
success does not establish faithful semantics or DSL expressivity.

## Reproduction and artifacts

Raw data: `/workspaces/.agent-state/actplane-research/raw/translation-models-20261028`.
The directory contains prompts, responses, compiler reports, fixtures, verifier
logs, and per-trace tool/kernel logs. The repository contains scripts and compact
CSVs, `summary.csv`, `comparison.pdf`, and `table.tex`. The figure uses embedded
TrueType fonts. Model access and infrastructure are never changed by this study.

```bash
make
make test
python3 docs/empirical-study/translation-models/prepare.py --as-of 2026-06-07T00:00:00Z
python3 docs/empirical-study/translation-models/extra_candidates.py
python3 docs/empirical-study/translation-models/select_fixtures.py
python3 docs/empirical-study/translation-models/pack_fixtures.py
python3 docs/empirical-study/translation-models/models.py
python3 docs/empirical-study/translation-models/select_openai.py
python3 docs/empirical-study/translation-models/build_loader.py
python3 -m unittest discover -s docs/empirical-study/translation-models -p 'test_*.py'
```

`guest.py` runs `controls.py`, then `replay.py` for references or translated rules.
`translate.py --corpus rq2` and `--corpus rq1` resume completed trials.
`compile_references.py`, `prices.py`, `summarize.py`, and `report.py` regenerate
derived outputs. No script opens or updates a pull request.

## Paper paragraph

We compare policy translation across 7 response-verified model configurations using a shared DSL reference and compiler feedback. The behavioral sample contains 38 repository policies and 190 labeled traces, including 114 violations and 76 compliant traces. We replay tool effects under the kernel engine without agent continuation or model judges. Completed model rows attain F1 from 0.548 to 0.637. Configured output budgets and CLI defaults also affect these rates. Compiler acceptance on the 607-policy corpus measures syntactic compatibility rather than semantic correctness. Reference agreement and replay failures are reported separately because backend behavior and fixture fidelity can also affect detection.
