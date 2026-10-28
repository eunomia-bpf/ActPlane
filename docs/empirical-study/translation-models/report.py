#!/usr/bin/env python3
"""Render the README, paper snippet, and TrueType PDF from committed CSV schemas."""
import csv
import textwrap

import matplotlib
matplotlib.use('Agg')
matplotlib.rcParams['pdf.fonttype'] = 42
matplotlib.rcParams['ps.fonttype'] = 42
import matplotlib.pyplot as plt

from prepare import HERE, DEFAULT_RAW, csv_write

NAMES = {'reference': 'Paper reference', **{m: m for m in (
    'qwen3.8-27b-nvfp4', 'zai/glm-5.3', 'zai/glm-5.3-flash',
    'zai/glm-4.7-flash', 'zai/glm-4.5-air', 'gpt-6-astra', 'claude-opus-4-6')}}


def read(name):
    p = HERE / name
    return list(csv.DictReader(p.open())) if p.exists() else []


def pct(value):
    return f'{100*float(value):.1f}%' if value != '' else 'unavailable'


def main():
    all_rows = read('summary.csv')
    rows = [r for r in all_rows if r['access_status'] in ('ok', 'reference')]
    counts = {r['corpus']: int(r['policies']) for r in read('corpus-counts.csv')}
    overlap = read('corpus-overlap.csv')[0]
    settings = read('model-settings.csv')
    api_cap = next(r['api_max_output_tokens'] for r in settings if r['model'] == 'qwen3.8-27b-nvfp4')
    traces = read('trace-manifest.csv')
    positive = sum(int(r['violation']) for r in traces)
    negative = len(traces) - positive
    access = read('model-access.csv')
    available = sum(r['status'] == 'ok' and r['identity_verified'] == '1' for r in access)
    provenance = read('provenance.csv')[0]
    native = read('matcher-equivalence.csv')[0]
    controls = read('controls-guest68-scored-v3.csv')
    parallel_controls = read('controls-guest68-parallel-v3.csv')
    parallel_passes = sum(r['control_passed'] == '1' for r in parallel_controls)
    control_passes = sum(r['control_passed'] == '1' for r in controls)
    table = ['| Model | Sample compile@1 / @3 | Corpus compile@1 / @3 | Detection | False trigger | F1 | Access failures (sample / corpus) | Sample USD/policy |',
             '| --- | --- | --- | --- | --- | --- | --- | --- |']
    for r in rows:
        sample = f"{r['rq2_compiled_at_1']} / {r['rq2_compiled_at_3']} of {r['rq2_completed']}"
        corpus = f"{r['rq1_compiled_at_1']} / {r['rq1_compiled_at_3']} of {r['rq1_completed']}" if r['model'] != 'reference' else 'not generated'
        cost = f"${float(r['rq2_uncached_list_usd_mean']):.4f}" if r['rq2_uncached_list_usd_mean'] != '' else 'n/a'
        f1 = f"{float(r['f1']):.3f}" if r['f1'] != '' else 'unavailable'
        table.append(f"| {NAMES.get(r['model'], r['model'])} | {sample} | {corpus} | {pct(r['detection_rate'])} | {pct(r['false_trigger_rate'])} | {f1} | {r['rq2_access_failures']} / {r['rq1_access_failures']} | {cost} |")
    families = ['| Model | Direct detected / replayed | Script detected / replayed | Hidden detected / replayed | Replay errors | Tool-error traces |',
                '| --- | --- | --- | --- | --- | --- |']
    for r in rows:
        families.append('| ' + ' | '.join([NAMES.get(r['model'], r['model'])] +
                         [f"{r[f + '_detected']} / {r[f + '_n']}" for f in ('direct', 'script', 'hidden')] +
                         [r['replay_errors'], r['tool_error_traces']]) + ' |')
    budgets = ['| Model | Sample policies with reported cutoff | Corpus policies with reported cutoff | Sample terminal output-limit failures | Corpus terminal output-limit failures |',
               '| --- | --- | --- | --- | --- |']
    for r in rows:
        if r['model'] != 'reference':
            budgets.append(f"| {NAMES[r['model']]} | {r['rq2_truncated_policies']} | {r['rq1_truncated_policies']} | {r['rq2_output_limit_failures']} | {r['rq1_output_limit_failures']} |")
    coverage = ['| Model | Usable outcomes / planned | Compiled-rule traces | Compiled-only detection | Compiled-only false trigger | Compiled-only F1 |',
                '| --- | --- | --- | --- | --- | --- |']
    for r in rows:
        cf1 = f"{float(r['compiled_rule_f1']):.3f}" if r['compiled_rule_f1'] != '' else 'unavailable'
        coverage.append(f"| {NAMES.get(r['model'], r['model'])} | {r['replay_valid']} / {len(traces)} | {r['compiled_rule_traces']} | {pct(r['compiled_rule_detection_rate'])} | {pct(r['compiled_rule_false_trigger_rate'])} | {cf1} |")
    accounting = ['| Model | Corpus policies | Mean input tokens | Mean output tokens | Mean active wall seconds | Known USD/policy | Transports missing usage |',
                  '| --- | --- | --- | --- | --- | --- | --- |']
    for r in rows:
        if r['model'] == 'reference' or not int(r['rq1_completed']):
            continue
        mean = lambda key: f"{float(r['rq1_' + key]):.1f}"
        cost = f"${float(r['rq1_uncached_list_usd_mean']):.4f}" if r['rq1_uncached_list_usd_mean'] != '' else 'unmeasured'
        accounting.append(f"| {r['model']} | {r['rq1_completed']} | {mean('input_tokens_mean')} | {mean('output_tokens_mean')} | {mean('wall_s_mean')} | {cost} | {r['rq1_usage_missing_transports']} |")
    artifact_summary = read('artifact-reference-summary.csv')[0]
    reference_audit = read('reference-validation-summary.csv')
    reference_audit = reference_audit[0] if reference_audit else dict(matching_trace_snapshots=0, traces=0, script_disagreements_old_nonzero_new_zero=0)
    reference = next(r for r in rows if r['model'] == 'reference')
    p_rows = [r for r in rows if r['model'] != 'reference' and r['f1'] != '']
    if p_rows:
        fmin, fmax = min(float(r['f1']) for r in p_rows), max(float(r['f1']) for r in p_rows)
        paragraph = (f"We compare policy translation across {available} response-verified model configurations using a shared DSL reference and compiler feedback. "
                     f"The behavioral sample contains {counts['rq2']} repository policies and {len(traces)} labeled traces, including {positive} violations and {negative} compliant traces. "
                     f"We replay tool effects under the kernel engine without agent continuation or model judges. "
                     f"Completed model rows attain F1 from {fmin:.3f} to {fmax:.3f}. "
                     f"Configured output budgets and CLI defaults also affect these rates. Compiler acceptance on the {counts['rq1']}-policy corpus measures syntactic compatibility rather than semantic correctness. "
                     "Reference agreement and replay failures are reported separately because backend behavior and fixture fidelity can also affect detection.")
    else:
        paragraph = (f"We compare policy translation across {available} response-verified model configurations with identical directive, source-evidence, instruction-file, and DSL-reference inputs. "
                     f"The behavioral sample contains {counts['rq2']} policies and {len(traces)} labeled traces, while a separate corpus contains {counts['rq1']} policies. "
                     "Each translation receives compiler feedback on revisions. Kernel replay uses fixed tool effects without agent continuation or model judges. "
                     "Compiler acceptance is reported separately from behavioral correctness. Behavioral scores remain pending until reference replay and the full trace set are available.")
    assert len(paragraph.split()) <= 150
    excluded = '\n'.join(f"* `{r['model']}`: {r['error']}" for r in access if r['status'] != 'ok' or r['identity_verified'] != '1')
    fixture_rows = read('selected-statement-fixtures.csv')
    edits, edit_matches = sum(int(r['edit_preconditions']) for r in fixture_rows), sum(int(r['edit_matches']) for r in fixture_rows)
    reads, read_matches = sum(int(r['read_preconditions']) for r in fixture_rows), sum(int(r['read_matches']) for r in fixture_rows)
    text = f'''# Policy translation across models

Results on branch `experiments/translation-models-20261028`. The operator will
consolidate lane branches. No pull request is created or updated by this lane.

The planned scope is {available} accessible model configurations, {counts['rq2']}
behavioral policies with {len(traces)} traces ({positive} violation, {negative}
compliant), and a separate {counts['rq1']}-policy compilation corpus. Counts in
the table are completed trials, so partial rows must not be read as full-corpus
rates. Detection, false-trigger rate, and F1 remain unavailable unless every planned
trace has an outcome. The reference row is a supplied translation, not a new
model-generation trial. The behavioral sample covers
{overlap['behavioral_repositories']} repositories, while compilation covers
{overlap['compilation_repositories']}. The corpora share
{overlap['matching_repo_statement_ids']} repository/statement identifiers and
{overlap['matching_directive_text']} exact directive texts. They are not disjoint
held-out sets, and no semantic deduplication is claimed.

{chr(10).join(table)}

Corpus accounting means include completed trials and known transport usage.
Active wall time includes provider waits and compiler revisions. It excludes
time queued for a worker and gaps between interrupted sessions. Per-policy costs,
tokens, and time are retained for both corpora in the translation CSVs.

{chr(10).join(accounting)}

{chr(10).join(families)}

{chr(10).join(coverage)}

{chr(10).join(budgets)}

API output is capped at {api_cap} tokens, including reported reasoning.
This budget constrains these deployment configurations. Reported cutoffs
are separated from other compiler failures. CLI stop reasons are not always
reported, so a zero known cutoff count does not establish absence of truncation.
The results do not measure unconstrained model capability.

Compiled-only scores use successfully compiled and replayed policies. This
selection can bias comparisons. Coverage-conditioned end-to-end scores are
also retained in the CSV. Headline end-to-end scores require complete outcomes.
A final compiler failure supplies no policy and is an end-to-end nondetection.
An API/identity failure or failed kernel load has an unknown behavioral outcome.

The reference replay currently has {reference['replay_valid']} usable outcomes
and {reference['replay_errors']} engine/replay errors. Among comparable artifact
outcomes, {reference['agreements']} of {reference['agreement_traces']} agree with
the original RQ2 artifact's `setup_fired`. This comparison uses kernel detections,
not the artifact's recovery scores or trajectory judges. Per-policy agreement and
every disagreement appear in `reference-validation-policies.csv` and
`reference-disagreements.csv`. Differences can arise from recovered fixtures, the
current compiler, and the experimental backend, so replay does not perfectly
isolate backend fidelity. All {reference_audit['matching_trace_snapshots']} of
{reference_audit['traces']} trace snapshots match the original result records.
Among script-family disagreements, {reference_audit['script_disagreements_old_nonzero_new_zero']}
had a nonzero tool return code in the original setup and none in this replay.
The execution audit records these environment differences without inferring
why an original command failed. The original artifact's
reference detections were themselves imperfect against the trace labels:
{artifact_summary['true_positives']} of {artifact_summary['violation_traces']}
violations detected, {artifact_summary['false_positives']} of
{artifact_summary['compliant_traces']} compliant traces triggered, and
F1 {float(artifact_summary['f1']):.3f}. Those preserved outcomes appear in
`artifact-reference-detections.csv` and are not a new model-comparison row.

## Method

`prepare.py` exports frozen inputs without checking out artifact branches.
The artifact commit is `{provenance['artifact_commit']}`. The DSL reference is
`{provenance['dsl_ref']}`, SHA-256 `{provenance['dsl_sha256']}`. Its artifact
counterpart has SHA-256 `{provenance['artifact_dsl_sha256']}`. The current CLI was
built from master commit `{provenance['compiler_source_commit']}`. Binary hashes
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
inference counts. Codex token counts use CLI-reported turn usage. Cache-warmup
metadata are retained separately and are not added again to those counts.
A scored call must contain exactly one inference and no tool
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
retry budget for missing responses, recorded in `model-settings.csv`. The corpus
budget includes an additional recovery transport after a supervisor-reported
service interruption. Capacity, timeout, and transient HTTP errors use exponential
backoff. CLI session limits wait for the provider-reported UTC reset before the
next transport, with the wait retained in wall-time accounting. A recovery worker
waits for the original model queue to finish before reopening its bounded access
failures. This avoids duplicate requests. Permanent access errors remain access
failures. Every completed transport
is checkpointed before retrying, and returned model answers are never resampled.
API calls use parallel workers per model,
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
Read, Write, Edit, and Bash. Write/Edit reuse the frozen helper body via
`python -c`. The original runner materialized a temporary helper script per
call. This replayer omits those preparation writes, so helper argv and setup I/O
differ and can affect exec or broad-write policies. Bash commands are verbatim.
Effects become notify so the complete trace can run.
Predicates, labels, conditions, and reasons remain fixed. The root receives the
same AGENT/COMMAND label convention as the CLI. Each worker has private network
and mount namespaces, a short `/tmp/repo` bind mount, artifact safety shims, and
an environment without credentials. Relative Bash and file-changing tool paths
are preserved. Read uses an absolute path, as in the original harness.
Short checkout paths reduce finite-buffer path truncation and differ from the
original runner's temporary paths.
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
{native['cases']} cases, {native['mismatches']} mismatches. These checks are not a
whole-engine equivalence proof. Expanded guest controls pass {control_passes} of
{len(controls)}, including positive/negative write checks and read-before-write
label propagation. Parallel controls pass {parallel_passes} of
{len(parallel_controls)} with separate simultaneous engine instances. All scored models and references use this same engine build.
Per-trace loader and fixture hashes identify the actual configuration.

Original evaluated source checkout SHAs are absent from the artifact. Candidate
sources are recorded instruction-file commits, commits before the artifact date,
and explicitly recorded extra candidates. `select_fixtures.py` selects per-policy
sources by Read/Edit preconditions, never detection outcomes or labels. The
selected fixtures satisfy {edit_matches} of {edits} Edit literal preconditions and
{read_matches} of {reads} Read path preconditions. No trace is rewritten. Tool
errors remain visible because successful command invocation does not imply that
the intended forbidden side effect occurred.

## Exclusions and limitations

{excluded}

The preserved `invalid-protocol-calls.csv` audits an interrupted preliminary run
whose compiler invocation combined incompatible CLI flags. Those calls are not
model failures or scored trials. Raw responses remain in `invalid-protocol/`.
Interrupted requests with unknown usage are preserved in `interrupted-requests.csv`.
The installed Codex shell wrapper initially left native children alive on timeout.
Those trial-only orphan processes are audited in `orphaned-cli-processes.csv` and
terminated without interrupting the active corpus worker. New CLI launches use
private process groups, which are terminated together on timeout. Usage from
timed-out requests remains unknown, even when their child process is cleaned up.
Kernel smoke failures are retained separately as diagnostics. Failed engine loads
are never counted as true negatives. The behavioral sample is small, constructed,
and selected for OS observability. It is not a held-out natural policy population.
Prior paper translators can have corpus familiarity. Reusing the original
compilation corpus does not establish generalization to unseen policy classes. Recovered fixtures, notify
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

{paragraph}
'''
    (HERE / 'README.md').write_text(text)
    latex = ['\\begin{tabular}{lrrrrrr}', '\\toprule',
             'Model & Compile@1 & Compile@3 & Detect. & FTR & F1 & Traces \\\\', '\\midrule']
    for r in rows:
        comp = [pct(r['rq1_compile_at_1_rate']), pct(r['rq1_compile_at_3_rate'])] if r['model'] != 'reference' else ['n/a', 'n/a']
        scores = [pct(r['detection_rate']), pct(r['false_trigger_rate']), f"{float(r['f1']):.3f}" if r['f1'] != '' else 'unavailable']
        latex.append(' & '.join([NAMES[r['model']]] + comp + scores + [r['replay_valid'] + '/' + str(len(traces))]).replace('%', '\\%') + ' \\\\')
    latex += ['\\bottomrule', '\\end{tabular}', '% Compilation yield includes access failures. Traces gives usable replay coverage. See README for exclusions.']
    (HERE / 'table.tex').write_text('\n'.join(latex) + '\n')
    fig, ax = plt.subplots(figsize=(7.2, 4.2))
    plotted = []
    markers = ['*', 'o', 's', '^', 'D', 'v', 'P']
    for i, r in enumerate(rows):
        if r['detection_rate'] == '' or r['false_trigger_rate'] == '':
            continue
        x, y = 100*float(r['false_trigger_rate']), 100*float(r['detection_rate'])
        ax.scatter(x, y, label=NAMES[r['model']], marker=markers[len(plotted) % len(markers)], s=85,
                   color='black' if r['model'] == 'reference' else plt.get_cmap('tab10')(i))
        plotted.append(dict(model=r['model'], false_trigger_rate=r['false_trigger_rate'], detection_rate=r['detection_rate']))
    if plotted:
        csv_write(HERE / 'figure-data.csv', plotted)
        ax.legend(loc='center left', bbox_to_anchor=(1, .5), frameon=False, fontsize=8)
    else:
        ax.text(.5, .5, 'Behavioral replay pending validation', ha='center', va='center', transform=ax.transAxes)
    ax.set(title='End-to-end translation and replay', xlabel='False-trigger rate (%)', ylabel='Violation detection rate (%)', xlim=(-2, 102), ylim=(-2, 102))
    ax.grid(alpha=.2)
    fig.tight_layout()
    fig.savefig(HERE / 'comparison.pdf', bbox_inches='tight', metadata={'CreationDate': None, 'ModDate': None})
    fig.savefig(DEFAULT_RAW / 'comparison-preview.png', dpi=150, bbox_inches='tight')
    plt.close(fig)


if __name__ == '__main__':
    main()
