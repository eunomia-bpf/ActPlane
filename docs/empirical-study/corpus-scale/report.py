#!/usr/bin/env python3
"""Render the README using committed CSVs rather than hand-entered results."""
from collections import Counter
import math
from urllib.parse import quote

from analyze import BOOTSTRAPS, MIN_COVERAGE, MIN_KAPPA, MIN_PRIMARY_KAPPA, SEED
from collect import QUOTAS
from common import HERE, read_csv, write_csv

NAMES = {'policy_fraction': 'Policy / all statements', 'system_state_fraction': 'System-observable / policies',
         'context_required_fraction': 'Context needed / system-observable',
         'cross_event_project_share': 'Repositories with cross-event policies',
         'os_enforceable_count': 'OS-tier policy candidates (count)'}


def stat(value):
    try:
        x = float(value)
    except (ValueError, TypeError):
        return 'undefined'
    return f'{x:.3f}' if math.isfinite(x) else 'undefined'


def fmt(r, field='value'):
    if not r or r.get(field, '') == '':
        if r and r.get('status') == 'undefined_zero_denominator':
            return 'undefined'
        return 'withheld' if r and r.get('status', '').startswith('withheld') else 'pending'
    x = float(r[field])
    return f'{x:,.0f}' if r.get('metric', '').endswith('_count') else f'{100*x:.1f}%'


def delta_fmt(row):
    if not row or row.get('status') != 'ok':
        return fmt(row)
    if row.get('artifact_delta', '') == '':
        return 'not available'
    count = row['metric'].endswith('_count')
    values = [float(row[field]) * (1 if count else 100)
              for field in ['artifact_delta', 'delta_ci_low', 'delta_ci_high']]
    point, low, high = [f'{x:+,.0f}' if count else f'{x:+.1f}' for x in values]
    return f'{point}{"" if count else " pp"} [{low}, {high}]'


def interval_fmt(row):
    value = fmt(row)
    if row and row.get('status') == 'ok':
        value += f' [{fmt(row, "ci_low")}, {fmt(row, "ci_high")}]'
    return value


def main():
    config = [('snapshot_date', '2026-10-28'), ('stars_min', 100), ('pushed_since', '2025-01-01'),
              ('search_results_per_query', 100), ('paths_per_family', 1), ('max_file_bytes', 128000),
              ('bootstrap_replicates', BOOTSTRAPS), ('bootstrap_seed', SEED),
              ('historical_bootstrap_seed', SEED + 1),
              ('confidence_level', .95),
              ('min_final_kappa', MIN_KAPPA), ('min_primary_kappa', MIN_PRIMARY_KAPPA),
              ('min_coverage', MIN_COVERAGE), ('max_excerpt_lines_target', 160)]
    config += [('historical_retry_policy', 'batch'), ('scaling_retry_policy', 'invalid'),
               ('historical_local_batch_size', 16), ('historical_remote_batch_size', 12),
               ('historical_and_focused_local_workers', 4), ('remote_workers', 2),
               ('scale_primary_local_workers', 6), ('scale_interim_adjudication_workers', 2),
               ('scale_final_adjudication_workers', 4), ('deferred_optional_scope_workers', 3),
               ('post_core_optional_scope_workers', 5),
               ('reduced_and_scale_local_batch_size', 48), ('reduced_and_scale_remote_batch_size', 24)]
    config += [('max_schema_repairs_before_split', 2), ('schema_repair_mode', 'batch')]
    config += [('quota_' + k, v) for k, v in QUOTAS.items()]
    write_csv(HERE / 'study_config.csv', [dict(parameter=k, value=v) for k, v in config])
    cfg = dict(config)
    claims = {r['metric']: r for r in read_csv(HERE / 'paper_claims.csv')}
    baseline = {r['metric']: r for r in read_csv(HERE / 'paper_summary.csv')}
    audit = read_csv(HERE / 'paper_audit.csv')[0]
    cal = read_csv(HERE / 'calibration_summary.csv')
    gates = read_csv(HERE / 'calibration_gates.csv')
    path = HERE / 'summary.csv'
    summary = read_csv(path) if path.exists() else []
    overall = {r['metric']: r for r in summary if r['group_type'] == 'overall'}
    coverage = read_csv(HERE / 'analysis_coverage.csv')[0] if (HERE / 'analysis_coverage.csv').exists() else {}
    repos = read_csv(HERE / 'repositories.csv') if (HERE / 'repositories.csv').exists() else []
    manifest = read_csv(HERE / 'corpus_manifest.csv') if (HERE / 'corpus_manifest.csv').exists() else []
    counts = Counter(r['status'] for r in manifest)
    family_count = len({r['family'] for r in manifest if r['status'] == 'included'})
    unique_files = len({(r['repo'], r['content_sha256']) for r in manifest if r['status'] == 'included'})
    write_csv(HERE / 'collection_summary.csv', [dict(metric='collected_repositories', value=len(repos)),
        dict(metric='represented_file_families', value=family_count),
        dict(metric='selected_unique_repo_content_pairs', value=unique_files),
        *[dict(metric='file_status_' + k, value=v) for k, v in sorted(counts.items())]])
    analyzed_path = HERE / 'analysis_statements.csv'
    analyzed_files = len({(r['repo'], r['content_sha256']) for r in read_csv(analyzed_path)}) if analyzed_path.exists() else 0
    inventory = [dict(metric=key, paper_claim=claims[key]['value'], recovered=recovered,
                      new_snapshot=collected, new_analyzed=analyzed)
                 for key, recovered, collected, analyzed in [
                     ('repositories', baseline['policy_fraction']['repositories'], len(repos), coverage.get('analyzed_repositories', 0)),
                     ('instruction_files', audit['unique_non_redirect_files'], unique_files, analyzed_files),
                     ('statements', audit['labeled_statements'], coverage.get('extracted_statements', 0),
                      coverage.get('analyzed_statements', 0))]]
    write_csv(HERE / 'inventory_comparison.csv', inventory)
    lines = ['# Expanded instruction-file characterization', '',
        '**Status: scaled characterization is incomplete. Do not replace paper claims until the calibration gates and analysis coverage below are complete.**' if not overall else
        '**Status: automated characterization. Use only dimensions marked passed below. Coverage and sampling limitations constrain interpretation.**', '',
        f'Snapshot: {cfg["snapshot_date"]} UTC. All reported counts, percentages, agreement measures, and configuration values come from CSVs generated by the scripts in this directory.', '',
        '## Comparison with the submitted paper', '',
        '| Inventory | Paper claim | Recovered artifact | New snapshot | New analyzed |',
        '|---|---:|---:|---:|---:|']
    for r in inventory:
        label = {'repositories': 'Repositories', 'instruction_files': 'Instruction files (byte deduplicated)',
                 'statements': 'Statements'}[r['metric']]
        lines.append('| ' + ' | '.join([label, *[f'{int(float(r[k])):,}' for k in
                     ['paper_claim', 'recovered', 'new_snapshot', 'new_analyzed']]]) + ' |')
    lines += ['', 'The new snapshot statement count includes all extracted sources, while the analyzed column requires complete labels for every selected source in each repository. Historical file inventory and annotated source coverage differ, as detailed below.', '',
              '| Measure | Paper claim | Recovered labels | New automated labels (repository bootstrap interval) | Difference vs recovered |',
              '|---|---:|---:|---:|---:|']
    if coverage and coverage['analyzed_repositories'] != coverage['collected_repositories']:
        lines[2] = '**Interim subset: labeling is incomplete. These are results for fully labeled repositories only; do not substitute them for the final full-snapshot claims.**'
    for key, name in NAMES.items():
        old = dict(claims[key], metric=key)
        r = overall.get(key)
        new = fmt(r)
        if r and r['status'] == 'ok':
            new += f' [{fmt(r, "ci_low")}, {fmt(r, "ci_high")}]'
        lines.append(f'| {name} | {fmt(old)} | {fmt(baseline[key])} | {new} | {delta_fmt(r)} |')
    lines += ['', f'The collected manifest covers {len(repos):,} repositories and {counts["included"]:,} selected instruction paths '
        f'({unique_files:,} distinct repository/content pairs). ' +
        (f'The analysis includes {coverage["analyzed_repositories"]} repositories and {int(coverage["analyzed_statements"]):,} statements. '
         f'{coverage["incomplete_files"]} extracted files await complete model pairs or final adjudication. '
         f'{coverage["repositories_with_incomplete_sources"]} repositories are withheld until every selected source is successfully extracted and labeled.'
         if coverage else 'Labeling coverage is pending.'), '',
        'The OS-tier count is the union of per-event and cross-event taxonomy labels. It is a count of candidate policies, not evidence that the current ActPlane engine implements every semantic predicate. The system-state fraction uses the paper’s system-observable definition, including content predicates. It does not measure actual executions or observed state changes.', '',
        '## Historical recovery and calibration', '',
        f'`recover.py` exports the artifact branch by immutable commit without checking it out. It recovered {audit["labeled_statements"]} labeled statements in {audit["label_files"]} annotation files referencing {audit["referenced_source_files"]} primary instruction paths. '
        f'The corresponding artifact directories contain {audit["raw_instruction_files"]} raw instruction files ({audit["raw_unique_contents_within_repo"]} byte-distinct within repositories). '
        f'Excluding {audit["pure_at_redirect_files"]} pure `@AGENTS.md` redirect files after byte deduplication yields exactly {audit["unique_non_redirect_files"]} files, '
        f'{int(audit["unique_non_redirect_lines"]):,} lines, and {int(audit["unique_non_redirect_bytes"]):,} bytes, reproducing the historical file denominator and size totals. '
        f'However, annotation spans cover {int(audit["labeled_span_lines"]):,} lines in the primary referenced sources, so the recovered labels do not establish statement coverage of every additional instruction file. '
        'The cross-event repository share differs from the rounded paper claim and remains visible in the comparison table.', '',
        '`compare_references.py` checks both supplied historical branches without checkout. Their annotation files are byte-identical, as recorded by the shared annotation hash in `historical_reference_comparison.csv`. The project-share discrepancy is therefore present in both supplied references.', '',
        '`taxonomy.txt` reconstructs the coding guide and examples in `origin/artifact-ready:docs/empirical.md` and the current motivation section. The exact historical invocation prompts and the human review sample were not located. This is a reconstructed prompt, not a claim of exact prompt replication. Reference labels for the statements being judged are never included in prediction or adjudication payloads.', '',
        'Equivalent JSON wrappers are normalized without changing labels or source boundaries. Invalid values, missing IDs, and inconsistent cross-axis applicability are rejected and retried, with earlier responses retained in the raw cache. `calibration_schema_errors.csv` records predictions rejected during schema validation. The reported agreement measures the accepted automated labeling pipeline rather than strict first-response JSON compliance.', '',
        'The initial full-axis calibration uses the legacy whole-batch retry policy (`--retry-policy batch`). During scaling, a small number of invalid values caused repeated requests for otherwise valid rows. The revised default retains valid rows and retries only invalid or missing IDs, while ambiguous IDs still reject the whole response. The focused prompt was recalibrated from cached initial requests under this exact revised policy before resuming scaling. `format_calibration_v1_summary.csv` preserves the earlier whole-batch check. This initial retry/schema change did not rescue the failed axes, and its codebook and thresholds remained unchanged. The separate prospective codebook rescue below, when available, supplies explicitly versioned new evidence.', '',
        'The partial first-pass source labels and figures are preserved in branch history and the raw `retry-protocol-v1/` backup. They are superseded by the revised-policy run rather than mixed into its final accepted labels. `retry_protocol.csv` records the versions, and the interruption remains in the run audit.', '',
        f'A schema-invalid subset receives up to {cfg["max_schema_repairs_before_split"]} additional schema-repair requests that repeat the permitted values and unchanged coding guide before binary splitting. Persistently invalid singletons remain failures. The legacy full-axis calibration does not use this feedback.', '',
        'An observed all-blank-type subset made singleton-only repairs expensive during the scaled run. The current implementation applies the identical schema feedback to an unusable batch before splitting it. Accepted earlier annotations remain frozen. `retry_protocol` records the implementation on each accepted prediction, and `annotation_protocol_counts.csv` summarizes the mixture. The earlier singleton-repair reference outputs and scores are preserved in `calibration-v2/`, and `calibration_protocol_comparison.csv` reports every changed reference value after the batched-repair recheck. Both implementations use the same models, coding guide, and thresholds. Cached initial responses can be reused when rechecking a repair implementation.', '',
        'The primary annotators are the direct, identity-verified `qwen3.8-27b-nvfp4` endpoint and the gateway’s named `zai/glm-5.3` route. The gateway-reported model identity is recorded but its provider weights cannot be independently audited. GLM uses low reasoning effort because its reasoning cannot be disabled. Disagreements are reread by Qwen with anonymized primary labels whose order is deterministically permuted by statement-ID hash. Adjudication remains correlated with a primary model and has no independent human reference.', '',
        '| Model vs paper | Dimension | Applicable gold N | Evaluated N | Raw agreement | Cohen’s kappa |',
        '|---|---|---:|---:|---:|---:|']
    for r in cal:
        if r['scope'] != 'applicable_gold':
            continue
        lines.append(f'| {r["model"]} | {r["dimension"]} | {r["expected"]} | {r["evaluated"]} | {stat(r["agreement"])} | {stat(r["kappa"])} |')
    lines += ['', '`calibration_summary.csv` also reports end-to-end agreement including inapplicable labels. The applicable-gold evaluation counts a predicted inapplicable value as disagreement. `calibration_confusion.csv` retains every confusion cell and missing predictions are reported explicitly.', '',
        f'Before inspecting the complete calibration, the scaling gate was fixed at final kappa ≥{MIN_KAPPA:.2f}, each primary-model kappa ≥{MIN_PRIMARY_KAPPA:.2f}, and coverage ≥{100*MIN_COVERAGE:.0f}%. '
        'Type must pass for any dependent result. Enforcement must pass before context may scale. These are study decisions rather than universal reliability standards. The same historical set is used for calibration and evaluation, so agreement is not a held-out generalization estimate.', '',
        '| Initial full-guide dimension | Initial scale gate | Reason |', '|---|---|---|']
    lines.extend(f'| {r["dimension"]} | {r["passed"]} | {r["reason"]} |' for r in gates)
    fidelity_path = HERE / 'paper_fidelity_summary.csv'
    if fidelity_path.exists():
        fidelity = {r['metric']: int(r['value']) for r in read_csv(fidelity_path)}
        lines += ['', f'The historical primary-source audit records {fidelity["missing_lines"]} missing lines, '
                  f'{fidelity["overlapping_lines"]} overlapping lines, and {fidelity["whitespace_normalized_mismatches"]} '
                  'text mismatches under the original validator’s whitespace normalization. '
                  f'{fidelity["exact_text_mismatches"]} spans differ in exact formatting. '
                  'Calibration uses the recorded annotated text unchanged. New extracted text is copied directly from its source spans and checked for exact fidelity.']
    format_path = HERE / 'format_calibration_summary.csv'
    if format_path.exists():
        lines += ['', 'When some axes fail, a focused prompt containing only the requested coding-guide axes and examples is calibrated again before scaling. The exact focused prompt and reduced output schema are used for both this check and deployment. This avoids assuming that removing rejected axes leaves predictions unchanged. During that initial schema-only check, definitions, examples, and agreement cutoffs were not tuned against individual errors. The later rescue permits development-only codebook revisions under its separate frozen protocol.', '',
                  '| Reduced-schema model | Dimension | Evaluated N | Cohen’s kappa |', '|---|---|---:|---:|']
        for r in read_csv(format_path):
            if r['scope'] == 'applicable_gold':
                lines.append(f'| {r["model"]} | {r["dimension"]} | {r["evaluated"]} | {stat(r["kappa"])} |')
    poor = [r for r in cal if r['scope'] == 'applicable_gold' and r['model'] != 'inter_model'
            and float(r.get('coverage', 0)) >= MIN_COVERAGE and float(r['kappa']) < MIN_PRIMARY_KAPPA]
    if poor:
        lines += ['', '**Poor agreement:** ' + '; '.join(f'{r["model"]} on {r["dimension"]} (κ={float(r["kappa"]):.3f})' for r in poor) +
                  '. Under the initial codebook, these results did not justify scaling the reference convention. The prospective rescue below is reported separately. No claim is made that the model or the historical label is necessarily correct in every disagreement.']
    agreement_path = HERE / 'scaled_model_agreement.csv'
    if agreement_path.exists():
        agreement_rows = read_csv(agreement_path)
        lines += ['', 'Agreement between the primary models on the analyzed new spans is reported separately below. These figures describe annotator consistency, and do not measure accuracy against a new human reference. `scaled_model_agreement.csv` also reports family and repository-category breakdowns and missing pairs.', '',
                  '| New-corpus intermodel dimension | Paired statements | Disagreements | Raw agreement | Kappa |',
                  '|---|---:|---:|---:|---:|']
        lines.extend(f'| {r["dimension"]} | {r["paired_statements"]} | {r["disagreements"]} | {stat(r["agreement"])} | {stat(r["kappa"])} |'
                     for r in agreement_rows if r['group_type'] == 'overall')
    lines += ['', '## Selection and measurement', '',
        f'The eligibility floor is {cfg["stars_min"]} stars with a push on or after {cfg["pushed_since"]}. Forks and archived repositories are excluded by the search. '
        f'`collect.py` takes the top {cfg["search_results_per_query"]} results of each fixed query, unions within a discovery stratum, and visits candidates by descending stars with repository name breaking ties. '
        f'Quotas are {cfg["quota_general"]} general-software repositories, {cfg["quota_agent"]} additional agent-ecosystem repositories, and {cfg["quota_noncoding_discovery"]} additional repositories from noncoding discovery queries. '
        'Earlier strata own overlaps. A quota can remain unfilled if the fixed candidate set is exhausted. Discovery strata do not establish repository categories.', '',
        'There is no language, creation-year, file-size minimum, directive-density, or subjective fake-star filter beyond rejecting empty or binary files. This broadens the original study’s eligibility and avoids outcome-based filtering, but admits low-information files, collections, and potentially inflated stars. `collection_attempts.csv` retains unsuccessful probes and `searches.csv` retains queries and truncation indicators. GitHub’s ranking and search cap prevent an exhaustive population sample.', '',
        f'All requested families are inspected in recursive commit-pinned trees: CLAUDE.md, AGENTS.md, GEMINI.md, .github/copilot-instructions.md, .cursor/rules/*, .cursorrules, .windsurfrules, and SKILL.md. '
        f'To bound very large skill/rule collections, at most {cfg["paths_per_family"]} path per family per repository is analyzed, preferring fewer path components, shorter paths, then lexical order. '
        f'Files above {cfg["max_file_bytes"]:,} bytes are excluded. All discovered paths, including capped paths and download failures, remain in the manifest. '
        'A truncated GitHub tree is flagged, so absence of a family in such a tree is not proof of absence.', '',
        'The Cursor family recognizer includes `.md` and `.mdc` files immediately inside a `.cursor/rules/` directory. Other extensions and nested rule directories are outside this operational definition.', '',
        'The new snapshot retains pure redirect files when selected. Historical redirect removal only reconstructs the original inventory and is not a new-corpus eligibility filter. A matching instruction filename establishes presence, while actual use by a deployed agent remains unverified.', '',
        f'Qwen proposes semantic statement starts in source chunks targeting {cfg["max_excerpt_lines_target"]} lines. The script derives half-open ranges and copies source text exactly. '
        'Coverage, hashes, and range continuity are checked, while extraction failures remain recorded. Earlier range-pair attempts that failed validation remain in the raw logs. This validates source fidelity, not the semantic correctness of boundaries. Chunking may separate context, and the new extraction has no human boundary audit. Calibration holds historical boundaries fixed and therefore does not validate new extraction quality.', '',
        'The historical reference contains coding-repository CLAUDE.md and AGENTS.md statements. Its calibration does not establish equivalent accuracy on the additional file families or noncoding tasks. The new family and task-scope breakdowns therefore remain descriptive automated estimates, even for axes that pass the historical agreement gate.', '',
        'Overall analysis counts each byte-identical file once within a repository. Family analysis attributes shared text to each family in which it appears, so family counts are not additive. Repository categories come from a separate metadata classifier and are explicitly marked as model judgments. A noncoding-agent repository can still contain coding instructions. The category breakdown must not be described as a noncoding-policy slice without inspecting file scope.', '',
        'Repository-purpose groups are defined in `categorize.py`: agent_frameworks includes reusable agent infrastructure, coding agents, editors, and developer-agent tools; applications includes general software, libraries, services, and educational collections; noncoding_agents covers assistants primarily advertised for personal, office, research, browser, or finance tasks. Mixed systems are assigned by their primary advertised purpose. These categories have not received independent human reliability validation.', '',
        'A separate `scope_files.py` classifier examines source excerpts to identify actual noncoding task instructions. `file_scopes.csv` preserves its decisions and rationales, and file-scope summaries are reported separately from repository categories. These scope labels have no human reliability calibration and may be affected by omitted middle content, so this is an exploratory noncoding slice. Both optional direct flash endpoints reject the available authentication; their recorded probes are in `endpoint_probes.csv` and they are not used. The optional OpenCode routes also reject requests with the requested session header, as recorded in `gateway_probes.csv`. A named GLM flash route was used only for a throughput pilot and is not part of the primary calibration.', '',
        '`noncoding_manifest.csv` and `noncoding_statements.csv` materialize the analyzed sources classified as `noncoding_assistance`. Mixed, unclear, unclassified, and software-development sources remain visible in the main tables rather than entering this exploratory subset. File-scope groups can include different files from the same repository, so their repository counts overlap while their statement counts partition the analyzed corpus.', '',
        'Optional scope classification initially ran alongside primary labeling. Observed local request latency motivated deferring its remaining work until primary labeling completes, allocating the bounded local concurrency to primary labels and interim adjudication. Scope work resumes alongside final adjudication and pauses when the primary analysis is ready. The separate finalization pass resumes any remaining scope judgments after other local clients exit. Incomplete or failed scope judgments remain explicitly unclassified in the file-scope table and `scope_coverage.csv`. They do not remove repositories from the primary analysis. This changes client request scheduling without changing the coding guide, accepted labels, or thresholds.', '',
        f'Intervals are central {100*cfg["confidence_level"]:.0f}% percentile intervals using {BOOTSTRAPS:,} bootstrap replicates resampling repositories within discovery strata, with new-corpus seed {SEED} and historical seed {cfg["historical_bootstrap_seed"]}. '
        'They describe sensitivity within this convenience sample. Sparse groups can yield degenerate intervals without establishing population precision. They do not correct star/query selection bias, model labeling error, duplicated templates across repositories, or changed eligibility since the historical snapshot. Comparisons are descriptive rather than evidence of temporal change. CSV delta intervals use independently resampled historical and new repositories. They do not model pairing or covariance for repository identities shared between snapshots.', '',
        'Headline analysis requires every selected source file in a repository to have complete model pairs and final labels. Incomplete repositories remain in the collection and coverage tables rather than entering project-level denominators with unobserved files treated as negative. This makes interim checkpoints subsets of the final snapshot, not final results.', '',
        '## Breakdowns', '', 'Full counts, denominators, intervals, and calibration status are in `summary.csv`.']
    lines += ['', '`paper_family_summary.csv` gives the recovered reference baselines by primary annotated file family. For shared families, `summary.csv` also includes independently bootstrapped differences from those baselines. These comparisons hold the family name fixed while repository selection and snapshot conditions still differ.']
    overlap_path = HERE / 'snapshot_overlap.csv'
    if overlap_path.exists():
        overlap = read_csv(overlap_path)[0]
        lines += ['', f'The new sample shares {overlap["shared_repositories"]} repository identities with the historical sample and adds '
                  f'{overlap["newly_sampled_repositories"]} previously unsampled repositories. '
                  f'{overlap["historical_repositories_not_resampled"]} historical repositories are not resampled. '
                  'This is a new convenience sample rather than a longitudinal panel. Repository identity is compared case-insensitively without attempting to resolve renames.']
    family_path = HERE / 'family_coverage.csv'
    if family_path.exists():
        lines += ['', '| File family | Selected paths | Repositories | Excluded discovered paths |', '|---|---:|---:|---:|']
        lines.extend(f'| {r["family"]} | {r["selected_paths"]} | {r["selected_repositories"]} | {r["excluded_paths"]} |'
                     for r in read_csv(family_path))
    overview_path = HERE / 'corpus_overview.csv'
    if overview_path.exists():
        overview = read_csv(overview_path)
        total = next((r for r in overview if r['dimension'] == 'overall'), None)
        if total:
            lines += ['', f'The collected repositories have a star range of {int(total["stars_min"]):,}–{int(total["stars_max"]):,}, '
                      f'with median {float(total["stars_median"]):,.0f}. These are snapshot metadata rather than authenticity judgments.', '',
                      '| Primary language | Repositories |', '|---|---:|']
            lines.extend(f'| {r["label"]} | {r["repositories"]} |' for r in overview if r['dimension'] == 'language')
    for kind in ('family', 'category', 'file_scope'):
        subset = [r for r in summary if r['group_type'] == kind]
        if not subset:
            continue
        lines += ['', '| ' + kind.capitalize() + ' | Repositories | Statements | Policy [interval] | System [interval] | Context [interval] | Cross-event projects [interval] | OS-tier count [interval] |',
                  '|---|---:|---:|---:|---:|---:|---:|---:|']
        for group in sorted({r['group'] for r in subset}):
            records = {r['metric']: r for r in subset if r['group'] == group}
            first = next(iter(records.values()))
            lines.append('| ' + ' | '.join([group, first['repositories'], first['statements'],
                                          *[interval_fmt(records.get(k)) for k in NAMES]]) + ' |')
    if (HERE / 'noncoding_manifest.csv').exists() and (HERE / 'file_scopes.csv').exists():
        illustrative = [('openclaw/openclaw', 'skills/gog/SKILL.md'),
                        ('NousResearch/hermes-agent', 'plugins/google_meet/SKILL.md')]
        scope_rows = {(r['repo'], r['content_sha256']): r for r in read_csv(HERE / 'file_scopes.csv')}
        examples = []
        for repo, path in illustrative:
            f = next((r for r in read_csv(HERE / 'noncoding_manifest.csv')
                      if (r['repo'], r['file_path']) == (repo, path)), None)
            if f:
                examples.append(dict(repo=repo, file_path=path, commit=f['commit'],
                    content_sha256=f['content_sha256'],
                    rationale=scope_rows[(repo, f['content_sha256'])]['rationale']))
        write_csv(HERE / 'noncoding_examples.csv', examples,
                  fields=['repo', 'file_path', 'commit', 'content_sha256', 'rationale'])
        if examples:
            lines += ['', 'Illustrative noncoding sources selected for email/calendar and meeting tasks are linked below. Scope judgments remain exploratory.', '',
                      '| Pinned instruction file | Classifier rationale |', '|---|---|']
            for r in examples:
                url = f'https://github.com/{r["repo"]}/blob/{r["commit"]}/' + quote(r['file_path'], safe='/')
                rationale = r['rationale'].replace('|', '\\|').replace('\n', ' ')
                lines.append(f'| [{r["repo"]}: {r["file_path"]}]({url}) | {rationale} |')
    lines += ['', '## Reproduction and artifacts', '',
        'Use an isolated Python environment with `requirements.txt`. Set `GH_TOKEN`, `LITELLM_BASE_URL`, and `LITELLM_API_KEY` in the environment. Never pass secrets as command-line arguments. Raw responses, cached prompts/completions, source files, retries, and HTTP logs stay in the operator-specified raw directory. Set `ACTPLANE_CORPUS_RAW` to reproduce in a different raw-data location. Access to the named model endpoints is required.', '',
        'For offline recomputation from the committed accepted tables, run `analyze.py`, `figures.py`, and `report.py`. These commands issue no model requests. Source-fidelity validation additionally needs the immutable raw files restored by `restore_sources.py`. Regenerating model judgments requires the named endpoints, while reproducing the historical request audit requires the retained raw logs.', '',
        '```bash',
        'python recover.py',
        '# Restore the pinned snapshot. collect.py instead discovers a new snapshot.',
        'python restore_sources.py',
        'python label.py --model qwen3.8-27b-nvfp4 --retry-policy batch --output calibration_qwen.csv',
        'python label.py --model zai/glm-5.3 --retry-policy batch --workers 2 --batch-size 12 --output calibration_glm.csv',
        'python label.py --model qwen3.8-27b-nvfp4 --retry-policy batch --primary calibration_qwen.csv --other calibration_glm.csv --output calibration_adjudicated.csv',
        'python analyze.py --calibration-only',
        '# Scale only the dimensions that passed. See run_scale.py for the gate-controlled pipeline.',
        'python run_scale.py',
        '# Finish optional scope work sequentially after the core model clients exit.',
        f'python scope_files.py --workers {cfg["post_core_optional_scope_workers"]}',
        'python analyze.py', 'python figures.py',
        'python audit_runs.py', 'python validate.py --require-complete',
        'python validate_figures.py --previews', 'python report.py', '```', '',
        '`restore_sources.py` verifies the committed source hashes and Git blob hashes, downloads missing or corrupt cached files from their immutable commit URLs, and records every outcome in `source_restore_validation.csv`. It does not overwrite collection metadata or rediscover repositories. `collect.py` is the separate discovery command for a new dated snapshot. Model regeneration can vary even with the same named endpoint and fixed prompts, so the committed accepted labels remain the record of this run.', '',
        'Committed artifacts include immutable historical provenance, historical labels, model labels, calibration confusion tables, search queries, corpus/file manifests, extraction status, repository categories, summary tables, and the figures corresponding to the paper’s plots. GitHub requests are sequential, cached, and honor retry/reset feedback. Model concurrency stays within the operator’s endpoint limits.', '',
        'The repository-requested `oss-change-workflow` skill was unavailable in the installed skill catalog and filesystem search. Work follows the explicit repository scope, validation, and documentation instructions. The operator’s updated handoff rule is to commit and push only to `experiments/corpus-scale-20261028`, with no further PR activity. No paper source, kernel code, cluster deployment, or other lane is changed.', '',
        '## Paper-ready paragraph', '']
    if (HERE / 'figure_manifest.csv').exists():
        table = ['## Figure handoff', '', '| Paper figure | PDF | Status | Unvalidated axes |', '|---|---|---|---|']
        for r in read_csv(HERE / 'figure_manifest.csv'):
            table.append(f'| {r["paper_figure"]} | [{r["file"].split("/")[-1]}]({r["file"]}) | {r["status"]} | {r["failed_dimensions"]} |')
        table += ['', 'An interim PDF describes an incomplete analyzed subset. A withheld PDF is an explicit placeholder and must not be inserted as an updated paper result. `figure_data.csv` contains the counts, denominators, and project fractions used by the plots. `figure_intervals.csv` gives repository-bootstrap intervals for every enforcement/context figure cell, including count intervals and the number of defined draws. These are raw-label intervals, separate from misclassification correction. `validate_figures.py` checks embedded fonts, placeholder text, and snapshot metadata against the actual PDFs. Its optional raster previews stay outside git for visual inspection.', '']
        lines[-2:-2] = table
    if overall and coverage.get('analyzed_repositories') == coverage.get('collected_repositories'):
        valid = {k: r for k, r in overall.items() if r['status'] == 'ok'}
        paragraph = ''
        if any(r['group_type'] == 'file_scope' and r['group'] == 'noncoding_assistance' and int(r['statements']) > 0 for r in summary):
            paragraph = 'We broadened the sample across applications and agent frameworks and included an exploratory slice of noncoding task instructions. '
        paragraph += f'We expanded the characterization to {coverage["analyzed_repositories"]} repositories and {int(coverage["analyzed_statements"]):,} statements from {int(coverage["selected_source_files"]):,} files after byte deduplication within each repository, using a dated, commit-pinned GitHub snapshot spanning {family_count} instruction-file families. '
        if 'policy_fraction' in valid:
            r = valid['policy_fraction']
            paragraph += f'The automated labels mark {fmt(r)} of statements as policies ({100*cfg["confidence_level"]:.0f}% repository-bootstrap interval {fmt(r, "ci_low")}–{fmt(r, "ci_high")}). '
        if 'system_state_fraction' in valid:
            paragraph += f'Of these policies, {fmt(valid["system_state_fraction"])} are system-observable, and {fmt(valid["cross_event_project_share"])} of repositories contain cross-event requirements. '
        if 'context_required_fraction' in valid:
            paragraph += f'Among system-observable policies, {fmt(valid["context_required_fraction"])} require project or task context. '
        paragraph += 'We calibrated named Qwen and GLM annotators against the recovered paper labels and withheld dimensions that failed the prespecified agreement gate. The enlarged corpus broadens repository and file-family coverage, although query selection, automated segmentation, and correlated model judgments limit generalization.'
        if (HERE / 'rescue/deployment_gates.csv').exists():
            paragraph = f'We characterized {coverage["analyzed_repositories"]} repositories and {int(coverage["analyzed_statements"]):,} statements in {int(coverage["selected_source_files"]):,} files after byte deduplication within repositories, across {family_count} instruction-file families. '
            paragraph += f'Named Qwen and GLM annotators label {fmt(valid["policy_fraction"])} of statements as policies (95% repository-bootstrap interval {fmt(valid["policy_fraction"], "ci_low")}–{fmt(valid["policy_fraction"], "ci_high")}). '
            if 'system_state_fraction' in valid:
                paragraph += f'Among policies, {fmt(valid["system_state_fraction"])} are system-observable, with {fmt(valid["os_enforceable_count"])} OS-tier candidates. Cross-event requirements appear in {fmt(valid["cross_event_project_share"])} of repositories. '
            if 'context_required_fraction' in valid:
                paragraph += f'Of system-observable policies, {fmt(valid["context_required_fraction"])} require project or task binding. '
            paragraph += 'A repository split was held out from codebook revision, although the reference had earlier aggregate diagnostic exposure. '
            if 'system_state_fraction' not in valid or 'context_required_fraction' not in valid:
                paragraph += 'Dimensions failing the test gate remain withheld. '
            paragraph += 'Scope includes exploratory noncoding instructions. Convenience sampling, automated segmentation, reference conventions, and correlated adjudication limit generalization.'
        assert len(paragraph.split()) <= 150
        lines.append(paragraph)
    else:
        lines.append('Pending complete-snapshot labeling. Interim descriptive estimates above are not paper-ready.')
    if (HERE / 'rescue/protocol.csv').exists():
        from rescue.report_rescue import render
        rescue_lines = render()
        at = lines.index('## Selection and measurement')
        lines[at:at] = rescue_lines + ['']
    (HERE / 'README.md').write_text('\n'.join(lines) + '\n')


if __name__ == '__main__':
    main()
