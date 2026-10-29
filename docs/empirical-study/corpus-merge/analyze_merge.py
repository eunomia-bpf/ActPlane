#!/usr/bin/env python3
"""Recompute the two repository unions from frozen accepted labels, offline."""
import ast
import csv
import difflib
import hashlib
import json
import platform
import sys
import tarfile
from collections import Counter, defaultdict
from pathlib import Path

import matplotlib
import numpy as np
import yaml

HERE = Path(__file__).resolve().parent
INPUT = HERE / '.inputs'
SCALE = INPUT / 'scale'
SEED, REPLICATES = 20261029, 10000
AXES = ('type', 'topic', 'enforceability', 'context_required')


def read(path):
    with path.open(newline='', encoding='utf-8') as f:
        return list(csv.DictReader(f))


def write(path, rows):
    with path.open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]), lineterminator='\n')
        writer.writeheader()
        writer.writerows(rows)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def constants():
    original = (INPUT / 'plot_empirical.original.py').read_text()
    tree = ast.parse(original)
    values = {n.targets[0].id: ast.literal_eval(n.value) for n in tree.body
              if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name)
              and n.targets[0].id in ('COLLAPSE', 'TOPIC_ORDER', 'ENF_LEVELS', 'CTX_LEVELS')}
    expected = original.replace("    'figure.dpi': 300,", "    'figure.dpi': 300,\n    'pdf.fonttype': 42,\n    'ps.fonttype': 42,")
    expected = expected.replace("os.path.dirname(__file__), '..', 'figures'", "os.path.dirname(__file__), 'figures'")
    modified = (HERE / 'plot_empirical.py').read_text()
    assert modified == expected, 'Plot differs beyond output directory and Type 42 font settings'
    (HERE / 'plot_empirical.diff').write_text(''.join(difflib.unified_diff(
        original.splitlines(True), modified.splitlines(True),
        fromfile='actplane-atc/scripts/plot_empirical.py', tofile='corpus-merge/plot_empirical.py')))
    return values


def load_inputs(collapse):
    historical = read(SCALE / 'paper_labels.csv')
    paper_files = read(SCALE / 'paper_files.csv')
    old_meta = {r['repo'].casefold(): dict(r, inventory_files=0, annotated_files=1, source='original_2026-05-23')
                for r in paper_files}
    by_repo = defaultdict(list)
    for r in historical:
        by_repo[r['repo'].casefold()].append(r)
    with tarfile.open(INPUT / 'original.tar') as archive:
        provenance = read(SCALE / 'paper_provenance.csv')
        contents = {r['path']: archive.extractfile(r['path']).read() for r in provenance}
    assert all(sha(contents[r['path']]) == r['sha256'] for r in provenance)
    for key, meta in old_meta.items():
        base = 'docs/corpus/' + meta['repo'].replace('/', '__') + '/'
        annotation = yaml.safe_load(contents[base + 'statements.yaml'])
        metadata = json.loads(contents[base + 'meta.json'])
        assert int(meta['stars']) == metadata['stars']
        exported = {r['statement_id'].rsplit(':', 1)[1]: r for r in by_repo[key]}
        assert len(exported) == len(annotation['statements'])
        for s in annotation['statements']:
            row = exported[str(s['id'])]
            assert row['text'] == s['text']
            assert [int(row['start_line']), int(row['end_line'])] == s['lines']
            assert row['type'] == s['type']
            assert row['topic'] == collapse.get(s['topic'], s['topic'])
            assert all(row[d] == (s.get(d) or '') for d in AXES[2:])
        unique = {data for name, data in contents.items() if name.startswith(base) and
                  name.rsplit('/', 1)[-1] in ('CLAUDE.md', 'AGENTS.md')}
        meta['inventory_files'] = sum(data.strip() not in (b'@AGENTS.md', b'@CLAUDE.md') for data in unique)
    assert len(historical) == 2116 and len(old_meta) == 64
    assert sum(r['inventory_files'] for r in old_meta.values()) == 84

    labels = read(SCALE / 'labels.csv')
    label_index = {r['statement_id']: r for r in labels}
    newer = read(SCALE / 'analysis_statements.csv')
    statements = read(SCALE / 'statements.csv')
    statement_index = {r['statement_id']: r for r in statements}
    assert len(newer) == len(labels) == len(label_index) == len(statement_index) == 30846
    assert {r['statement_id'] for r in newer} == set(label_index) == set(statement_index)
    for row in newer:
        label = label_index[row['statement_id']]
        assert label['status'] == 'ok'
        assert all(row[d] == label[d] for d in AXES)
        assert all(row[d] == statement_index[row['statement_id']][d] for d in row if d not in AXES)
    retained = next(r for r in read(SCALE / 'rescue/retained_axes.csv') if r['source_file'] == 'labels.csv')
    fingerprint = json.dumps(sorted((r['statement_id'], r['type'], r['topic']) for r in labels),
                             ensure_ascii=False, separators=(',', ':')).encode()
    assert sha(fingerprint) == retained['type_topic_sha256']
    deployed = read(SCALE / 'rescue/source-adjudicated.csv')
    recorded = next(r for r in read(SCALE / 'rescue/deployment_manifest.csv')
                    if r['source_file'] == 'rescue/source-adjudicated.csv')
    assert sha((SCALE / recorded['source_file']).read_bytes()) == recorded['sha256']
    assert {r['statement_id'] for r in deployed} == {r['statement_id'] for r in labels if r['type'] == 'directive'}
    for r in deployed:
        label = label_index[r['statement_id']]
        assert r['status'] == 'ok' and r['revision'] == label['rescue_revision'] == 'r1'
        assert all(r[d] == label[d] for d in AXES[2:])
    assert all(r['passed'] == 'True' for r in read(SCALE / 'rescue/deployment_gates.csv'))
    new_meta = {r['repo'].casefold(): dict(r, inventory_files=0, annotated_files=0, source='corpus-scale_2026-10-28')
                for r in read(SCALE / 'repositories.csv')}
    included = defaultdict(set)
    for row in read(SCALE / 'corpus_manifest.csv'):
        if row['status'] == 'included':
            included[row['repo'].casefold()].add(row['content_sha256'])
    for key, meta in new_meta.items():
        meta['inventory_files'] = meta['annotated_files'] = len(included[key])
    assert len(new_meta) == 325 and sum(r['inventory_files'] for r in new_meta.values()) == 761
    assert {(r['repo'].casefold(), r['content_sha256']) for r in newer} == {
        (repo, digest) for repo, hashes in included.items() for digest in hashes}
    for row in historical + newer:
        row['key'] = row['repo'].casefold()
        assert row['type'] in ('directive', 'description')
        if row['type'] == 'directive':
            assert row['enforceability'] in ('semantic_only', 'content', 'per_event', 'cross_event')
            if row['enforceability'] != 'semantic_only':
                assert row['context_required'] in ('none', 'project', 'task')
    shared = set(old_meta) & set(new_meta)
    assert len(shared) == 27 and len(set(new_meta) - set(old_meta)) == 298
    return historical, old_meta, newer, new_meta, shared


def metrics(rows, repos, topics):
    names = sorted(repos)
    grouped = defaultdict(list)
    for r in rows:
        grouped[r['key']].append(r)
    assert set(grouped) == set(repos)
    result, vectors = [], []

    def count(key, title, value, paper='unavailable', unit='count'):
        result.append(dict(metric=key, label=title, unit=unit, paper_value=paper,
                           numerator='', denominator='', value=value, ci_low='', ci_high=''))

    def ratio(key, title, num, den, paper='unavailable'):
        n, d = np.asarray(num), np.asarray(den)
        result.append(dict(metric=key, label=title, unit='fraction', paper_value=paper,
                           numerator=int(n.sum()), denominator=int(d.sum()), value=float(n.sum()/d.sum()),
                           ci_low='', ci_high=''))
        vectors.append((len(result)-1, n, d))

    groups = [grouped[name] for name in names]
    policies = [[r for r in g if r['type'] == 'directive'] for g in groups]
    total = np.array(list(map(len, groups)))
    p = np.array(list(map(len, policies)))
    enf = {e: np.array([sum(r['enforceability'] == e for r in g) for g in policies])
           for e in ('semantic_only', 'content', 'per_event', 'cross_event')}
    system = p - enf['semantic_only']
    context = {c: np.array([sum(r['enforceability'] != 'semantic_only' and r['context_required'] == c for r in g)
                            for g in policies]) for c in ('none', 'project', 'task')}
    one = np.ones(len(names), dtype=int)
    count('repositories', '1. Repositories', len(names), '64')
    count('instruction_files', '1. Instruction files (inventory)', sum(repos[n]['inventory_files'] for n in names), '84')
    count('annotated_files', '1. Files with statement labels', sum(repos[n]['annotated_files'] for n in names), 'unavailable')
    count('statements', '1. Statements', len(rows), '2,116')
    count('median_stars', '1. Median GitHub stars', float(np.median([int(repos[n]['stars']) for n in names])), '20K', 'stars')
    ratio('policy_fraction', '2. Policies / statements', p, total, '64%')
    ratio('description_fraction', '2. Descriptions / statements', total-p, total, '36%')
    ratio('majority_policy_repos', '2. Repositories with more policy than description', p > total-p, one, '70.1%')
    count('min_repo_policy_fraction', '2. Minimum repository policy share', float(min(p/total)), '0%', 'fraction_extreme')
    count('max_repo_policy_fraction', '2. Maximum repository policy share', float(max(p/total)), '97%', 'fraction_extreme')
    for topic in topics:
        num = [sum(r['topic'] == topic for r in g) for g in policies]
        den = [sum(r['topic'] == topic for r in g) for g in groups]
        ratio('topic_policy:' + topic, '3. Policy share: ' + topic, num, den,
              {'Development Process': '87%', 'Implementation Details': '85%', 'Architecture': '23%'}.get(topic, 'unavailable'))
    count('policies', '4. Policies', int(p.sum()), '1,361')
    for tier, paper in [('semantic_only', '17%'), ('content', '38%'), ('per_event', '29%'), ('cross_event', '16%')]:
        ratio(tier + '_fraction', '4. ' + tier + ' / policies', enf[tier], p, paper)
    ratio('system_observable_fraction', '4. System-observable / policies', system, p, '83%')
    ratio('development_share_cross_event', '5. Development Process / all cross-event policies',
          [sum(r['enforceability'] == 'cross_event' and r['topic'] == 'Development Process' for r in g) for g in policies],
          enf['cross_event'], '39.5%')
    ratio('cross_event_repo_share', '5. Repositories with at least one cross-event policy', enf['cross_event'] > 0, one, '81%')
    ratio('all_four_tiers_repo_share', '5. Repositories spanning all four tiers',
          np.logical_and.reduce([e > 0 for e in enf.values()]), one, '43%')
    count('system_observable', '6. System-observable policies', int(system.sum()), '1,127')
    for context_key, title, paper in [('none', 'Self-contained', '26.4%'), ('project', 'Project context', '64.2%'), ('task', 'Task context', '9.4%')]:
        ratio('context_' + context_key + '_fraction', '6. ' + title + ' / system-observable', context[context_key], system, paper)
    ratio('context_dependent_fraction', '6. Not self-contained / system-observable', context['project'] + context['task'], system, '73.6%')
    for tier, context_keys, title, paper in [
        ('cross_event', ('project', 'task'), 'Context-dependent / cross-event', '95%'),
        ('cross_event', ('project',), 'Project context / cross-event', '77%'),
        ('cross_event', ('task',), 'Task context / cross-event', '19%'),
        ('content', ('project', 'task'), 'Context-dependent / content', '58%'),
        ('content', ('none',), 'Self-contained / content', '42%')]:
        ratio(tier + '_context_' + '_'.join(context_keys), '7. ' + title,
              [sum(r['enforceability'] == tier and r['context_required'] in context_keys for r in g) for g in policies],
              enf[tier], paper)
    count('os_enforceable', '8. OS-enforceable policy candidates', int((enf['per_event'] + enf['cross_event']).sum()), '607')
    ratio('os_enforceable_fraction', '8. (Per-event + cross-event) / policies', enf['per_event'] + enf['cross_event'], p, '45%')
    count('max_repo_policies', '8. Largest per-repository policy count (all tiers)', int(max(p)))
    count('max_repo_os_policies', '8. Largest per-repository OS-tier policy count', int(max(enf['per_event'] + enf['cross_event'])), '66')

    # One draw samples N whole repositories uniformly with replacement.
    weights = np.random.default_rng(SEED).multinomial(len(names), np.full(len(names), 1/len(names)), size=REPLICATES)
    nums = weights @ np.stack([n for _, n, _ in vectors], axis=1)
    dens = weights @ np.stack([d for _, _, d in vectors], axis=1)
    draws = np.divide(nums, dens, out=np.full(nums.shape, np.nan), where=dens > 0)
    for j, (i, _, _) in enumerate(vectors):
        result[i]['ci_low'], result[i]['ci_high'] = np.nanquantile(draws[:, j], [0.025, 0.975])
    return result


def display(row, interval=True):
    v = row['value']
    if row['unit'].startswith('fraction'):
        text = f'{100*v:.1f}%'
    else:
        text = f'{v:,.0f}' if float(v).is_integer() else f'{v:,.1f}'
    if interval and row['ci_low'] != '':
        text += f" [{100*row['ci_low']:.1f}, {100*row['ci_high']:.1f}]"
    return text


def main():
    config = constants()
    old, old_meta, new, new_meta, shared = load_inputs(config['COLLAPSE'])
    topics = config['TOPIC_ORDER']
    for row in old + new:
        row['topic'] = config['COLLAPSE'].get(row['topic'], row['topic'])
        assert row['topic'] in topics
    new_only = [r for r in new if r['key'] not in old_meta]
    old_only = [r for r in old if r['key'] not in new_meta]
    cohorts = {
        'primary': (old + new_only, {**new_meta, **old_meta}),
        'alternative': (old_only + new, {**old_meta, **new_meta}),
        'original_64': (old, old_meta),
        'new_only_298': (new_only, {k: v for k, v in new_meta.items() if k not in old_meta}),
    }
    results = {name: metrics(rows, repos, topics) for name, (rows, repos) in cohorts.items()}
    check = metrics(new, new_meta, topics)
    by_metric = {r['metric']: r for r in check}
    correspondence = {'policy_fraction': 'policy_fraction', 'system_state_fraction': 'system_observable_fraction',
                      'context_required_fraction': 'context_dependent_fraction',
                      'cross_event_project_share': 'cross_event_repo_share', 'os_enforceable_count': 'os_enforceable'}
    checks = []
    for r in read(SCALE / 'summary.csv'):
        if r.get('group_type') != 'overall' or r.get('group') != 'all':
            continue
        calculated = by_metric[correspondence[r['metric']]]
        assert np.isclose(calculated['value'], float(r['value']), rtol=0, atol=1e-14)
        checks.append(dict(metric=r['metric'], numerator=calculated['numerator'], denominator=calculated['denominator'],
                           recomputed_value=calculated['value'], published_value=r['value'], status='exact_match'))
    assert len(checks) == 5 and by_metric['os_enforceable']['value'] == 7118
    write(HERE / 'source_headline_check.csv', checks)
    write(HERE / 'numbers.csv', [dict(cohort=name, **r) for name, rs in results.items() for r in rs])
    membership = []
    for key in sorted(set(old_meta) | set(new_meta)):
        a, b = old_meta.get(key), new_meta.get(key)
        membership.append(dict(repo=(a or b)['repo'], overlap=bool(a and b),
            primary_source=(a or b)['source'], alternative_source=(b or a)['source'],
            original_statements=sum(r['key'] == key for r in old),
            scale_statements=sum(r['key'] == key for r in new),
            original_files=a['inventory_files'] if a else '', scale_files=b['inventory_files'] if b else ''))
    write(HERE / 'repository_membership.csv', membership)
    repository_counts = []
    for source_rows, metadata in [(old, old_meta), (new, new_meta)]:
        grouped_source = defaultdict(list)
        for row in source_rows:
            grouped_source[row['key']].append(row)
        for key, rows in sorted(grouped_source.items()):
            policies = [r for r in rows if r['type'] == 'directive']
            repository_counts.append(dict(repo=metadata[key]['repo'], source=metadata[key]['source'],
                statements=len(rows), policies=len(policies), descriptions=len(rows)-len(policies),
                policy_fraction=len(policies)/len(rows),
                **{e: sum(r['enforceability'] == e for r in policies) for e in config['ENF_LEVELS']}))
    write(HERE / 'repository_counts.csv', repository_counts)
    layout = HERE / 'layout'
    layout.mkdir(exist_ok=True)
    grouped = defaultdict(list)
    for row in cohorts['primary'][0]:
        grouped[row['key']].append({d: row[d] for d in AXES})
    assert not ({p.name for p in layout.iterdir() if p.is_dir()} - {k.replace('/', '__') for k in grouped})
    for key, rows in grouped.items():
        dest = layout / key.replace('/', '__')
        dest.mkdir(exist_ok=True)
        (dest / 'statements.yaml').write_text(yaml.safe_dump(dict(statements=rows), sort_keys=False))
    hashes = [dict(source=str(p.relative_to(INPUT)), bytes=p.stat().st_size, sha256=sha(p.read_bytes()))
              for p in sorted(INPUT.rglob('*')) if p.is_file()]
    write(HERE / 'source_hashes.csv', hashes)
    (HERE / 'environment.txt').write_text('\n'.join([
        f'Python {platform.python_version()}', f'numpy {np.__version__}', f'matplotlib {matplotlib.__version__}',
        f'PyYAML {yaml.__version__}', f'bootstrap seed {SEED}', f'bootstrap replicates {REPLICATES}',
        'execution: actplane-dev /workspaces/exp/corpus-merge/src', '']) )
    table = ['| Measure | Paper value | Merged primary | Merged alternative | 64-only | 298-only |',
             '|---|---:|---:|---:|---:|---:|']
    for i, row in enumerate(results['primary']):
        table.append('| ' + ' | '.join([row['label'], row['paper_value']] +
                     [display(results[name][i]) for name in cohorts]) + ' |')
    hash_table = ['| Input (relative to staged `.inputs/`) | Bytes | SHA-256 |', '|---|---:|---|']
    hash_table += [f"| `{r['source']}` | {r['bytes']} | `{r['sha256']}` |" for r in hashes]
    (HERE / 'README.md').write_text(README.format(table='\n'.join(table), hashes='\n'.join(hash_table)))
    for name, rs in results.items():
        print(name, {r['metric']: display(r, False) for r in rs if r['metric'] in
                    ('repositories', 'instruction_files', 'statements', 'policy_fraction',
                     'system_observable_fraction', 'context_dependent_fraction', 'os_enforceable')})
    print('PASS: original labels and hashes, final deployed labels, 325-source headlines, overlap, plot-only diff')


README = """# Merged repository empirical study

Data-analysis-only handoff, 2026-10-29. The paper repository and the two data-free waterfall diagrams are unchanged.
All computation and figure production run in the existing actplane-dev Workspace. No extraction, inference, relabeling, or prevalence correction is performed.

## Sources and repository merge

- Original: `../corpus-scale/paper_labels.csv` (2,116 statements), `paper_files.csv`, and `paper_provenance.csv`, recovered by `recover.py` from immutable ActPlane commit `63db86945c9b8618a46aa68c8de214bc4b8343d9`, snapshot 2026-05-23. Every recovered statement's text, range, and four labels is checked against that commit's `docs/corpus/<repo>/statements.yaml`. All files in the historical provenance manifest are SHA-256 verified, including raw instructions and star metadata.
- Corpus-scale: `../corpus-scale/labels.csv` is the **final accepted deployed label table**. Type/topic are frozen decisions from the Qwen3.8-27B (`qwen3.8-27b-nvfp4`) and GLM-5.3 (`zai/glm-5.3`) pipeline. Enforcement/context are the accepted rescue `r1` labels deployed by `rescue/deploy.py`. Their values are checked against `rescue/source-adjudicated.csv` and its deployment-manifest hash. The frozen type/topic fingerprint is checked against `rescue/retained_axes.csv`.
- `analysis_statements.csv` supplies repository/file membership and is checked row by row against `labels.csv` for all four axes and against `statements.csv` for source fields. All 30,846 statement IDs and accepted labels are present, covering all 325 repositories and all 761 included repository/content pairs. The five headline values in `summary.csv` are reproduced exactly before any merge; see `source_headline_check.csv`: 53.0053%, 76.4098%, 80.1009%, 86.4615%, and 7,118. Misclassification-corrected estimates and pre-rescue failed labels are not used.
- `corpus_manifest.csv` supplies the byte-deduplicated included file inventory. `repositories.csv` supplies stars at the 2026-10-28 snapshot. Historical stars come from the selected May metadata. Stars follow the retained repository version in each merge, with no live refresh.
- Primary: keep **all original statements and labels for all 64 original repositories**, including the 27 overlaps; append the 298 new-only corpus-scale repositories. Alternative: retain 37 original-only repositories and all 325 corpus-scale repositories. Each has exactly 362 repository identities. Case-insensitive `owner/name` comparison matches `snapshot_overlap.csv`; repository renames are not inferred. No repository is included twice. `repository_membership.csv` records every selection.

## Definitions and denominators

`directive` means policy and `description` means descriptive statement. The exact `COLLAPSE` map and 12-topic order are read from the copied original plot script: Debugging and Project Management become Development Process; Performance and UI/UX become Implementation Details. No other topic remapping occurs.

The four tiers are `semantic_only`, `content`, `per_event`, and `cross_event`. System-observable = content + per_event + cross_event. OS-enforceable candidates = per_event + cross_event. These taxonomy counts do not establish that the current engine implements every predicate. Enforcement percentages divide by policies. Context percentages divide by system-observable policies, except the explicitly named tier-specific rows. `none` is self-contained, `project` and `task` are context-dependent. Repository prevalence uses all repositories, including repositories with no policies. Majority is strictly more policies than descriptions. The Development Process cross-event row divides by **all cross-event policies**, matching the paper's statement that this topic accounts for 39.5% of them.

Instruction-file inventory follows each source's historical convention: within a repository identical bytes count once, and the May inventory additionally excludes pure `@AGENTS.md` / `@CLAUDE.md` redirect files. The October inventory retains selected redirects. **The original 84 inventory files have labels for only 64 primary files.** The `Files with statement labels` row makes this coverage difference explicit. File counts are additive across selected repository identities; identical templates in different repositories remain separate.

## Recomputed paper numbers

Every percentage is recomputed from its numerator and denominator, without averaging repository percentages. Brackets give 95% repository-bootstrap intervals, expressed as percentages. Counts and extrema have no interval. Paper values are the operator-provided current-paper values, retained verbatim, rather than treated as exact recomputed historical values. `unavailable` means that no current-paper value was supplied for that row. `numbers.csv` contains unrounded fractions, integer numerators and denominators, both interval endpoints, and the four cohorts.

{table}

## Bootstrap method

For each cohort independently, sample N whole repositories uniformly with replacement N times per replicate, retaining every statement of each selected repository with multiplicity. Use 10,000 replicates, NumPy `default_rng(20261029)`, sorted case-folded repository identities, multinomial multiplicity vectors, and central percentile endpoints (2.5%, 97.5%, NumPy linear quantiles). Within each replicate recompute pooled ratios of sums. The repository-share rows instead average repository indicators. Intervals are supplied for all ratio rows, including all headline shares in items 2, 4, 6 and both repository shares in item 5. Undefined zero-denominator replicates are omitted from percentile calculation. Counts, median stars and per-repository extrema are descriptive point values.

This is an ordinary, unstratified repository cluster bootstrap of each merged convenience sample. Unlike the earlier corpus-scale summary's 2,000 discovery-stratified draws, it applies the same method to all four requested cohorts. It does not estimate uncertainty from model error, human error, segmentation, eligibility, snapshot mixing, selection bias, or correlated templates. The primary and alternative share repository identities; their intervals are marginal, not a paired test of differences.

## Annotation checks and limitations

The paper reports an LLM-agent extraction/labeling pipeline, span/coverage checks, independent Claude and Codex cross-checking, and a stratified **100-statement human check**. This analysis retains those historical labels unchanged. The exact historical invocation prompts and human-check sample were not recovered, so that human check cannot be re-audited here. The original source-fidelity audit found 417 exact-formatting differences but zero whitespace-normalized mismatches; this merge preserves the annotated text rather than re-extracting it.

For the corpus-scale final type/topic pipeline, `format_calibration_summary.csv` reports adjudicated Cohen's kappa **0.830704 / 0.679778**, with 2,116/2,116 reference statements evaluated. Individual Qwen kappas are 0.814768 / 0.692569, and GLM kappas are 0.803433 / 0.661046. These are agreement with the historical reference, not human ground truth for the expanded corpus.

The original full-guide enforcement/context calibration failed (adjudicated kappa 0.594 / 0.191). Those failed-axis predictions are not the final labels used here. The rescue split uses 21 development repositories (505 statements) and 43 test repositories (1,611 statements). Revision r1's adjudicated test kappas are **0.694233 enforcement** (1,017 applicable historical directives) and **0.679333 context** (865 applicable system-observable directives), at 100% coverage. Individual test kappas are Qwen 0.662778 / 0.646199 and GLM 0.681311 / 0.720348. The split is held out from rescue revision/selection only: all historical labels had earlier aggregate diagnostic exposure. Context calibration conditions on original directives, while deployment conditions on the frozen automated directive set. Qwen rereads disagreements, so adjudication is correlated with a primary model. No new human audit validates segmentation, additional instruction families or noncoding files.

The May snapshot uses CLAUDE.md/AGENTS.md and coding-focused eligibility. The October snapshot uses eight families (CLAUDE.md, AGENTS.md, GEMINI.md, copilot-instructions.md, .cursor/rules/*, .cursorrules, .windsurfrules, SKILL.md), broader discovery/eligibility, capped family selection and automated segmentation. Labels, snapshot dates, file coverage, file inventory conventions and labelers therefore differ. These are merged descriptive counts, not a longitudinal effect or population estimate. In particular more observed files can increase repository cross-event prevalence.

Several supplied paper values do not match recomputation of the original labels: majority-policy repositories 73.4% versus 70.1%, maximum policy share 100% versus 97%, Development Process and Implementation Details policy shares 88.1% / 86.9% versus 87% / 85%, cross-event repositories 79.7% versus 81%, and repositories spanning all tiers 42.2% versus 43%. The 64-only column deliberately exposes these discrepancies; it is not adjusted to reproduce prose numbers. The supplied largest-per-repository count of 66 is reproduced for **OS-tier** policies: the original openclaw/openclaw repository has 131 total policies, including 45 per-event and 21 cross-event policies. Both maxima are reported explicitly to avoid confusing these scopes. `repository_counts.csv` records both snapshots' per-repository counts for inspection. Rounded context subcategories may not sum to the separately rounded context-dependent percentage.

## Figures and reproduction

The four primary-merge figures preserve the original script's style, sizes, colors, sorting, order and labels. `plot_empirical.diff` contains only the output-directory change and `pdf.fonttype = 42` / `ps.fonttype = 42`. The script still reads `<repo>/statements.yaml` from its working directory; `analyze_merge.py` creates the ignored primary `layout/`. `verify_figures.py` checks the original plot's actual loaded repository, topic, enforcement and context counts against the primary numerical table. The original coloring of exactly-50% repositories (`>=50`) is retained, while the numerical majority metric uses the paper's strict `>50%` definition. The unchanged legend locations overlay portions of some bars and labels, as visible in the previews; no layout redesign is made. No waterfall is copied or regenerated. PDFs, PNG previews and `pdffonts` output are under `figures/`.

From this repository root in Windows PowerShell:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File docs/empirical-study/corpus-merge/stage_inputs.ps1
& "C:\\Program Files\\Git\\bin\\bash.exe" C:/Users/10678/actplane-tools/ws.sh run corpus-merge -- bash setup.sh
& "C:\\Program Files\\Git\\bin\\bash.exe" C:/Users/10678/actplane-tools/ws.sh run corpus-merge -- bash run.sh
& "C:\\Program Files\\Git\\bin\\bash.exe" C:/Users/10678/actplane-tools/ws.sh pull corpus-merge src/README.md src/numbers.csv src/source_hashes.csv src/source_headline_check.csv src/repository_membership.csv src/repository_counts.csv src/environment.txt src/plot_empirical.diff src/figures
```

`stage_inputs.ps1` only copies inputs and exports the immutable historical corpus subtree without checking out another branch. It requires the sibling paper checkout as specified by the operator. `.inputs/` is ignored to avoid duplicating already committed datasets. `ws.sh run` performs sync after local edits. The helper's pull places files under a nested local `src/`; move those returned artifacts into this lane directory. All Python analysis, bootstrapping, plotting, font checks and rendering occur inside actplane-dev. Python/library versions are in `environment.txt`; setup pins the three direct Python dependencies. Data inputs below must match before interpreting a rerun.

The source-label checks, merged-count checks, plot-loaded-data checks, and four `pdffonts` checks passed in the Workspace. PNG previews were visually inspected. Branch-wide CI on the initial data commit failed in an unrelated, unchanged libbpf build: GCC reports discarded const qualifiers as errors in `libbpf.c` (`kallsyms_cb`, `avail_kallsyms_cb`, `resolve_full_path`). See [CI run 40949503058](https://github.com/eunomia-bpf/ActPlane/actions/runs/40949503058). No kernel, vendored library, build configuration, or workflow repair is included in this data-only lane. No PR was opened.

## Input hashes

The `scale/` paths are byte copies of the corresponding sibling `../corpus-scale/` files. `original.tar` is the deterministic archive of the immutable historical corpus subtree. `plot_empirical.original.py` and `02-motivation.tex` are read-only snapshots from the paper repository. The latter is documentation context, not an input to counting or labeling. Per-historical-file hashes are additionally checked against `paper_provenance.csv`. Full hashes are also machine-readable in `source_hashes.csv`.

{hashes}
"""


if __name__ == '__main__':
    main()
