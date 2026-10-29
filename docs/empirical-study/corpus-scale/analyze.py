#!/usr/bin/env python3
"""Compute all reported numbers, calibration gates, and descriptive intervals.

Intervals resample repositories, preserving discovery strata for the new corpus.
They express sensitivity within the observed convenience sample, not a random
sample confidence claim about all GitHub repositories. No failed label is silently
converted into a negative example.
"""
import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
from sklearn.metrics import cohen_kappa_score

from common import HERE, read_csv, write_csv
from label import DIMS

SEED = 20261028
BOOTSTRAPS = 2000
MIN_KAPPA = .60
MIN_PRIMARY_KAPPA = .40
MIN_COVERAGE = .98


def kappa(left, right):
    if not left:
        return float('nan')
    if len(set(left + right)) == 1:
        return float('nan')
    return float(cohen_kappa_score(left, right))


def eligible(row, dim):
    if dim in ('type', 'topic'):
        return True
    if dim == 'enforceability':
        return row['type'] == 'directive'
    return row['type'] == 'directive' and row['enforceability'] in ('content', 'per_event', 'cross_event')


def calibration(prefix='calibration', dimensions=None):
    dimensions = dimensions or DIMS
    gold = read_csv(HERE / 'paper_labels.csv')
    predictions = {}
    for name in ('qwen', 'glm', 'adjudicated'):
        path = HERE / f'{prefix}_{name}.csv'
        if path.exists():
            predictions[name] = {r['statement_id']: r for r in read_csv(path)}
    results, confusion = [], []
    for model, pred in predictions.items():
        for dim in dimensions:
            for scope in ('applicable_gold', 'all_including_na'):
                base = [r for r in gold if scope == 'all_including_na' or eligible(r, dim)]
                pairs = [(g.get(dim, '') or '__NA__', pred[g['statement_id']].get(dim, '') or '__NA__')
                         for g in base if pred.get(g['statement_id'], {}).get('status') == 'ok']
                left, right = ([x[0] for x in pairs], [x[1] for x in pairs])
                results.append(dict(model=model, dimension=dim, scope=scope,
                    expected=len(base), evaluated=len(pairs), missing=len(base) - len(pairs),
                    coverage=len(pairs) / len(base), agreement=np.mean(np.array(left) == np.array(right)) if pairs else '',
                    kappa=kappa(left, right)))
                for (g, p), count in Counter(pairs).items():
                    confusion.append(dict(model=model, dimension=dim, scope=scope, gold=g, prediction=p, count=count))
    if 'qwen' in predictions and 'glm' in predictions:
        for dim in dimensions:
            pairs = [(predictions['qwen'][g['statement_id']].get(dim, '') or '__NA__',
                      predictions['glm'][g['statement_id']].get(dim, '') or '__NA__')
                     for g in gold if eligible(g, dim) and
                     all(predictions[n].get(g['statement_id'], {}).get('status') == 'ok' for n in ('qwen', 'glm'))]
            left, right = [p[0] for p in pairs], [p[1] for p in pairs]
            results.append(dict(model='inter_model', dimension=dim, scope='applicable_gold',
                expected=sum(eligible(g, dim) for g in gold), evaluated=len(pairs),
                kappa=kappa(left, right), agreement=np.mean(np.array(left) == np.array(right)) if pairs else ''))
    write_csv(HERE / f'{prefix}_summary.csv', results)
    write_csv(HERE / f'{prefix}_confusion.csv', confusion)
    index = {(r['model'], r['dimension']): r for r in results if r['scope'] == 'applicable_gold'}
    gates = []
    for dim in dimensions:
        records = [index.get((model, dim), {}) for model in ('qwen', 'glm', 'adjudicated')]
        passed = all(r.get('coverage', 0) >= MIN_COVERAGE for r in records)
        passed = passed and records[-1].get('kappa', -1) >= MIN_KAPPA
        passed = passed and all(r.get('kappa', -1) >= MIN_PRIMARY_KAPPA for r in records[:2])
        gates.append(dict(dimension=dim, passed=passed, min_final_kappa=MIN_KAPPA,
            min_primary_kappa=MIN_PRIMARY_KAPPA, min_coverage=MIN_COVERAGE,
            reason='passed' if passed else 'incomplete_or_below_prespecified_threshold'))
    # A dependent dimension cannot bypass a failed parent gate.
    by_dim = {r['dimension']: r for r in gates}
    for dim in ('topic', 'enforceability', 'context_required'):
        if dim in by_dim and not by_dim['type']['passed']:
            by_dim[dim].update(passed=False, reason='type_gate_failed')
    if 'context_required' in by_dim and not by_dim.get('enforceability', {}).get('passed', False):
        by_dim['context_required'].update(passed=False, reason='enforcement_gate_failed')
    write_csv(HERE / f'{prefix}_gates.csv', gates)
    return gates


def metric_vector(rows, repository_names):
    """Numerator/denominator contributions per repository for clustered CIs."""
    names = list(repository_names)
    grouped = defaultdict(list)
    for r in rows:
        grouped[r['repo']].append(r)
    keys = ['policy_fraction', 'system_state_fraction', 'context_required_fraction',
            'cross_event_project_share', 'os_enforceable_count']
    values = np.zeros((len(names), len(keys), 2))
    for i, name in enumerate(names):
        r = grouped[name]
        policies = [x for x in r if x['type'] == 'directive']
        system = [x for x in policies if x.get('enforceability') in ('content', 'per_event', 'cross_event')]
        vals = [(len(policies), len(r)), (len(system), len(policies)),
                (sum(x.get('context_required') in ('project', 'task') for x in system), len(system)),
                (int(any(x.get('enforceability') == 'cross_event' for x in policies)), 1),
                (sum(x.get('enforceability') in ('per_event', 'cross_event') for x in policies), 1)]
        values[i] = vals
    return keys, values


def bootstrap(values, strata, seed=SEED):
    rng = np.random.default_rng(seed)
    draws = np.zeros((BOOTSTRAPS, values.shape[1], 2))
    groups = defaultdict(list)
    for i, s in enumerate(strata):
        groups[s].append(i)
    for members in groups.values():
        indices = rng.choice(members, size=(BOOTSTRAPS, len(members)), replace=True)
        draws += values[indices].sum(axis=1)
    result = np.divide(draws[:, :, 0], draws[:, :, 1],
                       out=np.full(draws.shape[:2], np.nan), where=draws[:, :, 1] != 0)
    # OS count is a corpus count, so its bootstrap is not a population estimate.
    result[:, -1] = draws[:, -1, 0]
    return result


def summarize(rows, repos, gates=None, source='new', seed=SEED):
    keys, values = metric_vector(rows, list(repos))
    draws = bootstrap(values, [r.get('stratum', 'paper') for r in repos.values()], seed=seed)
    totals = values.sum(axis=0)
    summary = []
    for i, key in enumerate(keys):
        numerator, denominator = totals[i]
        value = numerator if key == 'os_enforceable_count' else numerator / denominator if denominator else float('nan')
        need = {'policy_fraction': 'type', 'system_state_fraction': 'enforceability',
                'context_required_fraction': 'context_required', 'cross_event_project_share': 'enforceability',
                'os_enforceable_count': 'enforceability'}[key]
        valid = gates is None or gates.get(need, False)
        defined = key == 'os_enforceable_count' or denominator > 0
        lo, hi = np.nanquantile(draws[:, i], [.025, .975]) if np.isfinite(draws[:, i]).any() else (float('nan'), float('nan'))
        summary.append(dict(source=source, metric=key, numerator=int(numerator) if valid else '', denominator=int(denominator) if valid else '',
            value=value if valid and defined else '', ci_low=lo if valid and defined else '', ci_high=hi if valid and defined else '',
            status=('withheld_calibration_failed' if not valid else
                    'undefined_zero_denominator' if not defined else 'ok'),
            repositories=len(repos), statements=len(rows)))
    return summary, draws


def compare(summary, draws, baseline, baseline_draws):
    for i, row in enumerate(summary):
        if row['status'] == baseline[i]['status'] == 'ok':
            row['artifact_delta'] = row['value'] - baseline[i]['value']
            diff = draws[:, i] - baseline_draws[:, i]
            row['delta_ci_low'], row['delta_ci_high'] = np.nanquantile(diff, [.025, .975])


def analyze():
    from effective_gates import load_gates
    gates = load_gates()
    paper = read_csv(HERE / 'paper_labels.csv')
    paper_repos = {r['repo']: r for r in read_csv(HERE / 'paper_files.csv')}
    baseline, baseline_draws = summarize(paper, paper_repos, source='paper_artifact', seed=SEED + 1)
    write_csv(HERE / 'paper_summary.csv', baseline)
    baseline_families, historical_families = {}, []
    for family in sorted({r['family'] for r in paper}):
        subset = [r for r in paper if r['family'] == family]
        rs = {r['repo']: paper_repos[r['repo']] for r in subset}
        ss, family_draws = summarize(subset, rs, source='paper_artifact', seed=SEED + 1)
        baseline_families[family] = (ss, family_draws)
        historical_families.extend(dict(r, group_type='family', group=family) for r in ss)
    write_csv(HERE / 'paper_family_summary.csv', historical_families)
    if (HERE / 'repositories.csv').exists():
        from describe_corpus import main as describe_corpus
        describe_corpus()
        snapshot = read_csv(HERE / 'repositories.csv')
        overview = []
        for dimension in ('stratum', 'language'):
            for label in sorted({r.get(dimension, '') or 'unspecified' for r in snapshot}):
                rs = [r for r in snapshot if (r.get(dimension, '') or 'unspecified') == label]
                stars = [int(r['stars']) for r in rs]
                overview.append(dict(dimension=dimension, label=label, repositories=len(rs),
                    stars_min=min(stars), stars_median=float(np.median(stars)), stars_max=max(stars)))
        stars = [int(r['stars']) for r in snapshot]
        if stars:
            overview.append(dict(dimension='overall', label='all', repositories=len(snapshot),
                stars_min=min(stars), stars_median=float(np.median(stars)), stars_max=max(stars)))
        write_csv(HERE / 'corpus_overview.csv', overview)
    statements_path = HERE / 'statements.csv'
    labels_path = HERE / 'labels.csv'
    if not statements_path.exists() or not labels_path.exists():
        return
    repos = {r['repo']: r for r in read_csv(HERE / 'repositories.csv')}
    labels = {r['statement_id']: r for r in read_csv(labels_path)}
    statements = read_csv(statements_path)
    # Complete-case file inclusion avoids pretending missing portions are negatives.
    by_file = defaultdict(list)
    for s in statements:
        by_file[(s['repo'], s['content_sha256'])].append(s)
    complete_files = {key for key, ss in by_file.items()
                      if all(labels.get(s['statement_id'], {}).get('status') == 'ok' for s in ss)}
    manifest = read_csv(HERE / 'corpus_manifest.csv')
    required = defaultdict(set)
    for f in manifest:
        if f['status'] == 'included':
            required[f['repo']].add((f['repo'], f['content_sha256']))
    fully_labeled_repos = {repo for repo, files in required.items() if files <= complete_files}
    joined = [dict(s, **{d: labels[s['statement_id']].get(d, '') for d in DIMS})
              for s in statements if (s['repo'], s['content_sha256']) in complete_files and s['repo'] in fully_labeled_repos]
    complete_repos = {r['repo'] for r in joined}
    selected_repos = {k: v for k, v in repos.items() if k in complete_repos}
    summary, draws = summarize(joined, selected_repos, gates)
    compare(summary, draws, baseline, baseline_draws)
    summaries = [dict(r, group_type='overall', group='all') for r in summary]
    categories_path = HERE / 'repository_categories.csv'
    categories = {repo: 'unclassified' for repo in repos}
    if categories_path.exists():
        categories.update({r['repo']: r.get('category', 'unclassified') for r in read_csv(categories_path)})
    for category in sorted(set(categories.values())):
        rs = {k: v for k, v in selected_repos.items() if categories.get(k) == category}
        subset = [s for s in joined if s['repo'] in rs]
        if rs:
            ss, _ = summarize(subset, rs, gates)
            summaries.extend(dict(r, group_type='category', group=category) for r in ss)
    # Attribute a byte-identical alias to each family it actually appears in,
    # while overall counts use each unique repository/content pair only once.
    families = defaultdict(set)
    for f in manifest:
        if f['status'] == 'included':
            families[f['family']].add((f['repo'], f['content_sha256']))
    for fam, pairs in sorted(families.items()):
        subset = [s for s in joined if (s['repo'], s['content_sha256']) in pairs]
        rs = {s['repo']: repos[s['repo']] for s in subset}
        if rs:
            ss, family_draws = summarize(subset, rs, gates)
            if fam in baseline_families:
                compare(ss, family_draws, *baseline_families[fam])
            summaries.extend(dict(r, group_type='family', group=fam) for r in ss)
    scopes_path = HERE / 'file_scopes.csv'
    if scopes_path.exists():
        scopes = {(s['repo'], s['content_sha256']): 'unclassified' for s in joined}
        scopes.update({(r['repo'], r['content_sha256']): r['scope'] for r in read_csv(scopes_path) if r['status'] == 'ok'})
        for scope in sorted(set(scopes.values())):
            subset = [s for s in joined if scopes.get((s['repo'], s['content_sha256'])) == scope]
            rs = {s['repo']: repos[s['repo']] for s in subset}
            if rs:
                ss, _ = summarize(subset, rs, gates)
                summaries.extend(dict(r, group_type='file_scope', group=scope) for r in ss)
        noncoding = [s for s in joined if scopes.get((s['repo'], s['content_sha256'])) == 'noncoding_assistance']
        export_fields = [*statements[0].keys(), *DIMS, 'scope', 'model', 'adjudicated', 'retry_protocol']
        write_csv(HERE / 'noncoding_statements.csv', [dict(s, scope='noncoding_assistance',
            **{key: labels[s['statement_id']].get(key, '') for key in ['model', 'adjudicated', 'retry_protocol']})
            for s in noncoding], export_fields)
        pairs = {(s['repo'], s['content_sha256']) for s in noncoding}
        write_csv(HERE / 'noncoding_manifest.csv',
            [dict(f, scope='noncoding_assistance') for f in manifest
             if f['status'] == 'included' and (f['repo'], f['content_sha256']) in pairs],
            [*manifest[0].keys(), 'scope'])
    write_csv(HERE / 'summary.csv', summaries)
    write_csv(HERE / 'analysis_statements.csv', [{k: v for k, v in s.items() if k != 'text'} for s in joined])
    write_csv(HERE / 'analysis_coverage.csv', [dict(
        collected_repositories=len(repos), extracted_repositories=len({r['repo'] for r in statements}),
        analyzed_repositories=len(selected_repos), extracted_statements=len(statements),
        analyzed_statements=len(joined), complete_files=len(complete_files),
        incomplete_files=len(by_file) - len(complete_files),
        repositories_with_incomplete_sources=len(repos) - len(selected_repos),
        selected_source_files=sum(len(files) for files in required.values()),
        extracted_source_files=len(by_file))])
    breakdown = []
    for group_type, groups in [('topic', {s['topic'] for s in joined}), ('enforceability', {s['enforceability'] for s in joined}),
                               ('context_required', {s['context_required'] for s in joined})]:
        if not gates.get(group_type, False):
            continue
        for group in sorted(groups):
            subset = [s for s in joined if s[group_type] == group]
            breakdown.append(dict(dimension=group_type, label=group, statements=len(subset),
                                  directives=sum(s['type'] == 'directive' for s in subset)))
    write_csv(HERE / 'label_breakdown.csv', breakdown)
    from agreement import main as model_agreement
    model_agreement()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--calibration-only', action='store_true')
    a = p.parse_args()
    calibration()
    if not a.calibration_only:
        analyze()


if __name__ == '__main__':
    main()
