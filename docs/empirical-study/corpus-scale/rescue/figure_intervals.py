#!/usr/bin/env python3
"""Repository-bootstrap companions for the four rescued paper figures."""
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from analyze import BOOTSTRAPS, SEED
from common import HERE, read_csv, write_csv


def main():
    rows = read_csv(HERE / 'analysis_statements.csv')
    repo_metadata = {r['repo']: r for r in read_csv(HERE / 'repositories.csv')}
    names = sorted({r['repo'] for r in rows})
    index = {name: i for i, name in enumerate(names)}
    strata = defaultdict(list)
    for name in names:
        strata[repo_metadata[name]['stratum']].append(index[name])
    policy = [r for r in rows if r['type'] == 'directive']
    system = [r for r in policy if r['enforceability'] in ('content', 'per_event', 'cross_event')]
    results = []
    for cell in read_csv(HERE / 'figure_data.csv'):
        figure, group, label = [cell[k] for k in ['figure', 'group', 'label']]
        if cell['group'] == 'withheld':
            continue
        if figure == 'empirical-waterfall-enforcement-horizontal':
            base, axis = policy, 'enforceability'
            wanted = {'Semantic only': 'semantic_only', 'Content': 'content',
                      'Per event': 'per_event', 'Cross event': 'cross_event'}[label]
        elif figure == 'empirical_rq3_enforcement_by_topic':
            base, axis, wanted = [r for r in policy if r['topic'] == group], 'enforceability', label
        elif figure == 'empirical-waterfall-context-horizontal':
            base, axis = system, 'context_required'
            wanted = {'Self-contained': 'none', 'Project': 'project', 'Task': 'task'}[label]
        elif figure == 'empirical_rq4_context_by_enforcement':
            base, axis, wanted = [r for r in system if r['enforceability'] == group], 'context_required', label
        else:
            continue
        values = np.zeros((len(names), 2))
        for row in base:
            values[index[row['repo']]] += (row[axis] == wanted, 1)
        total = values.sum(axis=0)
        assert total[0] == int(cell['value']) and total[1] == int(cell['denominator'])
        rng = np.random.default_rng(SEED)
        draws = np.zeros((BOOTSTRAPS, 2))
        for members in strata.values():
            draws += values[rng.choice(members, size=(BOOTSTRAPS, len(members)), replace=True)].sum(axis=1)
        ratios = np.divide(draws[:, 0], draws[:, 1], out=np.full(BOOTSTRAPS, np.nan), where=draws[:, 1] > 0)
        valid = np.isfinite(ratios)
        low, high = np.nanquantile(ratios, [.025, .975]) if valid.any() else ('', '')
        count_low, count_high = np.quantile(draws[:, 0], [.025, .975])
        results.append(dict(figure=figure, group=group, label=label,
            numerator=int(total[0]), denominator=int(total[1]),
            value=total[0] / total[1] if total[1] else '', ci_low=low, ci_high=high,
            count_ci_low=count_low, count_ci_high=count_high,
            successful_bootstraps=int(valid.sum()), bootstrap_replicates=BOOTSTRAPS,
            bootstrap_seed=SEED, method='repository_bootstrap_within_discovery_strata',
            status='ok' if total[1] else 'undefined_zero_denominator'))
    write_csv(HERE / 'figure_intervals.csv', results)
    print('Rescued figure interval cells:', len(results))


if __name__ == '__main__':
    main()
