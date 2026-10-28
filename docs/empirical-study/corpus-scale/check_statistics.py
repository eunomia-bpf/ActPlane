#!/usr/bin/env python3
"""Known-answer checks for policy denominators, project units, and kappa."""
import numpy as np

from analyze import kappa, metric_vector, summarize
from common import HERE, write_csv


def main():
    # Three repositories, including a description-only project. These explicit
    # outcomes catch accidental policy-only project denominators and averages of
    # per-project statement fractions in place of pooled statement fractions.
    rows = [dict(repo='a', type='directive', enforceability='cross_event', context_required='project'),
            dict(repo='a', type='description', enforceability='', context_required=''),
            dict(repo='b', type='directive', enforceability='content', context_required='none'),
            dict(repo='b', type='directive', enforceability='semantic_only', context_required=''),
            dict(repo='b', type='description', enforceability='', context_required=''),
            dict(repo='c', type='description', enforceability='', context_required='')]
    summary, _ = summarize(rows, {repo: {} for repo in 'abc'})
    expected = dict(policy_fraction=.5, system_state_fraction=2/3,
        context_required_fraction=.5, cross_event_project_share=1/3, os_enforceable_count=1)
    checks = [dict(check=r['metric'], expected=expected[r['metric']], actual=r['value']) for r in summary]
    checks.append(dict(check='kappa_known_contingency_table', expected=.5,
                       actual=kappa(['a', 'a', 'b', 'b'], ['a', 'b', 'b', 'b'])))
    # Repeating identical projects leaves a pooled proportion's bootstrap
    # interval degenerate at the known proportion, independent of resampling.
    same = [dict(r, repo=repo) for repo in 'abc' for r in rows[:2]]
    result, _ = summarize(same, {repo: {} for repo in 'abc'})
    policy = next(r for r in result if r['metric'] == 'policy_fraction')
    checks.extend(dict(check='identical_projects_' + field, expected=.5, actual=policy[field])
                  for field in ['value', 'ci_low', 'ci_high'])
    for r in checks:
        r['passed'] = bool(np.isclose(r['expected'], r['actual']))
    write_csv(HERE / 'statistics_validation.csv', checks)
    if not all(r['passed'] for r in checks):
        raise SystemExit('Statistics validation failed')
    print(checks)


if __name__ == '__main__':
    main()
