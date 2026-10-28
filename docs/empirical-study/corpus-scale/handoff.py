#!/usr/bin/env python3
"""Write the operator handoff from committed CSVs and the current branch commit."""
import argparse
import subprocess
from pathlib import Path

from common import HERE, read_csv


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--state', type=Path, default=Path('/workspaces/.agent-state/actplane-corpus-scale'))
    a = p.parse_args()
    branch = subprocess.check_output(['git', '-C', str(HERE), 'branch', '--show-current'], text=True).strip()
    commit = subprocess.check_output(['git', '-C', str(HERE), 'rev-parse', 'HEAD'], text=True).strip()
    coverage = read_csv(HERE / 'analysis_coverage.csv')[0]
    rows = [r for r in read_csv(HERE / 'summary.csv') if r['group_type'] == 'overall']
    lines = ['# Corpus-scale characterization handoff', '', f'Branch: `{branch}`', f'Final commit: `{commit}`', '',
        f'Measured {coverage["analyzed_repositories"]} fully labeled repositories and {coverage["analyzed_statements"]} statements. '
        'Source repositories, commits, paths, stars, snapshot dates, exclusions, extraction status, model outputs, calibration and bootstrap summaries are committed.', '',
        '| Metric | Value | Interval | Status |', '|---|---:|---:|---|']
    for r in rows:
        value, lo, hi = r['value'], r['ci_low'], r['ci_high']
        if value:
            if r['metric'].endswith('_count'):
                value, lo, hi = [f'{float(x):,.0f}' for x in (value, lo, hi)]
            else:
                value, lo, hi = [f'{100*float(x):.1f}%' for x in (value, lo, hi)]
        lines.append(f'| {r["metric"]} | {value or "withheld"} | {lo}–{hi} | {r["status"]} |')
    lines += ['', f'Artifacts: `{HERE}`', '',
              'Raw downloads and logs: `/workspaces/.agent-state/actplane-research/raw/corpus-scale-20261028`', '',
              'Open caveats: convenience/star/query sampling; automated statement boundaries; historical reference conventions and missing human review sample; correlated model adjudication; exploratory model-based file scopes; withheld dimensions must not replace paper claims. See README.md and calibration tables for exact agreement and limitations.', '',
              'No paper files were edited. Operator handoff is branch-only; no further PR activity was performed after the update.']
    a.state.mkdir(parents=True, exist_ok=True)
    (a.state / 'SUMMARY.md').write_text('\n'.join(lines) + '\n')


if __name__ == '__main__':
    main()
