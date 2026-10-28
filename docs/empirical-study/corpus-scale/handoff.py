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
        interval = f'{lo}–{hi}' if lo and hi else 'withheld'
        lines.append(f'| {r["metric"]} | {value or "withheld"} | {interval} | {r["status"]} |')
    lines += ['', '| Calibration | Dimension | Applicable N | Kappa |', '|---|---|---:|---:|']
    for name in ['calibration', 'format_calibration']:
        path = HERE / (name + '_summary.csv')
        if not path.exists():
            continue
        for r in read_csv(path):
            if r['model'] == 'adjudicated' and r['scope'] == 'applicable_gold':
                lines.append(f'| {name} | {r["dimension"]} | {r["evaluated"]} | {float(r["kappa"]):.3f} |')
    audit = read_csv(HERE / 'paper_audit.csv')[0]
    baseline = {r['metric']: r for r in read_csv(HERE / 'paper_summary.csv')}
    claims = {r['metric']: r for r in read_csv(HERE / 'paper_claims.csv')}
    cross = baseline['cross_event_project_share']
    lines += ['', f'Historical caveats: the recovered annotations reference {audit["referenced_source_files"]} primary files, '
              f'while the deduplicated non-redirect inventory contains {audit["unique_non_redirect_files"]} files. '
              'The labels do not establish coverage of every additional file. '
              f'The recovered cross-event project share is {cross["numerator"]}/{cross["denominator"]} '
              f'({100*float(cross["value"]):.1f}%), versus the paper claim of '
              f'{100*float(claims["cross_event_project_share"]["value"]):.1f}%. '
              'Both supplied historical branches contain identical annotations.']
    figure_path = HERE / 'figure_manifest.csv'
    if figure_path.exists():
        lines += ['', '| Paper figure | Status | PDF |', '|---|---|---|']
        lines.extend(f'| {r["paper_figure"]} | {r["status"]} | {r["file"]} |' for r in read_csv(figure_path))
        lines += ['', 'Withheld PDFs are placeholders and must not be inserted as updated results.']
    lines += ['', f'Artifacts: `{HERE}`', '',
              'Raw downloads and logs: `/workspaces/.agent-state/actplane-research/raw/corpus-scale-20261028`', '',
              'Open caveats: convenience/star/query sampling; automated statement boundaries; historical reference conventions and missing human review sample; correlated model adjudication; exploratory model-based file scopes; withheld dimensions must not replace paper claims. See README.md and calibration tables for exact agreement and limitations.', '',
              'No paper files were edited. Operator handoff is branch-only; no further PR activity was performed after the update.']
    a.state.mkdir(parents=True, exist_ok=True)
    (a.state / 'SUMMARY.md').write_text('\n'.join(lines) + '\n')


if __name__ == '__main__':
    main()
