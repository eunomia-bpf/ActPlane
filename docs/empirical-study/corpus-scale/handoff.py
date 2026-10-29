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
    inventory = {r['metric']: r['value'] for r in read_csv(HERE / 'collection_summary.csv')}
    rows = [r for r in read_csv(HERE / 'summary.csv') if r['group_type'] == 'overall']
    lines = ['# Corpus-scale characterization handoff', '', f'Branch: `{branch}`', f'Final commit: `{commit}`', '',
        f'Measured {coverage["analyzed_repositories"]} fully labeled repositories and {coverage["analyzed_statements"]} statements '
        f'from {coverage["selected_source_files"]} distinct repository/content pairs '
        f'({inventory["file_status_included"]} selected paths) across {inventory["represented_file_families"]} file families. '
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
    scope_path = HERE / 'scope_coverage.csv'
    if scope_path.exists():
        scopes = read_csv(scope_path)
        lines += ['', f'Exploratory file-scope classification: {sum(r["status"] == "ok" for r in scopes)} '
                  f'of {len(scopes)} distinct repository/content pairs have accepted judgments. '
                  'Scope and repository-category judgments have no human reliability calibration.']
        subset = next((r for r in read_csv(HERE / 'summary.csv') if r['group_type'] == 'file_scope'
                       and r['group'] == 'noncoding_assistance' and r['metric'] == 'policy_fraction'), None)
        if subset and subset['status'] == 'ok':
            files = read_csv(HERE / 'noncoding_manifest.csv')
            pairs = {(r['repo'], r['content_sha256']) for r in files}
            lines += ['', f'The exploratory noncoding slice contains {len(pairs)} source pairs in '
                      f'{subset["repositories"]} repositories and {subset["statements"]} statements. '
                      f'Its automated policy fraction is {100*float(subset["value"]):.1f}% '
                      f'({100*float(subset["ci_low"]):.1f}%–{100*float(subset["ci_high"]):.1f}%). '
                      'The inspectable exports are noncoding_manifest.csv and noncoding_statements.csv.']
    lines += ['', '| Calibration | Dimension | Applicable N | Kappa |', '|---|---|---:|---:|']
    for name in ['calibration', 'format_calibration']:
        path = HERE / (name + '_summary.csv')
        if not path.exists():
            continue
        for r in read_csv(path):
            if r['model'] == 'adjudicated' and r['scope'] == 'applicable_gold':
                label = 'Initial full codebook' if name == 'calibration' else 'Deployed retained axes'
                lines.append(f'| {label} | {r["dimension"]} | {r["evaluated"]} | {float(r["kappa"]):.3f} |')
    if (HERE / 'rescue/test_gates.csv').exists():
        revision = read_csv(HERE / 'rescue/selection.csv')[0]['revision']
        lines += ['', f'Rescue revision `{revision}` was selected on development repositories and evaluated once on the frozen test split. '
                  'All original reference rows had earlier calibration/aggregate diagnostic exposure, so this is a prospective holdout for rescue tuning, not an untouched external test set.', '',
                  '| Rescue test dimension | Kappa | Coverage | Passed |', '|---|---:|---:|---|']
        for r in read_csv(HERE / 'rescue/test_gates.csv'):
            lines.append(f'| {r["dimension"]} | {float(r["test_kappa"]):.3f} | {100*float(r["coverage"]):.1f}% | {r["passed"]} |')
        lines += ['', 'Context uses the operational project-binding convention supported by the development labels. '
                  'The recovered written guide and the paper prose about fully named targets conflict with that convention. '
                  'The operator should reconcile that wording when integrating the context result. No paper source was changed in this lane.']
        corrected = HERE / 'rescue/corrected_summary.csv'
        if corrected.exists():
            lines += ['', '| Corrected overall metric | Estimate | Bootstrap interval | Status |', '|---|---:|---:|---|']
            for r in read_csv(corrected):
                if r['group_type'] != 'overall' or r['metric'] not in ['system_state_fraction', 'context_required_fraction', 'cross_event_project_share', 'os_enforceable_count']:
                    continue
                def fmt(field):
                    if not r.get(field):
                        return 'unavailable'
                    return f'{float(r[field]):,.0f}' if r['metric'].endswith('_count') else f'{100*float(r[field]):.1f}%'
                lines.append(f'| {r["metric"]} | {fmt("value")} | [{fmt("ci_low")}, {fmt("ci_high")}] | {r["status"]} |')
            lines += ['', 'Corrections assume the test error matrix transfers across repositories, instruction families and task domains. This assumption is unverified. They are conditional on the frozen directive set. Failed-gate corrections remain exploratory. See rescue/PROTOCOL.md and correction diagnostics for boundary and non-identifiable fits.']
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
    for filename, label in [('validation.csv', 'Source, label, and metadata checks'),
                            ('figure_production_validation.csv', 'Actual-PDF font and snapshot checks'),
                            ('rescue/validation.csv', 'Frozen rescue protocol and provenance checks'),
                            ('rescue/correction_validation.csv', 'Known-answer correction checks')]:
        path = HERE / filename
        if path.exists():
            checks = read_csv(path)
            lines += ['', f'{label}: {sum(r["passed"] == "True" for r in checks)}/{len(checks)} passed.']
    lines += ['', f'Artifacts: `{HERE}`', '',
              'Raw downloads and logs: `/workspaces/.agent-state/actplane-research/raw/corpus-scale-20261028`', '',
              'Open caveats: convenience/star/query sampling; automated statement boundaries; historical reference conventions and missing human review sample; correlated model adjudication; exploratory model-based file scopes; any remaining withheld dimensions must not replace paper claims. See README.md and calibration tables for exact agreement and limitations.', '',
              'No paper files were edited. Operator handoff is branch-only; no further PR activity was performed after the update.']
    a.state.mkdir(parents=True, exist_ok=True)
    (a.state / 'SUMMARY.md').write_text('\n'.join(lines) + '\n')


if __name__ == '__main__':
    main()
