#!/usr/bin/env python3
"""A separately labeled milestone snapshot of complete files, not full projects."""
from collections import defaultdict
import argparse

from analyze import summarize
from common import HERE, now, read_csv, write_csv
from label import DIMS
from report import fmt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--replay', action='store_true', help='Reproduce the frozen included-file scope.')
    args = parser.parse_args()
    source = read_csv(HERE / 'statements.csv')
    labels = {r['statement_id']: r for r in read_csv(HERE / 'labels.csv')}
    files = defaultdict(list)
    for row in source:
        files[(row['repo'], row['content_sha256'])].append(row)
    complete = {key for key, rows in files.items()
                if all(labels.get(r['statement_id'], {}).get('status') == 'ok' for r in rows)}
    if args.replay:
        complete = {(r['repo'], r['content_sha256']) for r in read_csv(HERE / 'interim_file_inclusions.csv')}
        stamp = read_csv(HERE / 'interim_file_coverage.csv')[0]['as_of']
    else:
        stamp = now()
    joined = [dict(r, **{d: labels[r['statement_id']].get(d, '') for d in DIMS})
              for key in sorted(complete) for r in files[key]]
    all_repos = {r['repo']: r for r in read_csv(HERE / 'repositories.csv')}
    present = {r['repo'] for r in joined}
    represented = {name: row for name, row in all_repos.items() if name in present}
    required = defaultdict(set)
    for row in read_csv(HERE / 'corpus_manifest.csv'):
        if row['status'] == 'included':
            required[row['repo']].add((row['repo'], row['content_sha256']))
    coverage = dict(as_of=stamp, collected_repositories=len(all_repos),
        represented_repositories=len(represented),
        fully_labeled_repositories=sum(keys <= complete for keys in required.values()),
        complete_unique_files=len(complete), selected_unique_files=len(files),
        excluded_incomplete_files=len(files) - len(complete), statements=len(joined))
    write_csv(HERE / 'interim_file_coverage.csv', [coverage])
    write_csv(HERE / 'interim_file_inclusions.csv', [dict(repo=key[0], content_sha256=key[1],
        commit=files[key][0]['commit'], file_path=files[key][0]['file_path'],
        statements=len(files[key]), policies=sum(labels[r['statement_id']]['type'] == 'directive' for r in files[key]))
        for key in sorted(complete)])
    gates = {r['dimension']: r['passed'] == 'True' for r in read_csv(HERE / 'calibration_gates.csv')}
    for row in read_csv(HERE / 'format_calibration_gates.csv'):
        gates[row['dimension']] = gates.get(row['dimension'], False) and row['passed'] == 'True'
    summary, _ = summarize(joined, represented, gates, source='interim_complete_files')
    write_csv(HERE / 'interim_file_summary.csv', summary)
    lines = ['# Completed-file milestone', '',
        '**Interim process snapshot. Do not substitute these for complete-snapshot paper results.**', '',
        f'As of {coverage["as_of"]}, {coverage["complete_unique_files"]} complete files contain '
        f'{coverage["statements"]:,} labeled statements from {coverage["represented_repositories"]} repositories. '
        f'{coverage["fully_labeled_repositories"]} repositories have every selected source labeled. '
        f'{coverage["excluded_incomplete_files"]} unfinished files are excluded from this separate snapshot.', '',
        '| Metric | Estimate | Repository-bootstrap interval | Status |', '|---|---:|---:|---|']
    for row in summary:
        interval = f'{fmt(row, "ci_low")}–{fmt(row, "ci_high")}' if row['status'] == 'ok' else 'withheld'
        lines.append(f'| {row["metric"]} | {fmt(row)} | {interval} | {row["status"]} |')
    lines += ['', 'The main `summary.csv` requires complete repository coverage. This separate milestone includes finished files from partially covered repositories, so timing-dependent file selection differs from the final analysis. Intervals describe resampling repositories in this observed subset. They do not account for unfinished-file selection or model error. `interim_file_coverage.csv`, `interim_file_inclusions.csv`, and `interim_file_summary.csv` retain the exact included files, denominators, and exclusions. Run `python interim_files.py --replay` to reproduce the frozen scope. See README.md for calibration and the selection protocol.']
    (HERE / 'MILESTONE.md').write_text('\n'.join(lines) + '\n')
    print(coverage)


if __name__ == '__main__':
    main()
