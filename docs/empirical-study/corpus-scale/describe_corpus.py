#!/usr/bin/env python3
"""Summarize source coverage and historical overlap without requiring labels."""
from collections import defaultdict

from common import HERE, read_csv, write_csv


def main():
    repos = read_csv(HERE / 'repositories.csv')
    historical = read_csv(HERE / 'paper_files.csv')
    old_names = {r['repo'].casefold() for r in historical}
    new_names = {r['repo'].casefold() for r in repos}
    write_csv(HERE / 'snapshot_overlap.csv', [dict(
        historical_repositories=len(old_names), new_repositories=len(new_names),
        shared_repositories=len(old_names & new_names),
        newly_sampled_repositories=len(new_names - old_names),
        historical_repositories_not_resampled=len(old_names - new_names))])
    manifest = read_csv(HERE / 'corpus_manifest.csv')
    groups = defaultdict(list)
    for row in manifest:
        groups[row['family']].append(row)
    families = []
    for family, rows in sorted(groups.items()):
        selected = [r for r in rows if r['status'] == 'included']
        families.append(dict(family=family, discovered_paths=len(rows),
            selected_paths=len(selected), selected_repositories=len({r['repo'] for r in selected}),
            unique_repo_content_pairs=len({(r['repo'], r['content_sha256']) for r in selected}),
            excluded_paths=len(rows) - len(selected)))
    write_csv(HERE / 'family_coverage.csv', families)


if __name__ == '__main__':
    main()
