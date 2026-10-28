#!/usr/bin/env python3
"""Audit provenance, source fidelity, complete partitions, and label coverage."""
import argparse
from collections import Counter, defaultdict
from pathlib import Path

from common import DEFAULT_RAW, HERE, digest, read_csv, write_csv
from label import ALLOWED, DIMS


def main(a):
    checks = []
    def record(check, expected, actual):
        checks.append(dict(check=check, expected=expected, actual=actual, passed=expected == actual))
    paper = read_csv(HERE / 'paper_labels.csv')
    claims = {r['metric']: r['value'] for r in read_csv(HERE / 'paper_claims.csv')}
    record('historical_statement_total', int(claims['statements']), len(paper))
    record('historical_repository_total', int(claims['repositories']), len({r['repo'] for r in paper}))
    record('historical_os_tier_count', int(claims['os_enforceable_count']),
           sum(r['type'] == 'directive' and r['enforceability'] in ('per_event', 'cross_event') for r in paper))
    audit = read_csv(HERE / 'paper_audit.csv')[0]
    record('historical_deduplicated_non_redirect_file_total', int(claims['instruction_files']),
           int(audit['unique_non_redirect_files']))
    for name in ['calibration_qwen', 'calibration_glm', 'calibration_adjudicated']:
        path = HERE / (name + '.csv')
        if path.exists():
            rows = read_csv(path)
            record(name + '_unique_ids', len(rows), len({r['statement_id'] for r in rows}))
            if a.require_complete:
                record(name + '_successful_rows', len(paper), sum(r['status'] == 'ok' for r in rows))
    manifest_path = HERE / 'corpus_manifest.csv'
    if manifest_path.exists():
        manifest = read_csv(manifest_path)
        repositories = read_csv(HERE / 'repositories.csv')
        if a.require_complete:
            record('at_least_300_collected_repositories', True, len(repositories) >= 300)
        record('repositories_below_star_floor', 0, sum(int(r['stars']) < 100 for r in repositories))
        record('repositories_inactive_since_2025', 0,
               sum(r['pushed_at'] < '2025-01-01' for r in repositories))
        hashes_bad, missing, undecodable, sources = 0, 0, 0, {}
        for f in manifest:
            if f['status'] != 'included':
                continue
            path = a.raw / f['raw_relpath']
            if not path.exists():
                missing += 1
                continue
            content = path.read_bytes()
            hashes_bad += digest(content) != f['content_sha256']
            try:
                content.decode('utf-8')
            except UnicodeDecodeError:
                undecodable += 1
            sources[(f['repo'], f['content_sha256'])] = content.decode('utf-8', errors='replace').splitlines(keepends=True)
        record('missing_raw_source_files', 0, missing)
        record('source_sha256_mismatches', 0, hashes_bad)
        record('undecodable_utf8_sources', 0, undecodable)
        path = HERE / 'statements.csv'
        if path.exists():
            rows = read_csv(path)
            record('statement_unique_ids', len(rows), len({r['statement_id'] for r in rows}))
            groups = defaultdict(list)
            mismatches, gaps = 0, 0
            for r in rows:
                key = (r['repo'], r['content_sha256'])
                s, e = int(r['start_line']), int(r['end_line'])
                mismatches += ''.join(sources[key][s-1:e-1]) != r['text']
                groups[key].append((s, e))
            for key, spans in groups.items():
                cursor = 1
                for s, e in sorted(spans):
                    gaps += s != cursor or e <= s
                    cursor = e
                gaps += cursor != len(sources[key]) + 1
            record('verbatim_source_mismatches', 0, mismatches)
            record('source_partition_errors', 0, gaps)
            if a.require_complete:
                record('all_selected_source_files_segmented', len(sources), len(groups))
            labels_path = HERE / 'labels.csv'
            if labels_path.exists():
                labels = read_csv(labels_path)
                record('scaled_label_unique_ids', len(labels), len({r['statement_id'] for r in labels}))
                unknown = {r['statement_id'] for r in labels} - {r['statement_id'] for r in rows}
                record('unknown_scaled_label_ids', 0, len(unknown))
                enabled = {r['dimension'] for r in read_csv(HERE / 'calibration_gates.csv') if r['passed'] == 'True'}
                format_path = HERE / 'format_calibration_gates.csv'
                if format_path.exists():
                    enabled &= {r['dimension'] for r in read_csv(format_path) if r['passed'] == 'True'}
                invalid = sum(r.get(d, '') not in ALLOWED[d] for r in labels if r['status'] == 'ok' for d in enabled)
                record('invalid_scaled_label_values', 0, invalid)
                record('values_in_withheld_dimensions', 0,
                       sum(bool(r.get(d, '')) for r in labels if r['status'] == 'ok' for d in set(DIMS) - enabled))
                if 'enforceability' in enabled:
                    record('enforcement_applicability_errors', 0, sum(
                        bool(r['enforceability']) != (r['type'] == 'directive') for r in labels if r['status'] == 'ok'))
                if 'context_required' in enabled:
                    record('context_applicability_errors', 0, sum(
                        bool(r['context_required']) != (r['type'] == 'directive' and r['enforceability'] in ('content', 'per_event', 'cross_event'))
                        for r in labels if r['status'] == 'ok'))
                if a.require_complete:
                    record('scaled_successful_rows', len(rows), sum(r['status'] == 'ok' for r in labels))
    write_csv(HERE / 'validation.csv', checks)
    failures = [r for r in checks if not r['passed']]
    for r in checks:
        print(r)
    if failures:
        raise SystemExit('Validation failed')


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--raw', type=Path, default=DEFAULT_RAW)
    p.add_argument('--require-complete', action='store_true')
    main(p.parse_args())
