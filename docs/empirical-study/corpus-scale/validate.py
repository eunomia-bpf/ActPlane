#!/usr/bin/env python3
"""Audit provenance, source fidelity, complete partitions, and label coverage."""
import argparse
import hashlib
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
            expected_model = 'zai/glm-5.3' if name.endswith('_glm') else 'qwen3.8-27b-nvfp4'
            record(name + '_unexpected_model_identity', 0, sum(
                r.get('returned_model') != expected_model for r in rows if r['status'] == 'ok'))
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
        categories_path = HERE / 'repository_categories.csv'
        if categories_path.exists():
            categories = read_csv(categories_path)
            record('duplicate_repository_categories', 0, len(categories) - len({r['repo'] for r in categories}))
            record('unknown_category_repositories', 0,
                   len({r['repo'] for r in categories} - {r['repo'] for r in repositories}))
            record('invalid_successful_categories', 0, sum(r['category'] not in
                   {'agent_frameworks', 'applications', 'noncoding_agents'}
                   for r in categories if r['status'] == 'ok'))
        scopes_path = HERE / 'file_scopes.csv'
        if scopes_path.exists():
            scopes = read_csv(scopes_path)
            scope_keys = [(r['repo'], r['content_sha256']) for r in scopes]
            selected_keys = {(r['repo'], r['content_sha256']) for r in manifest if r['status'] == 'included'}
            record('duplicate_file_scope_keys', 0, len(scope_keys) - len(set(scope_keys)))
            record('unknown_file_scope_keys', 0, len(set(scope_keys) - selected_keys))
            record('invalid_successful_file_scopes', 0, sum(r['scope'] not in
                   {'software_development', 'noncoding_assistance', 'general_agent_operations',
                    'mixed', 'descriptive_reference', 'unclear'} for r in scopes if r['status'] == 'ok'))
            analysis_path, noncoding_path = HERE / 'analysis_statements.csv', HERE / 'noncoding_statements.csv'
            if analysis_path.exists() and noncoding_path.exists():
                noncoding_keys = {(r['repo'], r['content_sha256']) for r in scopes
                                 if r['status'] == 'ok' and r['scope'] == 'noncoding_assistance'}
                expected_ids = {r['statement_id'] for r in read_csv(analysis_path)
                                if (r['repo'], r['content_sha256']) in noncoding_keys}
                exported = read_csv(noncoding_path)
                exported_ids = {r['statement_id'] for r in exported}
                record('duplicate_noncoding_statement_ids', 0, len(exported) - len(exported_ids))
                record('noncoding_statement_membership_difference', 0, len(expected_ids ^ exported_ids))
        hashes_bad, blob_hashes_bad, missing, undecodable, sources = 0, 0, 0, 0, {}
        for f in manifest:
            if f['status'] != 'included':
                continue
            path = a.raw / f['raw_relpath']
            if not path.exists():
                missing += 1
                continue
            content = path.read_bytes()
            hashes_bad += digest(content) != f['content_sha256']
            git_blob = b'blob ' + str(len(content)).encode() + b'\0' + content
            blob_hashes_bad += hashlib.sha1(git_blob).hexdigest() != f['blob_sha']
            try:
                content.decode('utf-8')
            except UnicodeDecodeError:
                undecodable += 1
            sources[(f['repo'], f['content_sha256'])] = content.decode('utf-8', errors='replace').splitlines(keepends=True)
        record('missing_raw_source_files', 0, missing)
        record('source_sha256_mismatches', 0, hashes_bad)
        record('pinned_git_blob_sha1_mismatches', 0, blob_hashes_bad)
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
                record('unexpected_final_model_identity', 0, sum(
                    r.get('returned_model') != 'qwen3.8-27b-nvfp4' for r in labels if r['status'] == 'ok'))
                for model, expected_model in [('qwen', 'qwen3.8-27b-nvfp4'), ('glm', 'zai/glm-5.3')]:
                    primary_path = HERE / f'labels_{model}.csv'
                    if primary_path.exists():
                        primary = read_csv(primary_path)
                        record('unexpected_' + model + '_model_identity', 0, sum(
                            r.get('returned_model') != expected_model for r in primary if r['status'] == 'ok'))
                        if a.require_complete:
                            record(model + '_primary_successful_rows', len(rows), sum(r['status'] == 'ok' for r in primary))
                from effective_gates import load_gates
                enabled = {d for d, passed in load_gates().items() if passed}
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
