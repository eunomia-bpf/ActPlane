#!/usr/bin/env python3
"""Fault-injection checks that failed model batches never lose source IDs."""
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

from common import HERE, write_csv
from label import classify


def main():
    batch = [dict(statement_id=str(i), text='A source statement.') for i in range(3)]
    checks = []
    with TemporaryDirectory() as temp:
        args = SimpleNamespace(raw=Path(temp), model='qwen3.8-27b-nvfp4')
        with patch('label.complete', side_effect=RuntimeError('model_request_failed')) as request:
            result = classify(args, batch, 'coding guide', ['type'], None)
            checks.append(dict(check='transport_failure_retains_all_ids',
                passed={r['statement_id'] for r in result} == {'0', '1', '2'}))
            checks.append(dict(check='transport_failure_status_is_explicit',
                passed=all(r['status'] == 'failed' for r in result)))
            checks.append(dict(check='transport_failure_does_not_multiply_requests',
                passed=request.call_count == 1))

        def malformed_batch_then_valid_singleton(_args, _system, payload, budget):
            content = ('not JSON' if len(payload['statements']) > 1 else
                       '{"labels": [[0, "description"]]}')
            return dict(model='test', choices=[dict(message=dict(content=content))])

        with patch('label.complete', side_effect=malformed_batch_then_valid_singleton):
            result = classify(args, batch, 'coding guide', ['type'], None)
            checks.append(dict(check='malformed_batch_split_retains_all_ids',
                passed=[r['statement_id'] for r in result] == ['0', '1', '2']))
            checks.append(dict(check='successful_split_accepts_every_source',
                passed=all(r['status'] == 'ok' for r in result)))

        calls = []
        def partly_invalid(_args, _system, payload, budget):
            entries = payload['statements']
            calls.append([r['text'] for r in entries])
            content = ('{"labels": [[0, "description"], [1, ""], [2, "directive"]]}'
                       if len(entries) == 3 else '{"labels": [[0, "description"]]}')
            return dict(model='test', choices=[dict(message=dict(content=content))])
        with patch('label.complete', side_effect=partly_invalid):
            result = classify(args, batch, 'coding guide', ['type'], None)
            checks.append(dict(check='partial_validation_retries_only_invalid_id',
                passed=[len(c) for c in calls] == [3, 1]))
            checks.append(dict(check='partial_validation_retains_valid_decisions',
                passed=[r['type'] for r in result] == ['description', 'description', 'directive']))

        calls = []
        def missing_id(_args, _system, payload, budget):
            entries = payload['statements']
            calls.append(len(entries))
            content = ('{"labels": [[0, "description"], [2, "directive"]]}'
                       if len(entries) == 3 else '{"labels": [[0, "description"]]}')
            return dict(model='test', choices=[dict(message=dict(content=content))])
        with patch('label.complete', side_effect=missing_id):
            result = classify(args, batch, 'coding guide', ['type'], None)
            checks.append(dict(check='missing_id_retry_preserves_source_order',
                passed=calls == [3, 1] and [r['statement_id'] for r in result] == ['0', '1', '2']))
        attempts = []
        def repair_singleton(_args, system, payload, budget):
            attempts.append(system)
            label = 'description' if 'Schema repair attempt' in system else ''
            content = '{"labels": [[0, "' + label + '"]]}'
            return dict(model='test', choices=[dict(message=dict(content=content))])
        with patch('label.complete', side_effect=repair_singleton):
            result = classify(args, batch[:1], 'coding guide', ['type'], None)
            checks.append(dict(check='singleton_schema_feedback_repairs_invalid_value',
                passed=len(attempts) == 2 and result[0]['type'] == 'description'))
        invalid_response = dict(model='test', choices=[dict(message=dict(content='{"labels": [[0, ""]]}'))])
        with patch('label.complete', return_value=invalid_response) as request:
            result = classify(args, batch[:1], 'coding guide', ['type'], None)
            checks.append(dict(check='singleton_schema_repair_is_bounded',
                passed=request.call_count == 3 and result[0]['status'] == 'failed'))
        args.retry_policy = 'batch'
        with patch('label.complete', return_value=invalid_response) as request:
            result = classify(args, batch[:1], 'coding guide', ['type'], None)
            checks.append(dict(check='legacy_policy_has_no_new_schema_feedback',
                passed=request.call_count == 1 and result[0]['status'] == 'failed'))
    write_csv(HERE / 'label_failure_validation.csv', checks)
    if not all(r['passed'] for r in checks):
        raise SystemExit('Label failure validation failed')
    print(checks)


if __name__ == '__main__':
    main()
