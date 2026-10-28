"""Checks of scoring-sensitive protocol behavior, not product implementation."""
import unittest
from unittest.mock import patch
import tempfile
from pathlib import Path

import json
from models import identity_ok, codex_server_evidence
from replay import copy_fixture, notify_policy, runner_label, tools_in_trace, replay_cache_matches
from translate import compile_policy, extract, inputs, make_prompt, usage_of, translate_one, retryable, reset_time, backoff_remaining
from summarize import detection
from prepare import DEFAULT_RAW, sha


class ProtocolTests(unittest.TestCase):
    def test_identity_does_not_accept_substitute_model(self):
        self.assertTrue(identity_ok('zai/glm-5.3', 'zai/glm-5.3'))
        self.assertTrue(identity_ok('zai/glm-5.3', 'GLM-5.3'))
        self.assertFalse(identity_ok('zai/glm-5.3', 'glm-5.3-flash'))

    def test_effect_conversion_preserves_reasons_and_conditions(self):
        text = 'rule r:\n  kill exec "git" "push" if AGENT unless after exec "pytest"\n  because "kill exec is prohibited"'
        self.assertEqual(notify_policy(text), text.replace('  kill exec', '  notify exec'))
        inline = 'source AGENT = exec "**" rule x: block exec "git" if AGENT because "kill exec"'
        self.assertIn('rule x: notify exec', notify_policy(inline))
        self.assertEqual(runner_label('source Z = exec "x" source A = file "a" source AGENT = exec "**" rule x: notify exec "x" if AGENT and\nnot Z because "source B = exec x"'), 2)

    def test_seed_bit_matches_sorted_compiler_label_allocation(self):
        self.assertEqual(runner_label('source Z = file "**/AGENT"\nsource AGENT = exec "python"\nrule x:\n notify exec "x" if Z and AGENT\n because "x"'), 1)
        self.assertEqual(runner_label('source A = file "a"\nsource AGENT = exec "**"\nrule x:\n notify exec "x" if A and AGENT\n because "x"'), 2)
        self.assertEqual(runner_label('source AGENT = exec "**" rule x: notify exec "x" if(A or AGENT) because "x"'), 2)

    def test_input_scope_and_prompt_has_no_reference_answer(self):
        self.assertEqual(len(inputs(DEFAULT_RAW, 'rq1')), 607)
        self.assertEqual(len(inputs(DEFAULT_RAW, 'rq2')), 38)
        prompt = make_prompt(DEFAULT_RAW, inputs(DEFAULT_RAW, 'rq2')[0])
        self.assertNotIn('rule.yaml', prompt)
        self.assertNotIn('trace_visible_violation.jsonl', prompt)
        self.assertIn('<dsl-reference>', prompt)

    def test_formatting_removal_does_not_repair_bad_syntax(self):
        self.assertEqual(extract('```dsl\nrule nonsense\n```'), 'rule nonsense')
        self.assertEqual(extract('Here is the rule:\ninvalid'), 'Here is the rule:\ninvalid')

    def test_real_cli_acceptance_and_rejection(self):
        with tempfile.TemporaryDirectory(dir=DEFAULT_RAW) as temp:
            out = Path(temp)
            good = 'source AGENT = exec "**"\nrule test:\n notify exec "git" "commit" if AGENT\n because "test"'
            self.assertTrue(compile_policy(good, out)['ok'])
            self.assertFalse(compile_policy('not a policy', out)['ok'])

    def test_usage_accepts_optional_null_details(self):
        data = {'response': {'usage': {'prompt_tokens': 2, 'completion_tokens': 3,
                                      'prompt_tokens_details': None, 'completion_tokens_details': None}}}
        self.assertEqual(usage_of(data, 'qwen3.8-27b-nvfp4')['input_tokens'], 2)

    def test_fixture_symlink_is_copied_independently(self):
        with tempfile.TemporaryDirectory(dir=DEFAULT_RAW) as temp:
            root = Path(temp)
            (root / 'source').mkdir()
            (root / 'source/file').write_text('baseline')
            (root / 'selected').symlink_to(root / 'source', target_is_directory=True)
            copy_fixture(root / 'selected', root / 'checkout')
            self.assertFalse((root / 'checkout').is_symlink())
            (root / 'checkout/file').write_text('modified')
            self.assertEqual((root / 'source/file').read_text(), 'baseline')

    def test_scoring_known_confusion_matrix_and_missing_outcomes(self):
        rows = [dict(violation='1', fired=str(int(i < 66)), status='ok', family='visible_violation') for i in range(114)]
        rows += [dict(violation='0', fired=str(int(i < 17)), status='ok', family='allowed_effect_compliant') for i in range(76)]
        result = detection(rows)
        self.assertEqual(result['detection_rate'], 66/114)
        self.assertEqual(result['false_trigger_rate'], 17/76)
        self.assertEqual(result['f1'], 132/197)
        self.assertEqual(result['agreement_traces'], 0)
        rows[0].update(status='error', fired='')
        self.assertEqual(detection(rows)['detection_rate'], '')
        self.assertEqual(detection(rows)['conditional_detection_rate'], 65/113)
        rows[0].update(status='translation_failed', fired='0')
        self.assertEqual(detection(rows)['detection_rate'], 65/114)
        self.assertEqual(detection(rows)['compiled_rule_detection_rate'], 65/113)

    def test_revision_gets_real_compiler_error_and_cache_does_not_resample(self):
        good = 'source AGENT = exec "**"\nrule test:\n notify exec "git" if AGENT\n because "test"'
        def response(text):
            return dict(status='ok', elapsed_s=.01, identity_verified=True,
                        response_model='qwen3.8-27b-nvfp4',
                        response={'choices': [{'message': {'content': text}}],
                                  'usage': {'prompt_tokens': 10, 'completion_tokens': 10}})
        with tempfile.TemporaryDirectory(dir=DEFAULT_RAW) as temp:
            raw = Path(temp)
            (raw / 'dsl-reference.md').write_text('frozen test reference')
            item = dict(uid='test', repo_dir='test', statement_id='test', directive='No git', source_evidence=[])
            with patch('translate.api_call', side_effect=[response('not a policy'), response(good)]) as call:
                result = translate_one(raw, 'rq2', 'qwen3.8-27b-nvfp4', item)
                self.assertEqual(result['compile_at_1'], 0)
                self.assertEqual(result['compile_at_3'], 1)
                self.assertEqual(result['attempts'], 2)
                self.assertIn('compiler rejected', call.call_args_list[1].args[1][-1]['content'])
                translate_one(raw, 'rq2', 'qwen3.8-27b-nvfp4', item)
                self.assertEqual(call.call_count, 2)

    def test_capacity_transport_retries_without_using_compiler_revision(self):
        self.assertTrue(retryable(dict(status='cli_error', error='Selected model is at capacity')))
        self.assertFalse(retryable(dict(status='http_error', http_status=401, error='expired key')))
        good = 'source AGENT = exec "**"\nrule test:\n notify exec "git" if AGENT\n because "test"'
        failed = dict(status='cli_error', error='Selected model is at capacity', elapsed_s=.01)
        success = dict(status='ok', text=good, elapsed_s=.01, identity_verified=True,
                       response_model='gpt-6-astra', usage=dict(input_tokens=10, output_tokens=10))
        with tempfile.TemporaryDirectory(dir=DEFAULT_RAW) as temp:
            raw = Path(temp)
            (raw / 'dsl-reference.md').write_text('frozen test reference')
            item = dict(uid='test', repo_dir='test', statement_id='test', directive='No git', source_evidence=[])
            with patch('translate.cli_call', side_effect=[failed, success]) as call, patch('translate.time.sleep') as sleep:
                result = translate_one(raw, 'rq1', 'gpt-6-astra', item)
                self.assertEqual(result['compile_at_1'], 1)
                self.assertEqual(result['attempts'], 1)
                self.assertEqual(result['transport_retries'], 1)
                self.assertEqual(sleep.call_count, 1)
                self.assertTrue(14 <= sleep.call_args.args[0] <= 15)
                translate_one(raw, 'rq1', 'gpt-6-astra', item)
                self.assertEqual(call.call_count, 2)

    def test_provider_reset_uses_observation_date_not_resume_date(self):
        import datetime as dt
        observed = dt.datetime(2026, 10, 28, 8, 50, tzinfo=dt.timezone.utc).timestamp()
        response = dict(status='cli_error', error="You've hit your session limit · resets 10:40am (UTC)",
                        observed_at_unix=observed)
        self.assertTrue(retryable(response))
        self.assertEqual(reset_time(response), dt.datetime(2026, 10, 28, 10, 41, tzinfo=dt.timezone.utc).timestamp())

    def test_checkpoint_gap_satisfies_backoff_without_resampling_answer(self):
        with patch('translate.time.time', return_value=300):
            self.assertEqual(backoff_remaining(dict(observed_at_unix=100), 4), 0)
            self.assertEqual(backoff_remaining(dict(observed_at_unix=299), 1), 14)

    def test_serial_recovery_extends_transport_budget_only(self):
        import os
        import time
        good = 'source AGENT = exec "**"\nrule test:\n notify exec "git" if AGENT\n because "test"'
        failed = dict(status='http_error', http_status=429, elapsed_s=.01, error='service overloaded')
        success = dict(status='ok', elapsed_s=.01, identity_verified=True, response_model='glm-4.7-flash',
                       response={'choices': [{'message': {'content': good}}],
                                 'usage': {'prompt_tokens': 10, 'completion_tokens': 10}})
        with tempfile.TemporaryDirectory(dir=DEFAULT_RAW) as temp:
            raw = Path(temp)
            (raw / 'dsl-reference.md').write_text('frozen test reference')
            out = raw / 'translations/rq1/zai__glm-4.7-flash/test'
            (out / 'attempt-1').mkdir(parents=True)
            (out / 'result.json').write_text(json.dumps(dict(status='access_failure', attempts=1)))
            saved = out / 'attempt-1/response.json'
            saved.write_text(json.dumps({**failed, 'transport_attempts': [dict(failed) for _ in range(3)]}))
            os.utime(saved, (time.time() - 3600, time.time() - 3600))
            item = dict(uid='test', repo_dir='test', statement_id='test', directive='No git', source_evidence=[])
            with patch('translate.api_call', return_value=success) as call, patch('translate.time.sleep') as sleep:
                result = translate_one(raw, 'rq1', 'zai/glm-4.7-flash', item, transport_limit=6)
                self.assertEqual(result['compile_at_1'], 1)
                self.assertEqual(result['attempts'], 1)
                self.assertEqual(result['transport_retries'], 4)
                sleep.assert_not_called()
                translate_one(raw, 'rq1', 'zai/glm-4.7-flash', item, transport_limit=6)
                self.assertEqual(call.call_count, 1)
                # Simulate a stop after saving the new response but before
                # replacing the older terminal access-failure policy record.
                (out / 'result.json').write_text(json.dumps(dict(status='access_failure', attempts=1)))
                resumed = translate_one(raw, 'rq1', 'zai/glm-4.7-flash', item, transport_limit=6)
                self.assertEqual(resumed['status'], 'compiled')
                self.assertEqual(call.call_count, 1)

    def test_replay_cache_invalidates_unavailable_outcomes_without_erasing_engine_errors(self):
        policy = 'source AGENT = exec "**"'
        self.assertFalse(replay_cache_matches(dict(status='translation_unavailable'), policy, 'compiled'))
        self.assertTrue(replay_cache_matches(dict(status='error', policy_sha256=sha(policy.encode())), policy, 'compiled'))
        self.assertFalse(replay_cache_matches(dict(status='translation_unavailable'), '', 'compiler_failure'))
        self.assertTrue(replay_cache_matches(dict(status='translation_failed'), '', 'compiler_failure'))

    def test_codex_identity_comes_from_incoming_server_response(self):
        outgoing = 'Sending message ' + json.dumps({'type': 'response.completed', 'response': {'model': 'requested'}})
        warmup = dict(type='response.completed', response=dict(id='warmup', model='gpt-6-astra', generate=False, output=[]))
        actual = dict(type='response.completed', response=dict(id='actual', model='gpt-6-astra', output=[dict(type='message')], usage={'input_tokens': 12, 'output_tokens': 3}))
        text = outgoing + '\nReceived message ' + json.dumps(warmup) + '\nReceived message ' + json.dumps(actual)
        evidence = codex_server_evidence(text)
        self.assertEqual([r['model'] for r in evidence], ['gpt-6-astra', 'gpt-6-astra'])
        self.assertEqual(len([r for r in evidence if r['generate'] is not False]), 1)
        self.assertEqual(usage_of({'usage': {'input_tokens': 12, 'output_tokens': 3}}, 'gpt-6-astra')['input_tokens'], 12)


if __name__ == '__main__':
    unittest.main()
