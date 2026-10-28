"""Checks of scoring-sensitive protocol behavior, not product implementation."""
import unittest
from unittest.mock import patch
import tempfile
from pathlib import Path

from models import identity_ok
from replay import copy_fixture, notify_policy, runner_label, tools_in_trace
from translate import compile_policy, extract, inputs, make_prompt, usage_of, translate_one
from summarize import detection
from prepare import DEFAULT_RAW


class ProtocolTests(unittest.TestCase):
    def test_identity_does_not_accept_substitute_model(self):
        self.assertTrue(identity_ok('zai/glm-5.3', 'zai/glm-5.3'))
        self.assertTrue(identity_ok('zai/glm-5.3', 'GLM-5.3'))
        self.assertFalse(identity_ok('zai/glm-5.3', 'glm-5.3-flash'))

    def test_effect_conversion_preserves_reasons_and_conditions(self):
        text = 'rule r:\n  kill exec "git" "push" if AGENT unless after exec "pytest"\n  because "kill exec is prohibited"'
        self.assertEqual(notify_policy(text), text.replace('  kill exec', '  notify exec'))

    def test_seed_bit_matches_sorted_compiler_label_allocation(self):
        self.assertEqual(runner_label('source Z = file "**/AGENT"\nsource AGENT = exec "python"\nrule x:\n notify exec "x" if Z and AGENT\n because "x"'), 1)
        self.assertEqual(runner_label('source A = file "a"\nsource AGENT = exec "**"\nrule x:\n notify exec "x" if A and AGENT\n because "x"'), 2)

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


if __name__ == '__main__':
    unittest.main()
