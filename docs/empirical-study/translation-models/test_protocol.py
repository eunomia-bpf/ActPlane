"""Checks of scoring-sensitive protocol behavior, not product implementation."""
import unittest
import tempfile
from pathlib import Path

from models import identity_ok
from replay import copy_fixture, notify_policy, runner_label, tools_in_trace
from translate import compile_policy, extract, inputs, make_prompt, usage_of
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


if __name__ == '__main__':
    unittest.main()
