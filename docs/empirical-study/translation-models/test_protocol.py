"""Checks of scoring-sensitive protocol behavior, not product implementation."""
import unittest

from models import identity_ok
from replay import notify_policy, runner_label, tools_in_trace
from translate import extract, inputs, make_prompt
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


if __name__ == '__main__':
    unittest.main()
