#!python
# encoding: utf-8

import unittest
from wsd import process_flags, RegularExpressionRule, RegularExpressionRuleSet
from wsd import default_flags
import re

class TestProcessFlags(unittest.TestCase):

    def test_process_flags_all(self):
        flags = 'SLUMIX'
        default = 0
        expected = re.S | re.L | re.U | re.M | re.I | re.X
        self.assertEqual(expected, process_flags(flags, default))

    def test_process_flags_minus(self):
        flags = '-U+X'
        expected = re.S | re.X
        self.assertEqual(expected, process_flags(flags, default_flags))


class TestRegularExpressionRule(unittest.TestCase):

    def setUp(self):
        self.expr = '[A-Z]+'
        self.prefix = r'\b'
        self.suffix = r'\b'
        self.rule_data = { 're': self.expr, 'flags': 'I' }
        self.rule = RegularExpressionRule(self.rule_data, self.prefix, self.suffix, default_flags, {})
        self.text = 'Some text'

    def test_itermatches(self):
        x = list(self.rule.itermatches(self.text))
        self.assertEqual(len(x), 1)
        pattern, item_matches = x[0]
        flags = process_flags(self.rule_data['flags'], default_flags)
        self.assertEqual(pattern, re.compile(self.prefix + self.expr + self.suffix, flags))
        item_matches_list = list(item_matches)
        self.assertEqual(len(item_matches_list), 1)
        item, matches = item_matches_list[0]
        self.assertEqual(item, self.text)
        matches_list = list(matches)
        self.assertEqual(len(matches_list), 2)
        self.assertEqual(matches_list[0].span(), (0, 4))
        self.assertEqual(matches_list[1].span(), (5, 9))

    def test_process(self):
        lines, pattern_matches = self.rule.process(self.text)
        self.assertEqual(lines, { 1: self.text })
        self.assertEqual(pattern_matches,
            [(
                self.prefix + self.expr + self.suffix,
                [(1, 0, 4), (1, 5, 9)]
            )]
        )

class TestRegularExpressionRuleSet(unittest.TestCase):

    def setUp(self):
        self.expr = '[A-Z]+'
        self.prefix = r'\b'
        self.suffix = r'\b'
        self.rule_data = {
            're': self.expr
        }
        self.text = 'Some text'
        self.data = {
            'ruleset': 'Test ruleset',
            'prefix': self.prefix,
            'suffix': self.suffix,
            'flags': 'I',
            'rules': [
                self.rule_data
            ]
        }
        self.ruleset = RegularExpressionRuleSet(self.data)

    def test_process(self):
        lines, processed_ruleset = self.ruleset.process(self.text)
        self.assertEqual(lines, { 1: self.text })
        self.assertEqual(len(processed_ruleset['matched_rules']), 1)
        matched_rule_data, pattern_matches = processed_ruleset['matched_rules'][0]
        self.assertEqual(matched_rule_data, self.rule_data)
        processed_ruleset.pop('matched_rules')
        self.assertEqual(processed_ruleset, self.data)
        self.assertEqual(pattern_matches,
            [(
                self.prefix + self.expr + self.suffix,
                [(1, 0, 4), (1, 5, 9)]
            )]
        )

if __name__ == '__main__':
    unittest.main()
