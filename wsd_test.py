#!python
# encoding: utf-8

import unittest
from wsd import process_flags, RegularExpressionRule, RegularExpressionRuleSet
from wsd import DEFAULT_FLAGS
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
        self.assertEqual(expected, process_flags(flags, DEFAULT_FLAGS))


class TestRegularExpressionRule(unittest.TestCase):

    def setUp(self):
        self.expr = '\w+'
        self.prefix = r'\b'
        self.suffix = r'\b'
        self.rule_data = {'re': self.expr, 'flags': 'I'}
        self.rule = RegularExpressionRule(
            self.rule_data, self.prefix, self.suffix, DEFAULT_FLAGS, {})
        self.text = u'Some text\n    with spaces\nи другими символами'

    def test_itermatches(self):
        x = list(self.rule.itermatches(self.text))
        self.assertEqual(len(x), 1)
        pattern, matches = x[0]
        flags = process_flags(self.rule_data['flags'], DEFAULT_FLAGS)
        self.assertEqual(pattern['original'], self.expr)
        self.assertEqual(pattern['compiled'],
                         re.compile(self.prefix + self.expr + self.suffix, flags))
        matches_list = list(matches)
        self.assertEqual(len(matches_list), 7)
        self.assertEqual(matches_list[0].span(), (0, 4))
        self.assertEqual(matches_list[1].span(), (5, 9))
        self.assertEqual(matches_list[2].span(), (14, 18))
        self.assertEqual(matches_list[3].span(), (19, 25))
        self.assertEqual(matches_list[4].span(), (26, 27))
        self.assertEqual(matches_list[5].span(), (28, 35))
        self.assertEqual(matches_list[6].span(), (36, 45))

    def test_process(self):
        result = self.rule.process(self.text)
        self.assertEqual(result.lines,
                         dict(enumerate(self.text.splitlines(), 1)))
        self.assertEqual(result.pattern_matches,
            {
                self.expr: {
                    1: [1, [(0, 4), (5, 9)]],
                    2: [1, [(4, 8), (9, 15)]],
                    3: [1, [(0, 1), (2, 9), (10, 19)]]
                }
            }
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
        result = self.ruleset.process(self.text)
        self.assertEqual(result.lines, {1: self.text})
        self.assertEqual(len(result.rules), 1)
        processed_rule = result.rules[0]
        self.assertEqual(processed_rule.rule.data, self.rule_data)
        self.assertEqual(result.ruleset.data, self.data)
        self.assertEqual(processed_rule.pattern_matches,
            {
                self.expr: {
                    1: [1, [(0, 4), (5, 9)]]
                }
            }
        )

if __name__ == '__main__':
    unittest.main()
