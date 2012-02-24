# encoding: utf-8

import nltk
from wsd import LOG, Rule, Ruleset


class AllSentencesRule(Rule):

    def __init__(self, ruleset):
        Rule.__init__(self, ruleset, 'All sentences')

    def itermatches(self, text):
        for pattern in self.patterns:
            yield pattern, self.ruleset.tokenizer.span_tokenize(text).__iter__()


class LongSentencesRule(Rule):

    def __init__(self, ruleset):
        Rule.__init__(self, ruleset, 'Long sentences')

    def itermatches(self, text):
        for pattern in self.patterns:
            yield pattern, (
                m for m
                in self.ruleset.tokenizer.span_tokenize(text).__iter__()
                if m[1] - m[0] > 200
            )


class ShortSentencesRule(Rule):

    def __init__(self, ruleset):
        Rule.__init__(self, ruleset, 'Short sentences')

    def itermatches(self, text):
        for pattern in self.patterns:
            yield pattern, (
                m for m
                in self.ruleset.tokenizer.span_tokenize(text).__iter__()
                if m[1] - m[0] < 40
            )

class SampleRuleset(Ruleset):

    def __init__(self):
        Ruleset.__init__(self, 'Sample ruleset')
        self.tokenizer = nltk.data.load('tokenizers/punkt/english.pickle')
        self.rules = [
            ShortSentencesRule(self),
            LongSentencesRule(self),
            AllSentencesRule(self)
        ]


def get_rulesets():
    ruleset = SampleRuleset()
    return [ruleset]
