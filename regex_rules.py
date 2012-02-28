# encoding: utf-8

import re
import os
import codecs
import json
from wsd import LOG, Rule, Ruleset

DEFAULT_FLAGS = re.S | re.U

def process_flags(flags, default=0):
    '''
    Process a string of regular expression flags like "+LUX-M".
    Return a combination of corresponding re.X values.
    '''
    mode = '+'
    result = default
    for flag in flags:
        if flag in '+-':
            mode = flag
            continue
        elif flag in 'SLUMIX':
            if mode == '-':
                result &= ~getattr(re, flag)
            else:
                result |= getattr(re, flag)
        else:
            LOG.warn('unknown flag: ' + flag)
            continue
    return result


class RegularExpressionRule(Rule):
    '''Regular expression rule'''

    def __init__(self, ruleset, props, data, flags, replace):
        Rule.__init__(self, ruleset,
            data.get('name', ''),
            data.get('comments', []),
            {
                'prefix': data.get('prefix', props['prefix']),
                'suffix': data.get('suffix', props['suffix']),
            }
        )
        for prop, value in self.props.iteritems():
            if '\b' in value:
                LOG.warn(r'\b found in {0}. \
                    To match word boundaries use \\b instead.'.format(prop))
        self.data = data
        self.flags = process_flags(data.get('flags', ''), flags)
        self.replace = data.get('replace', replace)
        self.re = data.get('re', [])
        if isinstance(self.re, basestring):
            patterns = [self.re]
        elif hasattr(self.re, '__getitem__'):
            patterns = self.re
        for patern in patterns:
            if '\b' in patern:
                LOG.warn(r'\b found in pattern {0}. \
                    To match word boundaries use \\b instead.'
                    .format(patern.replace('\b', r'\b')))
        self.patterns = []
        for patern in patterns:
            original_pattern = patern
            for search_string, replacement in self.replace.iteritems():
                patern = re.sub(search_string, replacement, patern)
            compiled = re.compile(
                self.props['prefix'] + patern + self.props['suffix'],
                self.flags
            )
            self.patterns.append({'compiled': compiled,
                                  'original': original_pattern})

    def itermatches(self, text):
        '''
        Return an iterator over all pairs (pattern, matches).
        matches is an iterator over all matches in the text.
        '''
        for pattern in self.patterns:
            yield pattern, (m.span() for m in pattern['compiled'].finditer(text))

    def get_pattern_props(self, pattern):
        if hasattr(self.re, 'iteritems'):
            return {'replace': self.re[pattern]}
        else:
            return {}


class RegularExpressionRuleset(Ruleset):
    '''
    Set of regular expression rules
    '''
    def __init__(self, data, uid):
        Ruleset.__init__(self,
            data['ruleset'],
            data.get('comments', []),
            {
                'prefix': data.get('prefix', ''),
                'suffix': data.get('suffix', ''),
            }
        )
        self.uid = unicode(uid).replace(u'\\', u'/')
        self.data = data
        self.flags = process_flags(data.get('flags', ''), DEFAULT_FLAGS)
        self.replace = data.get('replace', {})
        self.rules = [
            RegularExpressionRule(self, self.props, d, self.flags, self.replace)
            for d in data['rules']
        ]


def get_rulesets(masks=None):
    '''
    Load rulesets from masks list.
    `masks` is a string containing masks separated by semicolon.
    Shell wildcards are allowed.
    Load from `rules` directory by default.
    '''
    from glob import glob
    jsoncomment = re.compile('^\s*//')
    rules_folder = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 'rules')
    rulesets = []
    if not masks:
        masks = os.path.join(rules_folder, '*')
    for mask in masks.split(';'):
        empty_mask = True
        for rule_file_or_dir in glob(mask):
            empty_mask = False
            if os.path.isdir(rule_file_or_dir):
                rule_files = glob(os.path.join(rule_file_or_dir, '*'))
            else:
                rule_files = (rule_file_or_dir,)
            for rule_file in rule_files:
                try:
                    # remove comments but preserve the same number of lines
                    jsonrule = ''.join(
                        '\n' if jsoncomment.search(line)
                        else line
                        for line
                        in codecs.open(rule_file, encoding='utf-8').readlines()
                    )
                    ruleset_dict = json.loads(jsonrule)
                except ValueError, exc:
                    LOG.error(exc)
                    LOG.error("In file: " + rule_file)
                    continue
                ruleset = RegularExpressionRuleset(ruleset_dict,
                    os.path.relpath(rule_file, rules_folder))
                rulesets.append(ruleset)
        if empty_mask:
            LOG.warn('No files matching "{0}" found'.format(mask))
    return rulesets
