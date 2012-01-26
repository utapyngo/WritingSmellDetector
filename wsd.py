#!python
# encoding: utf-8

import re
import math

import logging
logger = logging.getLogger(__name__)
ch = logging.StreamHandler()
ch.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
logger.addHandler(ch)
logger.setLevel(logging.INFO)


class Rule(object):
    '''Base class of rules'''

    def itermatches(self, text):
        pass

    def process(self, text):
        pass

    def process_and_print(self, text):
        pass


class RuleSet(object):
    '''Set of rules'''

    def process(self, text):
        pass

    def process_and_print(self, text):
        pass


class RuleResults(object):
    
    def __init__(self, rule, lines, pattern_matches):
        self.rule = rule
        # dictionary of { lineno: line }
        self.lines = lines
        # dictionary of { pattern: [(lineno, start, end), ...] }
        self.pattern_matches = pattern_matches
              

class RulesetResults(object):
    
    def __init__(self, ruleset, lines, matched_rules):
        self.ruleset = ruleset
        self.lines = lines
        self.matched_rules = matched_rules
        
    def to_dict(self):
        result = self.ruleset.data.copy()
        matched_rules = []
        for processed_rule in self.matched_rules:
            rule_data = processed_rule.rule.data.copy()
            rule_data['matches'] = processed_rule.pattern_matches
            matched_rules.append(rule_data)
        result['rules'] = matched_rules
        return result


def process_flags(flags, default=0):
    '''Process a string of regular expression flags like "+LUX-M".
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
                result = result &~ getattr(re, flag)
            else:
                result |= getattr(re, flag)
        else:
            logger.warn('unknown flag: ' + flag)
            continue
    return result


default_flags = re.S | re.U


class RegularExpressionRule(Rule):
    '''Regular expression rule'''

    def __init__(self, data, prefix, suffix, flags, replace):
        self.data = data
        self.name = data.get('name', '')
        self.comments = data.get('comments', [])
        self.prefix = data.get('prefix', prefix)
        if '\b' in self.prefix:
            logger.warn(r'\b found in prefix. To match word boundaries use \\b instead.')
        self.suffix = data.get('suffix', suffix)
        if '\b' in self.suffix:
            logger.warn(r'\b found in suffix. To match word boundaries use \\b instead.')
        self.flags = process_flags(data.get('flags', ''), flags)
        self.replace = data.get('replace', replace)
        self.re = data.get('re', [])
        if isinstance(self.re, basestring):
            patterns = [ self.re ]
        elif hasattr(self.re, '__getitem__'):
            patterns = self.re
        for p in patterns:
            if '\b' in p:
                logger.warn(r'\b found in pattern {0}. To match word boundaries use \\b instead.'.format(p.replace('\b', r'\b')))
        self.patterns = []
        for p in patterns:
            original_pattern = p
            for s, r in self.replace.iteritems():
                p = re.sub(s, r, p)
            compiled = re.compile(self.prefix + p + self.suffix, self.flags)
            self.patterns.append({ 'compiled': compiled,
                                   'original': original_pattern })

    def itermatches(self, text):
        '''
        Return an iterator over all pairs (pattern, matches).
        matches is an iterator over all matches in the text.
        '''
        for pattern in self.patterns:
            yield pattern, pattern['compiled'].finditer(text)

    def process(self, text):
        '''Apply the rule to text and return the result'''

        matched_lines = {}
        pattern_matches = {}

        def add_line(line, lineno):
            for i, chunk in enumerate(line.strip().split('\n')):
                matched_lines[lineno + i] = chunk

        for pattern, matches in self.itermatches(text):
            rmatches = []
            line = None
            for m in matches:
                start, end = m.span()
                lineno = text.count('\n', 0, start) + 1
                linestart = text.rfind('\n', 0, start) + 1
                lineend = text.find('\n', end, -1)
                line = text[linestart:lineend] if lineend > 0 else text[linestart:]
                add_line(line, lineno)
                # location of the match relative to current line
                lstart, lend = start - linestart, end - linestart
                rmatches.append((lineno, lstart, lend))
            if rmatches:
                pattern_matches[pattern['original']] = rmatches
        return RuleResults(self, matched_lines, pattern_matches)

    def process_and_print(self, text):
        '''Apply the rule to text and print the results'''

        # max number of digits in line number
        line_number_max_digits = int(math.ceil(math.log10(text.count('\n') + 1)))

        def print_line(line, lineno):
            for i, chunk in enumerate(line.strip().split('\n')):
                print('{1:>{0}}: {2}'.format(line_number_max_digits, lineno + i, chunk))

        print
        if self.name or self.comments:
            print 'Rule:', self.name
        if self.comments:
            for comment in self.comments:
                print comment

        if hasattr(self.re, 'iteritems'):
            max_length = 1 + max([len(e) for e in self.re.iterkeys()])
            for pattern, replacement in self.re.iteritems():
                print '{1:>{0}} -> {2}'.format(max_length, pattern, replacement)

        for pattern, matches in self.itermatches(text):
            print
            print 'Pattern: /{0}/'.format(pattern['original'])
            found = False
            line = None
            plineno = None
            for m in matches:
                found = True
                start, end = m.span()
                lineno = text.count('\n', 0, start) + 1
                if plineno is not None and lineno != plineno:
                    # this is another line
                    # print previous line
                    print_line(line, plineno)
                if plineno is None or lineno != plineno:
                    # first iteration or other line
                    linestart = text.rfind('\n', 0, start) + 1
                    lineend = text.find('\n', end, -1)
                    line = text[linestart:lineend] if lineend > 0 else text[linestart:]
                # location of the match relative to current line
                lstart, lend = start - linestart, end - linestart
                line = line[:lstart] + '*' + line[lstart:lend] + '*' + line[lend:]
                linestart -= 2
                plineno = lineno
            if found:
                print_line(line, plineno)
            else:
                print "No matches"


class RegularExpressionRuleSet(RuleSet):
    '''Set of regular expression rules'''

    def __init__(self, data):
        self.data = data
        self.name = data['ruleset']
        self.comments = data.get('comments')
        self.prefix = data.get('prefix', '')
        self.suffix = data.get('suffix', '')
        self.flags = process_flags(data.get('flags', ''), default_flags)
        self.replace = data.get('replace', {})
        self.rules = [RegularExpressionRule(d, self.prefix, self.suffix, self.flags, self.replace) for d in data['rules']]

    def process_and_print(self, text):
        '''Apply all rules to text and print the results'''
        print
        print
        print 'Ruleset:', self.name
        if self.comments:
            for comment in self.comments:
                print comment
        for rule in self.rules:
            rule.process_and_print(text)

    def process(self, text):
        '''Apply all rules to text and return the results'''
        matched_lines = {}
        matched_rules = []
        for rule in self.rules:
            processed_rule = rule.process(text)
            matched_lines.update(processed_rule.lines)
            matched_rules.append(processed_rule)
            #if processed_rule.pattern_matches:
            #    matched_rules.append((rule, processed_rule.pattern_matches))
        return RulesetResults(self, matched_lines, matched_rules)


def analyze(args):
    '''
    Load text from args.text.
    Load and run rulesets from args.ruleset list.
    Shell wildcards are allowed in ruleset arguments.
    Store results to args.outfile if specified.
    '''
    from glob import glob
    import os
    import json

    if not args.ruleset:
        args.ruleset = [os.path.join(os.path.dirname(os.path.abspath(__file__)), 'rules', '*')]

    if not os.path.isfile(args.text):
        logger.error('File not found: ' + args.text)
        return 1
    text = open(args.text).read()
    logger.info('Loaded {0} bytes of text from {1}'.format(len(text), args.text))

    jsoncomment = re.compile('^\s*//')
    rulesets = []
    matched_lines = {}
    for mask in args.ruleset:
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
                    jsonrule = ''.join(['\n' if jsoncomment.search(line) else line for line in open(rule_file).readlines()])
                    ruleset_dict = json.loads(jsonrule)
                except ValueError, e:
                    logger.error(e)
                    logger.error("In file: " + rule_file)
                    continue
                ruleset = RegularExpressionRuleSet(ruleset_dict)
                if args.outfile:
                    processed_ruleset = ruleset.process(text)
                    matched_lines.update(processed_ruleset.lines)
                    rulesets.append(processed_ruleset)
                else:
                    ruleset.process_and_print(text)
        if empty_mask:
            logger.warn('No files matching "{0}" found'.format(mask))
    if args.outfile:
        json_results = { 'rulesets': [r.to_dict() for r in rulesets] }
        if args.reftext:
            import hashlib
            json_results['text'] = {
                'file': os.path.abspath(args.text) if args.abspath else args.text,
                'md5': hashlib.md5(args.text).hexdigest()
            }
        else:
            json_results['lines'] = matched_lines
        json.dump(json_results, open(args.outfile, 'wb'), indent=args.indent)
        logger.info('Results saved to: {0}'.format(args.outfile))

if __name__ == '__main__':
    import sys
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('text', type=str,
        help='text file',)
    parser.add_argument('ruleset', type=str, nargs='*',
        help='ruleset file')
    parser.add_argument('-o', '--outfile', action='store',
        help='output file name')
    parser.add_argument('-r', '--reftext', action='store_true',
        help='insert a reference to the text file into the output file instead of a list of matching lines')
    parser.add_argument('-a', '--abspath', action='store_true',
        help='use absolute path to the text file instead of the path passed to command line')
    parser.add_argument('-i', '--indent', type=int, action='store', default=4,
        help='json indent size')
    try:
        args = parser.parse_args()
    except Exception, e:
        logger.error(e)
        sys.exit(1)
    if args.indent == 0:
        args.indent = None
    sys.exit(analyze(args))
