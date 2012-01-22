import re
import math

import logging
logger = logging.getLogger(__name__)
ch = logging.StreamHandler()
ch.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
logger.addHandler(ch)
logger.setLevel(logging.INFO)

class WritingSmellRule(object):
    '''Base class of rules'''

    def match_text(self, text):
        pass

    def process(self, text):
        pass


class WritingSmellRuleSet(object):
    '''Set of rules'''

    def process(self, text):
        pass


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


class RegularExpressionRule(WritingSmellRule):
    '''Regular expression rule'''

    def __init__(self, json_dict, prefix, suffix, flags, replace):
        self.name = json_dict.get('name', '')
        self.comments = json_dict.get('comments', [])
        self.prefix = json_dict.get('prefix', prefix)
        self.suffix = json_dict.get('suffix', suffix)
        self.flags = process_flags(json_dict.get('flags', ''), flags)
        self.replace = json_dict.get('replace', replace)
        self.re = json_dict.get('re', [])
        if isinstance(self.re, basestring):
            patterns = [self.prefix + self.re + self.suffix]
        elif hasattr(self.re, '__getitem__'):
            patterns = [self.prefix + e + self.suffix for e in self.re]
        self.patterns = []
        for p in patterns:
            for s, r in self.replace.iteritems():
                p = re.sub(s, r, p)
            self.patterns.append(re.compile(p, self.flags))

    def match_text(self, text):
        '''
        Return an iterator over all patterns in rule.
        Each pattern is accompanied with a list of pairs (piece, matches).
        piece is an item of the text array.
        matches is an iterator over all matches in the respective piece.
        text can be either a list of strings or a string.
        In case it is a string, each pattern has only one (piece, matches) pair
        where piece is equal to text
        '''
        if isinstance(text, basestring):
            pieces = [text]
        else:
            pieces = text
        for pattern in self.patterns:
            # list of pairs (piece, matches)
            piece_matches = []
            for piece in pieces:
                matches = pattern.finditer(piece)
                if pattern.search(piece):
                    piece_matches.append((piece, matches))
            yield pattern, piece_matches

    def process(self, text):
        '''Apply the rule to text and print the results'''

        # max number of digits in line number
        line_number_max_digits = int(math.ceil(math.log10(text.count('\n') + 1)))

        def print_line(line, lineno):
            for i, chunk in enumerate(line.split('\n')):
                # print ('{{0:>{0}}}: {{1}}').format(line_number_max_digits).format(lineno + i, chunk)
                print('{1:>{0}}: {2}'.format(line_number_max_digits, lineno + i, chunk))

        print
        if self.name or self.comments:
            print 'Rule:', self.name
        if self.comments:
            for comment in self.comments:
                print comment
        # generate warning
        if '\b' in self.prefix:
            logger.warn(r'\b found in prefix. To match word boundaries use \\b instead.')
        if '\b' in self.suffix:
            logger.warn(r'\b found in suffix. To match word boundaries use \\b instead.')

        if hasattr(self.re, 'iteritems'):
            max_length = 1 + max([len(e) for e in self.re.iterkeys()])
            for pattern, replacement in self.re.iteritems():
                print '{1:>{0}} -> {2}'.format(max_length, pattern, replacement)

        for pattern, item_matches in self.match_text(text):
            print
            print 'Pattern: /{0}/'.format(pattern.pattern)
            found = False
            for item, matches in item_matches:
                line = None
                plineno = None
                for m in matches:
                    start, end = m.span()
                    lineno = item.count('\n', 0, start)
                    if plineno is not None and lineno != plineno:
                        # this is another line
                        # print previous line
                        print_line(line, plineno)
                    if plineno is None or lineno != plineno:
                        # first iteration or other line
                        linestart = item.rfind('\n', 0, start) + 1
                        lineend = item.find('\n', end, -1)
                        line = text[linestart:lineend]
                    # location of the match relative to current line
                    lstart, lend = start - linestart, end - linestart
                    line = line[:lstart] + '*' + line[lstart:lend] + '*' + line[lend:]
                    linestart -= 2
                    plineno = lineno
                print_line(line, plineno)
                found = True
            if not found:
                print "No matches"


class RegularExpressionRuleSet(WritingSmellRuleSet):
    '''Set of regular expression rules'''

    def __init__(self, json_dict):
        self.name = json_dict['ruleset']
        self.comments = json_dict.get('comments')
        self.prefix = json_dict.get('prefix', '')
        self.suffix = json_dict.get('suffix', '')
        self.flags = process_flags(json_dict.get('flags', ''), default_flags)
        self.replace = json_dict.get('replace', {})
        self.rules = [RegularExpressionRule(d, self.prefix, self.suffix, self.flags, self.replace) for d in json_dict['rules']]

    def process(self, text):
        '''Apply all rules to text and print the results'''
        print
        print
        print 'Ruleset:', self.name
        if self.comments:
            for comment in self.comments:
                print comment
        for rule in self.rules:
            rule.process(text)


def usage():
    print 'Usage:'
    print ' ', __file__, '<textfile> [<ruleset files mask> ...]'

def main(*args):
    '''
    Load text from first argument.
    Load and run rulesets from files specified by all other arguments.
    Shell wildcards are allowed in ruleset arguments.
    '''
    from glob import glob
    import os
    import json

    if len(args) < 1:
        usage()
        return 1
    if len(args) == 1:
        rule_file_masks = [os.path.join(os.path.dirname(os.path.abspath(__file__)), 'rules', '*')]
    else:
        rule_file_masks = args[1:]
    filename = args[0]
    if not os.path.isfile(filename):
        logger.error('File not found: ' + filename)
        return 1
    text = open(filename).read()
    logger.info('Loaded {0} bytes of text from {1}'.format(len(text), filename))
    jsoncomment = re.compile('^\s*//')
    for mask in rule_file_masks:
        empty_mask = True
        for rule_file_or_dir in glob(mask):
            empty_mask = False
            if os.path.isdir(rule_file_or_dir):
                rule_files = glob(os.path.join(rule_file_or_dir, '*'))
            else:
                rule_files = (rule_file_or_dir,)
            for rule_file in rule_files:
                try:
                    # remove comments preserving the same number of lines
                    jsonrule = ''.join(['\n' if jsoncomment.search(line) else line for line in open(rule_file).readlines()])
                    json_dict = json.loads(jsonrule)
                except ValueError, e:
                    logger.error(e)
                    logger.error("In file: " + rule_file)
                    continue
                ruleset = RegularExpressionRuleSet(json_dict)
                ruleset.process(text)
            print
        if empty_mask:
            logger.warn('No files matching "{0}" found'.format(mask))

if __name__ == '__main__':
    import sys
    sys.exit(main(*sys.argv[1:]))
