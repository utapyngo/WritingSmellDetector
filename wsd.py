import re

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


class RegularExpressionRule(WritingSmellRule):
    '''Regular expression rule'''

    def __init__(self, json_dict, prefix='', suffix=''):
        self.name = json_dict.get('name', '')
        self.comments = json_dict.get('comments', [])
        self.prefix = json_dict.get('prefix', prefix)
        self.suffix = json_dict.get('suffix', suffix)
        self.re = json_dict.get('re', [])
        self.patterns = []
        if isinstance(self.re, basestring):
            self.patterns = [self.re]
        elif hasattr(self.re, '__getitem__'):
            self.patterns = [e for e in self.re]

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
            # pattern with prefix and suffix
            p = self.prefix + pattern + self.suffix
            # list of pairs (piece, matches)
            piece_matches = []
            for piece in pieces:
                matches = re.finditer(p, piece)
                if re.search(p, piece):
                    piece_matches.append((piece, matches))
            yield p, piece_matches

    def process(self, text):
        '''Apply the rule to text and print the results'''
        print
        if self.name:
            print 'Rule:', self.name
        if self.comments:
            for comment in self.comments:
                print comment
        # generate warning
        if '\b' in self.prefix:
            print r'WARNING: \b found in prefix. To match word boundaries use \\b instead.'
        if '\b' in self.suffix:
            print r'WARNING: \b found in suffix. To match word boundaries use \\b instead.'

        if hasattr(self.re, 'iteritems'):
            for pattern, replacement in self.re.iteritems():
                print '{0:>40} -> {1}'.format(pattern, replacement)
        for pattern, item_matches in self.match_text(text):
            print
            print 'Pattern: "{0}"'.format(pattern)
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
                        print '{0}: {1}'.format(plineno, line)
                    if plineno is None or lineno != plineno:
                        # first iteration or other line
                        linestart = item.rfind('\n', 0, start) + 1
                        lineend = item.find('\n', end, -1)
                        line = text[linestart:lineend]
                    lstart, lend = start - linestart, end - linestart
                    line = line[:lstart] + '*' + line[lstart:lend] + '*' + line[lend:]
                    linestart -= 2
                    plineno = lineno
                print '{0}: {1}'.format(plineno, line)
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
        self.rules = [RegularExpressionRule(d, self.prefix, self.suffix) for d in json_dict['rules']]

    def process(self, text):
        '''Apply all rules to text and print the results'''
        # lines = text.split('\n')
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
        print 'File not found:', filename
        return 1
    text = open(filename).read()
    print 'Loaded {0} bytes of text from {1}'.format(len(text), filename)

    for mask in rule_file_masks:
        empty_mask = True
        for rule_file_or_dir in glob(mask):
            empty_mask = False
            if os.path.isdir(rule_file_or_dir):
                rule_files = glob(os.path.join(rule_file_or_dir, '*'))
            else:
                rule_files = (rule_file_or_dir,)
            for rule_file in rule_files:
                ruleset = RegularExpressionRuleSet(json.load(open(rule_file)))
                ruleset.process(text)
            print
        if empty_mask:
            print 'No files matching "{0}" found'.format(mask)

if __name__ == '__main__':
    import sys
    sys.exit(main(*sys.argv[1:]))
