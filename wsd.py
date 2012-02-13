#!python
# encoding: utf-8

'''
Writing Smell Detector is a tool to help find problems in your writing.
'''

import os
import sys
import re
import math
import json
import codecs

__author__ = 'John Joseph Horton, utapyngo'
__copyright__ = 'Copyright (C) 2012  John Joseph Horton, utapyngo, oDesk'
__credits__ = ['qbonnard', 'eventh']
__license__ = 'GPL'
__maintainer__ = 'utapyngo'
__email__ = 'utapyngo@gmail.com'
__status__ = 'Development'


DEFAULT_FLAGS = re.S | re.U


def _setup_logger():
    '''
    Setup and return a console logger.
    '''
    import logging
    logger = logging.getLogger(__name__)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(
        logging.Formatter('%(levelname)s: %(message)s'))
    logger.addHandler(console_handler)
    logger.setLevel(logging.INFO)
    return logger

LOG = _setup_logger()

# sys.stdout.encoding is None when piping to a file
# sys.stdout does not have the `encoding` attribute with GAE dev_appserver
_encoding = sys.stdout.encoding if hasattr(sys.stdout, 'encoding') else None
if _encoding is None:
    _encoding = sys.getfilesystemencoding()


def print_console(*args):
    '''
    Print unicode args to console replacing unknown characters
    '''
    print u' '.join(args).encode(_encoding, 'replace')


class Rule(object):
    '''
    Base class of rules
    '''
    def itermatches(self, text):
        pass

    def process(self, text):
        pass


class RuleSet(object):
    '''
    Set of rules
    '''
    def process(self, text):
        pass


class ProcessedRule(object):
    '''
    Processed rule.
    
    Contains a reference to an original rule,
    a dictionary of matched lines and
    a dictionary of pattern matches.
    '''
    def __init__(self, rule, lines, pattern_matches):
        self.rule = rule
        # dictionary of { lineno: line }
        self.lines = lines
        # dictionary of { pattern: [(lineno, start, end), ...] }
        self.pattern_matches = pattern_matches
        self.nummatches = sum(len(m) for m in pattern_matches.itervalues())


class ProcessedRuleset(object):
    '''
    Processed ruleset.
    
    Contains a reference to an original ruleset,
    a dictionary of matched lines and
    a list of processed rules.
    '''
    def __init__(self, ruleset, lines, rules):
        self.ruleset = ruleset
        self.lines = lines
        self.rules = rules
        self.nummatches = sum(rule.nummatches for rule in rules)

    def to_dict(self):
        '''
        Build and return a dictionary suitable for serialization
        which contains all the information about ruleset
        including all matches.
        '''
        result = self.ruleset.data.copy()
        matched_rules = []
        for processed_rule in self.rules:
            rule_data = processed_rule.rule.data.copy()
            rule_data['matches'] = processed_rule.pattern_matches
            matched_rules.append(rule_data)
        result['rules'] = matched_rules
        return result


class ProcessedRulesets(object):
    '''
    A collection of processed rulesets.
    
    Contains methods for serialization of results.
    '''
    def __init__(self, rulesets, text):
        '''
        Perform processing of rulesets.
        
        Args:
            rulesets: A list of raw rulesets.
            text: A text to process.
        '''
        processed_rulesets = []
        matched_lines = {}
        for ruleset in rulesets:
            processed_ruleset = ruleset.process(text)
            matched_lines.update(processed_ruleset.lines)
            processed_rulesets.append(processed_ruleset)
        self.rulesets = processed_rulesets
        self.lines = matched_lines
        self.text = text

    def to_dict(self, include_lines):
        '''
        Args:
            include_lines: A boolean indicating if matched lines
                should be included.
                
        Returns:
            A dict suitable for seraalization
            containing a rulesets key (a list of processed rulesets)
            and optionally a lines key.
        '''
        result = {'rulesets': [r.to_dict() for r in self.rulesets]}
        if include_lines:
            result['lines'] = self.lines
        return result

    def to_html(self, embed_css=True, include_empty=False):
        '''
        Convert results into HTML.
        
        Args:
            embed_css: A boolean indicating whether css should be
                embedded into the HTML code.
            include_empty: A boolean indicating whether empty rulesets,
                rules and patterns should be returned.

        Returns:
            A string of HTML code representing the results.
        '''
        from jinja2 import Environment, FileSystemLoader
        loader = FileSystemLoader(
            os.path.join(os.path.dirname(os.path.abspath(__file__)), 'html'))
        env = Environment(loader=loader)
        template = env.get_template('template.html')
        return template.render(rulesets=self.rulesets,
            lines=self.lines,
            text=self.text,
            css=loader.get_source(env, 'style.css')[0] if embed_css else None,
            include_empty=include_empty)

    def to_console(self, include_empty=False):
        '''
        Print results to console.
        
        Args:
            include_empty: A boolean indicating whether empty rulesets,
                rules and patterns should be printed.
        '''
        # max number of digits in line number
        max_digits = int(math.ceil(math.log10(self.text.count('\n') + 1)))

        def print_line(line, lineno):
            '''
            Print a line together with its line number.
            
            If the line contains \n, split it into multiple lines 
            and print all of them.
            '''
            for i, chunk in enumerate(line.strip().split('\n')):
                print_console(u'{1:>{0}}: {2}'
                              .format(max_digits, lineno + i, chunk))

        for ruleset in self.rulesets:
            if not include_empty and ruleset.nummatches == 0:
                continue
            print
            print
            print_console(u'            {0} ({1})'
                          .format(ruleset.ruleset.name, ruleset.nummatches))
            if ruleset.ruleset.comments:
                for comment in ruleset.ruleset.comments:
                    print_console(comment)
            for rule in ruleset.rules:
                if not include_empty and rule.nummatches == 0:
                    continue
                print
                print_console(u'        Rule: {0} ({1})'
                              .format(rule.rule.name, rule.nummatches))
                if rule.rule.comments:
                    for comment in rule.rule.comments:
                        print_console(comment)
                if rule.rule.prefix:
                    print_console(u'        Prefix:', rule.rule.prefix)
                if rule.rule.suffix:
                    print_console(u'        Suffix:', rule.rule.suffix)
                for pattern in rule.rule.patterns:
                    opattern = pattern['original']
                    matched_lines = rule.pattern_matches.get(opattern, {})
                    nummatches = len(matched_lines)
                    if not include_empty and nummatches == 0:
                        continue
                    print
                    print_console(u'    Pattern: {0} ({1})'
                                  .format(opattern, nummatches))
                    if hasattr(rule.rule.re, 'iteritems'):
                        print_console(u'    Replace:', rule.rule.re[opattern])
                    for lineno in sorted(matched_lines.keys()):
                        linespan, matches = matched_lines[lineno]
                        data = ''
                        for i in range(linespan):
                            data += self.lines[lineno + i] + '\n'
                        offset = 0
                        chunks = [{'data': data}]
                        for match in matches:
                            start = match[0] - offset
                            end = match[1] - offset
                            line = chunks.pop()['data']
                            chunks.append({'highlight': False,
                                           'data': line[:start]})
                            chunks.append({'highlight': True,
                                           'data': line[start:end]})
                            chunks.append({'highlight': False,
                                           'data': line[end:]})
                            offset += len(line) - len(chunks[-1]['data'])
                        for chunk in chunks:
                            if chunk['highlight']:
                                chunk['data'] = '*' + chunk['data'] + '*'
                        print_line(''.join([c['data'] for c in chunks]), lineno)


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

    def __init__(self, data, prefix, suffix, flags, replace):
        Rule.__init__(self)
        self.data = data
        self.name = data.get('name', '')
        self.comments = data.get('comments', [])
        self.prefix = data.get('prefix', prefix)
        if '\b' in self.prefix:
            LOG.warn(r'\b found in prefix. \
                To match word boundaries use \\b instead.')
        self.suffix = data.get('suffix', suffix)
        if '\b' in self.suffix:
            LOG.warn(r'\b found in suffix. \
                To match word boundaries use \\b instead.')
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
            compiled = re.compile(self.prefix + patern + self.suffix,
                                  self.flags)
            self.patterns.append({'compiled': compiled,
                                  'original': original_pattern})

    def itermatches(self, text):
        '''
        Return an iterator over all pairs (pattern, matches).
        matches is an iterator over all matches in the text.
        '''
        for pattern in self.patterns:
            yield pattern, pattern['compiled'].finditer(text)

    def process(self, text):
        '''
        Apply the rule to text and return the result
        '''
        matched_lines = {}
        pattern_matches = {}

        def add_line(line, lineno):
            '''
            Add a line to the matched_lines dictionary.

            If the line contains \n, split it into multiple lines
            and add all of them.
            '''
            for i, chunk in enumerate(line.strip('\n').split('\n')):
                matched_lines[lineno + i] = chunk

        for pattern, matches in self.itermatches(text):
            rmatches = {}
            line = None
            for match in matches:
                start, end = match.span()
                lineno = text.count('\n', 0, start) + 1
                linestart = text.rfind('\n', 0, start) + 1
                lineend = text.find('\n', end, -1)
                if lineend > 0:
                    line = text[linestart:lineend]
                else:
                    line = text[linestart:]
                add_line(line, lineno)
                # location of the match relative to current line
                lstart, lend = start - linestart, end - linestart
                linespan = line.strip().count('\n') + 1
                if lineno in rmatches:
                    rmatches[lineno][0] = linespan
                    rmatches[lineno][1].append((lstart, lend))
                else:
                    rmatches[lineno] = [linespan, [(lstart, lend)]]
            if rmatches:
                pattern_matches[pattern['original']] = rmatches
        return ProcessedRule(self, matched_lines, pattern_matches)


class RegularExpressionRuleSet(RuleSet):
    '''
    Set of regular expression rules
    '''
    def __init__(self, data):
        RuleSet.__init__(self)
        self.data = data
        self.name = data['ruleset']
        self.comments = data.get('comments')
        self.prefix = data.get('prefix', '')
        self.suffix = data.get('suffix', '')
        self.flags = process_flags(data.get('flags', ''), DEFAULT_FLAGS)
        self.replace = data.get('replace', {})
        self.rules = [
            RegularExpressionRule(
                d, self.prefix, self.suffix, self.flags, self.replace)
            for d in data['rules']
        ]

    def process(self, text):
        '''
        Apply all rules to text and return the results
        '''
        matched_lines = {}
        matched_rules = []
        for rule in self.rules:
            processed_rule = rule.process(text)
            matched_lines.update(processed_rule.lines)
            matched_rules.append(processed_rule)
        return ProcessedRuleset(self, matched_lines, matched_rules)


class IterableEncoder(json.JSONEncoder):
    '''
    JSON encoder which supports encoding of iterables.
    '''
    def default(self, o):
        try:
            iterable = iter(o)
        except TypeError:
            pass
        else:
            return list(iterable)
        return super(IterableEncoder, self).default(o)


def load_rulesets(masks=None):
    '''
    Load rulesets from masks list.
    Shell wildcards are allowed.
    Load from `rules` directory by default.
    '''
    from glob import glob
    jsoncomment = re.compile('^\s*//')
    rulesets = []
    if not masks:
        masks = [
            os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                'rules',
                '*'
            )
        ]
    for mask in masks:
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
                ruleset = RegularExpressionRuleSet(ruleset_dict)
                rulesets.append(ruleset)
        if empty_mask:
            LOG.warn('No files matching "{0}" found'.format(mask))
    return rulesets


def main(args):
    '''
    Load text from args.text.
    Load and run rulesets from args.ruleset list.
    Store results to args.outfile if specified.
    '''
    # Load the text
    if not os.path.isfile(args.text):
        LOG.error('File not found: ' + args.text)
        return 1
    text = codecs.open(args.text, encoding='utf-8').read()
    LOG.info('Loaded {0} bytes from {1}'.format(len(text), args.text))
    # Load and process rulesets
    rulesets = load_rulesets(args.ruleset)
    prulesets = ProcessedRulesets(rulesets, text)
    # Output the result
    if args.outfile:
        if args.output_format == 'json':
            if args.reftext:
                path = os.path.abspath(args.text) if args.abspath else args.text
                json_results = prulesets.to_dict(False)
                import hashlib
                json_results['text'] = {
                    'file': path,
                    'md5': hashlib.md5(args.text).hexdigest()
                }
            else:
                json_results = prulesets.to_dict(True)
            json.dump(json_results,
                      codecs.open(args.outfile, 'wb', encoding='utf-8'),
                      indent=args.indent, cls=IterableEncoder)
        elif args.output_format == 'html':
            html = prulesets.to_html(not args.no_embed_css, args.include_empty)
            outfile = codecs.open(args.outfile, 'wb', encoding='utf-8')
            outfile.write(html)
        LOG.info('Results saved to: {0}'.format(args.outfile))
    else:
        prulesets.to_console(args.include_empty)


def parse_args():
    '''
    Parse and return command line arguments.
    '''
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('text', type=str,
        help='text file',)
    parser.add_argument('ruleset', type=str, nargs='*',
        help='ruleset file')
    export = parser.add_argument_group('export')
    html_group = parser.add_argument_group('html')
    json_group = parser.add_argument_group('json')
    export.add_argument('-o', '--outfile', action='store',
        help='output file name')
    export.add_argument('-f', '--output-format',
        default='html', choices=('json', 'html'),
        help='output file format')
    export.add_argument('-e', '--include-empty', action='store_true',
        help='Include empty rules to output')
    html_group.add_argument('-nec', '--no-embed-css', action='store_true',
        help="don't embed style.css into generated html file")
    json_group.add_argument('-r', '--reftext', action='store_true',
        help = 'insert a reference to the text file into the output \
        json file instead of the list of matching lines')
    json_group.add_argument('-a', '--abspath', action='store_true',
        help = 'insert absolute path to the text file into the output \
        json file instead of the path passed to command line')
    json_group.add_argument('-i', '--indent',
        type=int, action='store', default=4,
        help='json indent size')
    try:
        args = parser.parse_args()
    except Exception, exc:
        LOG.error(exc)
        sys.exit(1)
    if args.indent == 0:
        args.indent = None
    return args

if __name__ == '__main__':
    sys.exit(main(parse_args()))
