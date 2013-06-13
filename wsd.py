#!/usr/bin/env python
# encoding: utf-8

'''
Writing Smell Detector is a tool to help find problems in your writing.
'''

import os
import sys
import math
import json
from glob import glob
import codecs

__author__ = 'John Joseph Horton, utapyngo'
__copyright__ = 'Copyright (C) 2012  John Joseph Horton, utapyngo, oDesk'
__credits__ = ['qbonnard', 'eventh']
__license__ = 'GPL'
__maintainer__ = 'utapyngo'
__email__ = 'utapyngo@gmail.com'
__status__ = 'Development'
__version__ = '0.1'


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
    def __init__(self, ruleset, name, comments=[], props={}):
        self.ruleset = ruleset
        self.name = name
        self.comments = comments
        self.props = props
        self.patterns = [{'original': ''}]

    def itermatches(self, text):
        pass

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
                start, end = match
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


class Ruleset(object):
    '''
    Set of rules
    '''
    def __init__(self, name, comments=[], props={}, uid=None):
        self.name = name
        self.comments = comments
        self.props = props
        if uid:
            self.uid = uid
        else:
            self.uid = name

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

        def print_pattern(rule, pattern):
            matched_lines = rule.pattern_matches.get(pattern, {})
            nummatches = len(matched_lines)
            if not include_empty and nummatches == 0:
                return
            print
            print_console(u'    Pattern: {0} ({1})'
                          .format(pattern, nummatches))
            if hasattr(rule.rule, 'get_pattern_props'):
                props = rule.rule.get_pattern_props(pattern)
                for pp, pv in props.iteritems():
                    print_console(u'    {0}: {1}'.format(pp.title(), pv))
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
                for prop, value in rule.rule.props.iteritems():
                    if value:
                        print_console(u'        {0}: {1}'.format(prop.title(), value))
                for pattern in rule.rule.patterns:
                    print_pattern(rule, pattern['original'])


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


def main(args):
    '''
    Load text from args.text.
    Load and run rulesets from args.ruleset list.
    Store results to args.outfile if specified.
    '''
    # Check for errors
    if not os.path.isfile(args.text):
        LOG.error('File not found: ' + args.text)
        return 1
    # Load text
    text = codecs.open(args.text, encoding='utf-8').read()
    LOG.info('Loaded {0} bytes from {1}'.format(len(text), args.text))
    # Load rules
    rulesets = []
    rules = args.rules
    if rules:
        while rules:
            rule_name = rules[0]
            rules[0:1] = []
            mod = __import__('{0}_rules'.format(rule_name))
            if hasattr(mod, 'get_rulesets'):
                argcount = mod.get_rulesets.func_code.co_argcount
                rule_args = rules[:argcount]
                rules[:argcount] = []
                rulesets.extend(mod.get_rulesets(*rule_args))
    else:
        for rule_name in (fn[:-9] for fn in glob('*_rules.py')):
            try:
                mod = __import__('{0}_rules'.format(rule_name))
                rulesets.extend(mod.get_rulesets())
                LOG.info('Loaded: {0}'.format(rule_name))
            except Exception, e:
                LOG.warn('Not loaded: {0}: {1}'.format(rule_name, e))
    # Process rules
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
    ruletypes = (fn[:-9] for fn in glob('*_rules.py'))
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('text', type=str,
        help='text file',)
    parser.add_argument('rules', type=str, nargs='*',
        help = 'rule type followed by arguments required by this type\n' +
        'available types of rules are: ' + ', '.join(ruletypes))
    #parser.add_argument('--info', type=str, metavar='RULETYPE',
    #    help='show number of arguments and docstrings of a specific rule type')
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
        help='insert a reference to the text file into the output \
        json file instead of the list of matching lines')
    json_group.add_argument('-a', '--abspath', action='store_true',
        help='insert absolute path to the text file into the output \
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
    print parse_args() 
    sys.exit(main(parse_args()))
