#!python
# encoding: utf-8

'''Writing Smell Detector is a tool to help find problems in your writing.'''

import os
import sys
import re
import math
import json
import codecs

__author__ = 'John Joseph Horton, utapyngo'
__copyright__ = 'Copyright (C) 2012  John Joseph Horton, utapyngo, oDesk'
__credits__= ['qbonnard']
__license__ = 'GPL'
__maintainer__ = 'utapyngo'
__email__ = 'utapyngo@gmail.com'
__status__ = 'Development'

import logging
logger = logging.getLogger(__name__)
ch = logging.StreamHandler()
ch.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
logger.addHandler(ch)
logger.setLevel(logging.INFO)

def print_console(*args):
    print u' '.join(args).encode(sys.stdout.encoding, 'replace')

class Rule(object):
    '''Base class of rules'''

    def itermatches(self, text):
        pass

    def process(self, text):
        pass


class RuleSet(object):
    '''Set of rules'''

    def process(self, text):
        pass


class ProcessedRule(object):
    
    def __init__(self, rule, lines, pattern_matches):
        self.rule = rule
        # dictionary of { lineno: line }
        self.lines = lines
        # dictionary of { pattern: [(lineno, start, end), ...] }
        self.pattern_matches = pattern_matches
        self.nummatches = sum(len(m) for m in pattern_matches.itervalues())


class ProcessedRuleset(object):
    
    def __init__(self, ruleset, lines, rules):
        self.ruleset = ruleset
        self.lines = lines
        self.rules = rules
        self.nummatches = sum(rule.nummatches for rule in rules)
        
    def to_dict(self):
        result = self.ruleset.data.copy()
        matched_rules = []
        for processed_rule in self.rules:
            rule_data = processed_rule.rule.data.copy()
            rule_data['matches'] = processed_rule.pattern_matches
            matched_rules.append(rule_data)
        result['rules'] = matched_rules
        return result


class ProcessedRulesets(object):
    
    def __init__(self, rulesets, lines, text):
        self.rulesets = rulesets
        self.lines = lines
        self.text = text
      
    def to_dict(self, include_lines):
        d = { 'rulesets': [r.to_dict() for r in self.rulesets] }
        if include_lines:
            d['lines'] = self.lines
        return d
        
    def to_html(self, embed_css=True):
        from jinja2 import Environment, FileSystemLoader
        loader = FileSystemLoader(
            os.path.join(os.path.dirname(os.path.abspath(__file__)), 'html'))
        env = Environment(loader=loader)
        template = env.get_template('template.html')
        return template.render(rulesets=self.rulesets,
            lines=self.lines,
            text=self.text,
            css=loader.get_source(env, 'style.css')[0] if embed_css else None)
        
    def to_console(self):
        # max number of digits in line number
        line_number_max_digits = int(math.ceil(math.log10(self.text.count('\n') + 1)))
        
        def print_line(line, lineno):
            for i, chunk in enumerate(line.strip().split('\n')):
                print_console(u'{1:>{0}}: {2}'.format(line_number_max_digits, lineno + i, chunk))
               
        for ruleset in self.rulesets:
            print
            print
            print_console(u'            {0} ({1})'.format(ruleset.ruleset.name, ruleset.nummatches))
            if ruleset.ruleset.comments: 
                for comment in ruleset.ruleset.comments:
                    print_console(comment)
            for rule in ruleset.rules:
                print
                print_console(u'        Rule: {0} ({1})'.format(rule.rule.name, rule.nummatches))
                if rule.rule.comments:
                    for comment in rule.rule.comments:
                        print_console(comment)
                if rule.rule.prefix:
                    print_console(u'        Prefix:', rule.rule.prefix)
                if rule.rule.suffix:
                    print_console(u'        Suffix:', rule.rule.suffix)
                for pattern in rule.rule.patterns:
                    p = pattern['original']
                    matched_lines = rule.pattern_matches.get(p, {})
                    nummatches = len(matched_lines)
                    print
                    print_console(u'    Pattern: {0} ({1})'.format(p, nummatches))
                    if hasattr(rule.rule.re, 'iteritems'):
                        print_console(u'    Replace:', rule.rule.re[p])
                    for lineno in sorted(matched_lines.keys()):
                        linespan, matches = matched_lines[lineno]
                        data = ''
                        for i in range(linespan):
                            data += self.lines[lineno+i] + '\n'
                        offset = 0
                        chunks = [{ 'data': data }]
                        for m in matches:
                            s = m[0] - offset
                            e = m[1] - offset
                            l = chunks.pop()['data']
                            chunks.append({ 'bold': False, 'data': l[:s] })
                            chunks.append({ 'bold': True, 'data': l[s:e] })
                            chunks.append({ 'bold': False, 'data': l[e:] })
                            offset = offset + (len(l) - len(chunks[-1]['data']))
                        for chunk in chunks:
                            if chunk['bold']:
                                chunk['data'] = '*' + chunk['data'] + '*'
                        print_line(''.join([c['data'] for c in chunks]), lineno)


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
            for i, chunk in enumerate(line.strip('\n').split('\n')):
                matched_lines[lineno + i] = chunk

        for pattern, matches in self.itermatches(text):
            rmatches = {}
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
                linespan = line.strip().count('\n') + 1
                if rmatches.has_key(lineno):
                    rmatches[lineno][0] = linespan
                    rmatches[lineno][1].append((lstart, lend))
                else:
                    rmatches[lineno] = [linespan, [(lstart, lend)]]
            if rmatches:
                pattern_matches[pattern['original']] = rmatches
        return ProcessedRule(self, matched_lines, pattern_matches)


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

    def process(self, text):
        '''Apply all rules to text and return the results'''
        matched_lines = {}
        matched_rules = []
        for rule in self.rules:
            processed_rule = rule.process(text)
            matched_lines.update(processed_rule.lines)
            matched_rules.append(processed_rule)
        return ProcessedRuleset(self, matched_lines, matched_rules)


class IterableEncoder(json.JSONEncoder):
    '''
    JSON encoder which supports encoding iterables.
    '''
    def default(self, o):
        try:
            iterable = iter(o)
        except TypeError:
            pass
        else:
            return list(iterable)
        return super(IterableEncoder, self).default(o)


def analyze(args):
    '''
    Load text from args.text.
    Load and run rulesets from args.ruleset list.
    Shell wildcards are allowed in ruleset arguments.
    Store results to args.outfile if specified.
    '''
    from glob import glob

    if not args.ruleset:
        args.ruleset = [os.path.join(os.path.dirname(os.path.abspath(__file__)), 'rules', '*')]

    if not os.path.isfile(args.text):
        logger.error('File not found: ' + args.text)
        return 1
    
    text = codecs.open(args.text, encoding='utf-8').read()
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
                    jsonrule = ''.join(['\n' if jsoncomment.search(line) else line for line in codecs.open(rule_file, encoding='utf-8').readlines()])
                    ruleset_dict = json.loads(jsonrule)
                except ValueError, e:
                    logger.error(e)
                    logger.error("In file: " + rule_file)
                    continue
                ruleset = RegularExpressionRuleSet(ruleset_dict)
                processed_ruleset = ruleset.process(text)
                matched_lines.update(processed_ruleset.lines)
                rulesets.append(processed_ruleset)
        if empty_mask:
            logger.warn('No files matching "{0}" found'.format(mask))
            
    p = ProcessedRulesets(rulesets, matched_lines, text)
    if args.outfile:
        if args.output_format == 'json':
            if args.reftext:
                json_results = p.to_dict(False)
                import hashlib
                json_results['text'] = {
                    'file': os.path.abspath(args.text) if args.abspath else args.text,
                    'md5': hashlib.md5(args.text).hexdigest()
                }
            else:
                json_results = p.to_dict(True)                
            json.dump(json_results, codecs.open(args.outfile, 'wb', encoding='utf-8'),
                      indent=args.indent, cls=IterableEncoder)
        elif args.output_format == 'html':
            codecs.open(args.outfile, 'wb', encoding='utf-8').write(p.to_html(not args.no_embed_css))
        logger.info('Results saved to: {0}'.format(args.outfile))
    else:
        p.to_console()
  

if __name__ == '__main__':
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
    export.add_argument('-f', '--output-format', default='html', choices=('json', 'html'),
        help='output file format')
    html_group.add_argument('-nec', '--no-embed-css', action='store_true',
        help="don't embed style.css into generated html file")
    json_group.add_argument('-r', '--reftext', action='store_true',
        help='insert a reference to the text file into the output json file instead of the list of matching lines')
    json_group.add_argument('-a', '--abspath', action='store_true',
        help='insert absolute path to the text file into the output json file  instead of the path passed to command line')
    json_group.add_argument('-i', '--indent', type=int, action='store', default=4,
        help='json indent size')
    try:
        args = parser.parse_args()
    except Exception, e:
        logger.error(e)
        sys.exit(1)
    if args.indent == 0:
        args.indent = None
    sys.exit(analyze(args))
