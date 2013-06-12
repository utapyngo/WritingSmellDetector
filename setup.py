#!/usr/bin/env python
# -*- coding: utf-8 -*-
from distutils.core import setup
from os.path import join, dirname

import wsd


setup(name='WritingSmellDetector',
      version=wsd.__version__,
      description='Writing Smell Detector is a tool '
      'to help find problems in your writing',
      long_description=open(join(dirname(__file__), 'README.md')).read(),
      author=wsd.__author__,
      author_email=wsd.__email__,
      url='http://github.com/utapyngo/WritingSmellDetector',
      packages=[''],
      package_data={'': ['*.md', 'html/*.html', 'html/*.css',
                         'rules/*.json', 'rules/latex/*.json']},
      scripts=['wsd.py'],
      classifiers=(
          'Development Status :: 3 - Alpha',
          'Environment :: Console',
          'Environment :: Web Environment',
          'License :: OSI Approved :: GNU General Public License v3 or '
          'later (GPLv3+)',
          'Natural Language :: English',
          'Programming Language :: Python',
          'Programming Language :: Python :: 2.6',
          'Programming Language :: Python :: 2.7',
      ),
      install_requires=['Jinja2>=2.6'],
)
