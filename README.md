Writing Smell Detector
======================

A tool for finding problematic writing.

Requirements
------------

* [Python](http://python.org/download/) 2.6 or 2.7;
* [argparse](http://pypi.python.org/pypi/argparse) (bundled with Python 2.7);
* [jinja2](http://jinja.pocoo.org/).

Usage
-----

Simple usage:

    python wsd.py -o output_file.html your_text_file
    
will try to process your text with all rules 
and will output the result into an html file.

For advanced usage please refer to `python wsd.py --help`.
