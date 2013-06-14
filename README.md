Writing Smell Detector
======================

A tool for finding problematic writing.

Requirements
------------

* [Python](http://python.org/download/) 2.6 or 2.7;
* [argparse](http://pypi.python.org/pypi/argparse) (bundled with Python 2.7);
* [jinja2](http://jinja.pocoo.org/).

Installation
------------

CLone the repository onto your local machine, change into that directory and run: 

    sudo python setup.py install 

You can also just launch wsd.py from the directory without doing an installation. 

Usage
-----

Simple usage (following installation):

    wsd -o output_file.html your_text_file
    
This will try to process your text with all rules 
and will output the result into an html file.

If you did not install it, you can run it via: 

    python wsd.py --o output_file.html your_text_file 

For advanced usage please refer to `wsd --help`.
