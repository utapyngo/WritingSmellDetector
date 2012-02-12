# encoding: utf-8

import os
import jinja2
import webapp2
import wsd

jinja_environment = jinja2.Environment(
    loader=jinja2.FileSystemLoader(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), 'html')
    )
)


class MainPage(webapp2.RequestHandler):
    def get(self):
        template_values = {
        }
        template = jinja_environment.get_template('index.html')
        self.response.out.write(template.render(template_values))


class Process(webapp2.RequestHandler):
    def post(self):
        text = self.request.get('text')
        rulesets = wsd.load_rulesets()
        processed_rulesets = []
        matched_lines = {}
        for ruleset in rulesets:
            processed_ruleset = ruleset.process(text)
            matched_lines.update(processed_ruleset.lines)
            processed_rulesets.append(processed_ruleset)
        p = wsd.ProcessedRulesets(processed_rulesets, matched_lines, text)
        self.response.out.write(p.to_html(embed_css=True, include_empty=False))


handler = webapp2.WSGIApplication(
    [
        ('/', MainPage),
        ('/process', Process)
    ],
    debug=True
)
