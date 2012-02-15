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
        rulesets = wsd.load_rulesets()
        disabled_rulesets = self.request.cookies.get('d')
        if disabled_rulesets:
            disabled_rulesets = disabled_rulesets.split('|')
        else:
            disabled_rulesets = []
        template_values = {
            'rulesets': rulesets,
            'disabled': disabled_rulesets
        }
        template = jinja_environment.get_template('index.html')
        self.response.out.write(template.render(template_values))


class Process(webapp2.RequestHandler):
    def post(self):
        text = self.request.get('text')
        checked_rulesets = self.request.POST.getall('ruleset')
        rulesets = []
        disabled = []
        for ruleset in wsd.load_rulesets():
            if ruleset.id in checked_rulesets:
                rulesets.append(ruleset)
            else:
                disabled.append(ruleset.id)
        prulesets = wsd.ProcessedRulesets(rulesets, text)
        self.response.set_cookie('d', '|'.join(disabled), max_age=365)
        self.response.out.write(prulesets.to_html(True))


handler = webapp2.WSGIApplication(
    [
        ('/', MainPage),
        ('/process', Process)
    ],
    debug=True
)
