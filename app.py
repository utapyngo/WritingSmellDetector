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
        prulesets = wsd.ProcessedRulesets(rulesets, text)
        self.response.out.write(prulesets.to_html(True))


handler = webapp2.WSGIApplication(
    [
        ('/', MainPage),
        ('/process', Process)
    ],
    debug=True
)
