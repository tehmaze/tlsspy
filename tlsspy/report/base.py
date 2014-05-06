import codecs
import sys


class Report(object):
    types = {}

    def __init__(self, options):
        self.options = options

    @classmethod
    def register(cls, typ, report):
        cls.types[typ] = report

    def render(self, results):
        raise NotImplementedError()

    def open(self, encoding='ascii'):
        if self.options.output and self.options.output != '-':
            return codecs.open(self.options.output, 'wb', encoding)
        else:
            return sys.stdout


def make_report(typ, results, options=None):
    report = Report.types[typ](options)
    report.render(results)
