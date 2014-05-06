from collections import defaultdict

from jinja2 import Environment, PackageLoader

from tlsspy.report.base import Report


class HTMLReport(Report):
    def render(self, results):
        env = Environment(
            loader=PackageLoader('tlsspy', 'report')
        )
        template = env.get_template('report.html')

        errors   = []
        warnings = []
        analysis = results['analysis']

        for checks in ('ciphers', 'public_keys'):
            for item in analysis.get(checks, []):
                name, values = item.items()[0]
                if not 'reason' in values:
                    continue
                elif values['status'] == 'error':
                    errors.append('{} {}: {}'.format(
                        checks[:-1].replace('_', ' ').capitalize(),
                        name.capitalize(),
                        values['reason']
                    ))
                elif values['status'] in ['warning', 'uknown']:
                    warnings.append('{} {}: {}'.format(
                        checks[:-1].replace('_', ' ').capitalize(),
                        name.capitalize(),
                        values['reason']
                    ))

        import pprint
        pprint.pprint(results)

        rendered = template.render(
            site=self.options.host,
            report=results,
            analysis=results.get('analysis', {}),
            features=results.get('analysis', {}).get('features', {}),
            errors=errors,
            warnings=warnings,
        )
        fd = self.open('utf_8')
        fd.write(rendered)


Report.register('html', HTMLReport)
