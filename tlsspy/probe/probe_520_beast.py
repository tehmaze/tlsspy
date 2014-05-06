from tlsspy.probe.base import Probe
from tlsspy.tls.connection import Connection


class ProbeBEAST(Probe):
    def probe(self, address, certificates):
        weakness = {}
        weakness['status'] = 'unknown'
        weakness['exists'] = False
        weakness['reason'] = 'Not implemented'

        self.merge(dict(weakness=dict(beast=weakness)))


PROBES = (ProbeBEAST,)


class ProbeBEAST(Probe):
    pass
