from tlsspy.probe.base import Probe
from tlsspy.tls.connection import Connection


class ProbeBEAST(Probe):
    def probe(self, address, certificates):
        '''
        Tests for the BEAST (Browser Exploit Against SSL/TLS) attack, which
        exploits a known Cipher Block Chaining (CBC) vulnerability in TLSv1.0.

        Provides the following keys:

        * ``weakness.beast``
        '''
        weakness = {}
        weakness['status'] = 'unknown'
        weakness['exists'] = False
        weakness['reason'] = 'Not implemented'

        self.merge(dict(weakness=dict(beast=weakness)))


PROBES = (ProbeBEAST,)


class ProbeBEAST(Probe):
    pass
