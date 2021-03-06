from tlsspy.probe.base import Probe
from tlsspy.tls.connection import Connection


class ProbeCRIME(Probe):
    def probe(self, address, certificates):
        '''
        Tests for the CRIME (Compression Ration Info-leak Made Easy) TLS attack
        which targets protocols that also enable data compression. CRIME allows
        for session hijacking on an authenticated web session.

        Provides the following keys:

        * ``weakness.crime``
        '''
        weakness = {}
        weakness['status'] = 'good'
        weakness['exists'] = False
        weakness['reason'] = 'Compression disabled'
        try:
            if self.collected['analysis']['features']['compression']:
                # Compression enabled
                weak_ciphers = []
                for cipher in self.collected['ciphers']:
                    if not '_CBC_' in cipher:
                        weak_ciphers.append(cipher)

                if not weak_ciphers:
                    weakness['status'] = 'good'
                    weakness['exists'] = False
                    weakness['reason'] = 'Server-side mitigation'
                else:
                    weakness['status'] = 'error'
                    weakness['exists'] = True
                    weakness['reason'] = 'Compression enabled with weak ciphers'

        except KeyError:
            pass

        self.merge(dict(weakness=dict(crime=weakness)))


PROBES = (ProbeCRIME,)
