import json
import os
import sys
import traceback

from pyasn1.type import univ
from pyasn1.codec.der import decoder as der_decoder

from tlsspy.config import CONFIG
from tlsspy.log import log
from tlsspy.pki import parse_pem, parse_certificate
from tlsspy.probe.loader import load_probes
from tlsspy.trust import TRUST_STORE
from tlsspy.util import OrderedSet


class Analyzer(object):
    def __init__(self, options):
        self.config = CONFIG
        self.probes = load_probes()
        self.load_trust()

        if options.CAdir and os.path.isdir(options.CAdir):
            TRUST_STORE.add_trust_from_ca_dir(options.CAdir)
        if options.CAfile and os.path.isfile(options.CAfile):
            TRUST_STORE.add_trust_from_ca_file(options.CAfile)

    def analyze(self, address, certificates):
        if not isinstance(certificates, OrderedSet):
            certificates = OrderedSet(certificates)

        info = {'tests': [], 'tests_skipped': []}
        for Probe in self.probes:
            log.debug('Running {0}'.format(Probe.__module__))
            try:
                probe = Probe(info)
                probe.probe(address, certificates)
                info['tests'].append(Probe.__module__)
            except Probe.Skip, r:
                log.warning('Skip {0}: {1}'.format(Probe.__module__, r))
                info['tests_skipped'].append(Probe.__module__)
            except Exception as error:
                log.error('Uncaught exception: {0}'.format(error))
                for line in traceback.format_exc().splitlines():
                    log.error(line)

        return info

    def analyze_certificate(self, data, **kwargs):
        certificates = map(parse_certificate,
                           parse_pem(data.splitlines(), 'CERTIFICATE'))

        return self.analyze(None, certificates)

    def analyze_tcp(self, address):
        return self.analyze(address, [])

    def _json_handler(self, obj):
        if hasattr(obj, 'isoformat'):
            # for datetime.* objects
            return obj.isoformat()
        elif hasattr(obj, 'seconds') and hasattr(obj, 'microseconds'):
            # for datetime.timedelta objects
            return obj.seconds + (obj.microseconds / 1000000.0)
        elif isinstance(obj, univ.ObjectIdentifier):
            return str(obj)
        else:
            raise TypeError(
                'Object of type {0} with value {1} is not supported'.format(
                    type(obj), repr(obj)
                )
            )

    def load_trust(self):
        try:
            ca_dir = self.config['trust']['ca_dir']
        except KeyError:
            pass
        else:
            TRUST_STORE.add_trust_from_ca_dir(ca_dir)

        try:
            ca_file = self.config['trust']['ca_file']
        except KeyError:
            pass
        else:
            TRUST_STORE.add_trust_from_ca_file(ca_file)

        try:
            certdata = self.config['trust']['certdata']
        except KeyError:
            pass
        else:
            TRUST_STORE.add_trust_from_certdata(certdata)
