import socket
import ssl

from tlsspy.probe.base import Probe
from tlsspy.log import log
from tlsspy.pki import parse_certificate, parse_pem
from tlsspy.remote import Remote
from tlsspy.tls.connection import Connection
from tlsspy.tls.parameters import TLS_CIPHER_SUITE, CipherSuite


class RetrieveCertificate(Probe):
    timeout = 15

    def probe(self, address, certificates):
        '''
        Retrieves the X.509 certificate from the remote host, being as
        permissive as we can in terms of TLS protocol support, selected cipher
        suites and other protocol violations that may occur. Fetched
        certificates will be added to the ``certificates`` set.

        Provides the following keys:

        * ``analysis.features``

        Probes that depend on this probe:

        * 105_analyze_certificate_
        * 110_analyze_public_key_

        .. _105_analyze_certificate: probe_105_analyze_certificate.html
        .. _110_analyze_public_key:  probe_110_analyze_public_key.html
        '''

        if not address:
            # Nothing to do
            raise Probe.Skip('Offline; no address supplied')
        else:
            log.info('Fetching certificate from %s:%d' % address)

        features = {}
        features['long_client_handshake'] = True

        try:
            secure = self._connect(address)
            cipher = CipherSuite.all
            try:
                self._handshake(secure, CipherSuite.all)
            except Exception as error:
                log.debug('Long client handshake not supported: {0}'.format(
                    error
                ))
                features['long_client_handshake'] = False
                self._handshake(secure, CipherSuite.basic)

            for certificate in secure.get_certificate_chain():
                certificates.add(certificate)

        except socket.error, e:
            raise Probe.Skip('network error: {0}'.format(e))

        log.info('Fetched {0} certifiates from {1}:{2}'.format(
            len(certificates),
            address[0],
            address[1],
        ))

    def _handshake(self, secure, cipher_suites):
        log.debug('Selected {0} out of {1} ciphers'.format(
            len(cipher_suites),
            len(CipherSuite.all),
        ))

        for result in secure.handshake(
                cipher_suites=cipher_suites,
            ):
            pass


PROBES = (
    RetrieveCertificate,
)
