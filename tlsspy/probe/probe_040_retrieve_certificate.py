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
        if not address:
            # Nothing to do
            raise Probe.Skip('Offline; no address supplied')
        else:
            log.info('Fetching certificate from %s:%d' % address)

        try:
            remote = Remote(address)
            remote.connect()
            secure = Connection(remote)
            cipher = CipherSuite.filter(
                key_exchange=('RSA', 'DH'),
            )
            log.debug('Selected {} out of {} ciphers'.format(
                len(cipher),
                len(TLS_CIPHER_SUITE),
            ))
            for result in secure.handshake(
                    server_name=address[0],
                    cipher_suites=cipher
                ):
                pass

            for certificate in secure.get_certificate_chain():
                certificates.add(certificate)

        except socket.error, e:
            raise Probe.Skip('network error: {}'.format(e))

        log.info('Fetched {} certifiates from {}:{}'.format(
            len(certificates),
            address[0],
            address[1],
        ))


PROBES = (
    RetrieveCertificate,
)
