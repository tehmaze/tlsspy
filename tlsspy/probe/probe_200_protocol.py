from collections import OrderedDict
import ssl
import socket

from tlsspy.probe.base import Probe
from tlsspy.log import log
from tlsspy.remote import Remote
from tlsspy.tls.buffer import Reader
from tlsspy.tls.packet import RecordHeader3
from tlsspy.tls.handshake import (
    ClientHello,
    ServerHello,
)
from tlsspy.tls.parameters import (
    contribute_to_class,
    ContentType,
    HandshakeType,
    TLS_CIPHER_SUITE,
    TLS_CONTENT_TYPE,
)
from tlsspy.util import get_random_bytes


STATUS_OK, STATUS_ERROR = range(2)


TLS_VERSION = {
    (0x03, 0x04): 'TLSv1.3_draft',
    (0x03, 0x03): 'TLSv1.2',
    (0x03, 0x02): 'TLSv1.1',
    (0x03, 0x01): 'TLSv1.0',
    (0x03, 0x00): 'SSLv3',
    (0x02, 0x00): 'SSLv2',
}
# "Fake" versions and their max tolerated response
TLS_VERSION_TOLERANCE = {
    (0x03, 0x62): (0x03, 0x04),
    (0x04, 0x00): (0x03, 0x04),
    (0x04, 0x62): (0x03, 0x04),
}

@contribute_to_class(TLS_VERSION)
class TLSVersion(object):
    pass


PROTOCOLS = OrderedDict()
PROTOCOLS[TLSVersion.TLSv1_2] = (
    dict(status='good', reason='No known security issues'),
    dict(status='warning'),
)
PROTOCOLS[TLSVersion.TLSv1_1] = (
    dict(status='ok', reason='No known security issues'),
    dict(status='warning'),
)
PROTOCOLS[TLSVersion.TLSv1_0] = (
    dict(status='ok', reason='Largely still secure'),
    dict(status='warning'),
)
PROTOCOLS[TLSVersion.SSLv3] = (
    dict(
        status='warning',
        reason='Obsolete, most clients supporting SSLv3 also support '
               'TLSv1.0, consider disabling SSLv3'
    ),
    dict(status='good', reason='SSLv3 is obsolete'),
)
PROTOCOLS[TLSVersion.SSLv2] = (
    dict(status='error', reason='Insecure protocol'),
    dict(status='ok'),
)


class ProtocolSupport(Probe):
    timeout = 15

    def probe(self, address, certificates):
        if address is None:
            raise Probe.Skip('offline; no address supplied')

        protocols = []
        for version, statuses in PROTOCOLS.iteritems():
            name = TLS_VERSION[version]
            try:
                self._test_version(address, version)
                status = statuses[STATUS_OK]
                status['available'] = True
                protocols.append({name: status})
            except Exception as error:
                status = statuses[STATUS_ERROR]
                status['available'] = False
                status['reason'] = status.get(
                    'reason',
                    'Not available: {}'.format(error)
                )
                protocols.append({name: status})

        protocol_intolerance = []
        for version, max_server_version in TLS_VERSION_TOLERANCE.iteritems():
            name = '{} {}.{}'.format(
                'TLS' if version[0] > 2 else 'SSL',
                version[0] - 2,
                version[1],
            )
            try:
                server_version = self._test_version(address, version)
                server_name = '{} {}.{}'.format(
                    'TLS' if server_version[0] > 2 else 'SSL',
                    server_version[0] - 2,
                    server_version[1],
                )
                if server_version > max_server_version:
                    log.debug('Intolerant for version {} (got {} back!?)'.format(
                        name,
                        server_name,
                    ))
                    protocol_intolerance.append(name)
                else:
                    log.debug('Proper response for version {} (got {})'.format(
                        name,
                        server_name,
                    ))
            except Exception as error:
                log.debug('Intolerant for version {} (got error: {})'.format(
                    name,
                    error,
                ))
                protocol_intolerance.append(name)

        protocols.sort()
        protocols.reverse()
        protocol_intolerance.sort()
        self.merge(dict(
            analysis=dict(
                protocols=protocols,
                protocol_intolerance=protocol_intolerance,
            )
        ))

    def _test_version(self, address, version):
        '''
        Returns the version supported by the server for client version
        ``version``.
        '''
        log.debug('Testing TLS/SSL version 0x{:02x}{:02x}'.format(*version))
        chello = ClientHello()
        chello.client_version = version
        chello.random = get_random_bytes(32)
        chello.cipher_suites = TLS_CIPHER_SUITE.keys()  # Be very permissive
        packet = chello.render()

        remote = Remote(address)
        remote.connect()

        try:
            header = RecordHeader3()
            header.content_type = chello.content_type
            header.version = version
            header.size = len(packet)

            # Send request
            r = header.render() + packet
            remote.send_all(r)

            # Read response
            try:
                r = Reader(bytearray(remote.recv(1024)))
                content_type = r.get(1)
            except SyntaxError:
                raise ValueError('Expected record header')

            if content_type != ContentType.handshake:
                raise SyntaxError('Expected handshake, got {} (0x{:02x})'.format(
                    TLS_CONTENT_TYPE.get(content_type, content_type),
                    content_type,
                ))

            header_version = (r.get(1), r.get(1))
            # SSLv3/TLSv1.x
            if header_version >= (0x03, 0x00):
                header_size = r.get(2)
                b = r.get_fixed(header_size)
                if b[0] != HandshakeType.server_hello:
                    raise SyntaxError('Expected server hello, got {} (0x{:02x})'.format(
                        TLS_HANDSHAKE_TYPE.get(b[0], b[0]),
                        b[0]
                    ))
                server_hello = ServerHello().parse(Reader(b[1:]))
                return server_hello.server_version

            # SSLv2
            else:
                return header_version

        finally:
            remote.close()



PROBES = (
    ProtocolSupport,
)
