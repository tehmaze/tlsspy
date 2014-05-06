import ssl
import struct
import socket

from tlsspy.probe.base import Probe
from tlsspy.config import CONFIG
from tlsspy.util import ThreadPool
from tlsspy.log import log
from tlsspy.remote import Remote
from tlsspy.tls.parameters import (
    dict_key,
    TLS_CIPHER_SUITE,
    TLS_CIPHER_SUITE_HEAD,
    TLS_CIPHER_SUITE_INFO,
    TLS_VERSION,
    AlertDescription,
    CipherSuite,
    ContentType,
    HandshakeType,
    Version,
)


def get_cipher_info(cipher):
    name = TLS_CIPHER_SUITE[cipher]
    info = dict(zip(TLS_CIPHER_SUITE_HEAD,
                    TLS_CIPHER_SUITE_INFO[cipher]))
    info['hex'] = '0x{:04x}'.format(cipher)

    if info['key_exchange'] == 'ECDHE':
        info['forward_secrecy'] = u'ECDH 256 bits (&asymp; RSA 3072 bits)'
    elif info['key_exchange'] == 'DHE':
        info['forward_secrecy'] = 'DH 1024 bits'
    else:
        info['forward_secrecy'] = None

    return (name, info)


# TODO
# We now use TLS for all protocols by default, but for SSL protocols we should
# also ensure the connection is downgraded to SSLv2
class CipherSupport(Probe):
    timeout = 15

    def setup(self):
        self.config = CONFIG.get('analyze', {}).get('cipher', {})

    def probe(self, address, certificates):
        if address is None:
            raise Probe.Skip('offline; no address supplied')

        # Features
        features = {}
        features['forward_secrecy'] = False  # Detect later
        features['preferred_order'] = False  # Detect later

        # Enlist all ciphers, start with NULL cipher first
        all_cipher_suites = TLS_CIPHER_SUITE.keys()
        all_cipher_suites.sort()

        # Remove our pseudo-cipher, it's added later in the check
        all_cipher_suites.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV)

        # Test what cipher the server selects
        cipher_suite1 = self._test_cipher(address, *all_cipher_suites)
        if cipher_suite1 is None:
            log.error('No cipher suite selected by server?!')
            return

        # Now test what cipher the server selects next
        all_cipher_suites.remove(cipher_suite1)
        cipher_suite2 = self._test_cipher(address, *all_cipher_suites)
        if cipher_suite2 is None:
            log.error('No cipher suite selected by server?!')
            return

        # Now that we have two ciphers, offer them in reverse order. If the
        # server selects cipher1 again, the server has a preferred order.
        all_cipher_suites = [
            cipher_suite2,
            cipher_suite1,
        ]
        if self._test_cipher(address, *all_cipher_suites) == cipher_suite1:
            order = True
        else:
            order = False

        # Store feature
        features['preferred_order'] = order

        # Start bulk-testing ciphers
        all_cipher_suites = TLS_CIPHER_SUITE.keys()
        all_cipher_suites.sort()
        all_cipher_suites.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
        all_cipher_suites.remove(cipher_suite1)
        all_cipher_suites.remove(cipher_suite2)
        our_cipher_suites = [
            cipher_suite1,
            cipher_suite2,
        ]

        if order:
            log.info('Serial scanning {} suites in server order'.format(
                len(all_cipher_suites),
            ))
            while all_cipher_suites:
                try:
                    cipher_suite = self._test_cipher(address, *all_cipher_suites)
                except Exception as error:
                    log.debug('None of our suites are accepted, stopping')
                    cipher_suite = None

                if cipher_suite is None:
                    break
                else:
                    our_cipher_suites.append(cipher_suite)
                    all_cipher_suites.remove(cipher_suite)

        else:
            # If there is no server-preferred order, we can use parallel
            # (threaded) probing
            parallel = self.config.get('parallel', 0)
            if parallel:
                log.info('Parallel scanning {} suites'.format(
                    len(all_cipher_suites),
                ))
                pool = ThreadPool()

                for cipher_suite in reversed(all_cipher_suites):
                    pool.add_job(self._test_cipher, (address, cipher_suite))

                pool.start(parallel)
                for cipher_suite in pool.get_results():
                    if cipher_suite is not None:
                        our_cipher_suites.append(cipher_suite)

                pool.join()

            else:
                log.info('Serial scanning {} suites'.format(
                    len(all_cipher_suites),
                ))
                for cipher_suite in reversed(all_cipher_suites):
                    if self._test_cipher(address, cipher_suite):
                        our_cipher_suites.append(cipher_suite)

        # Post-processing
        log.debug('Discovered {} usable cipher suites'.format(
            len(our_cipher_suites),
        ))
        cipher_names = []
        support = []
        for cipher in our_cipher_suites:
            name, info = get_cipher_info(cipher)
            cipher_names.append(name)

            if info['encryption'] is None:
                info.update(dict(
                    status='error',
                    reason='Cipher offers no encryption'
                ))

            elif info['authentication'] is None:
                info.update(dict(
                    status='error',
                    reason='Cipher offers no authentication'
                ))

            elif info['encryption'] in ('DES', 'DES40', 'IDEA'):
                info.update(dict(
                    status='error',
                    reason='Weak encryption',
                ))

            elif info['encryption_bits'] < 112:
                info.update(dict(
                    status='error',
                    reason='Cipher offers weak encryption, only {} bits'.format(
                        info['encryption_bits'],
                    )
                ))

            elif info['encryption_bits'] < 128:
                info.update(dict(
                    status='warning',
                    reason='Cipher offers weak encryption, only {} bits'.format(
                        info['encryption_bits'],
                    )
                ))

            elif info['protocol'] == 'SSL':
                info.update(dict(
                    status='error',
                    reason='Cipher uses weak SSL implementation',
                ))

            else:
                if info['key_exchange'] in ('DHE', 'ECDHE'):
                    features['forward_secrecy'] = True
                info['status'] = 'good'

            support.append({name: info})

        self.merge(dict(
            analysis=dict(
                ciphers=support,
                features=features,
            ),
            ciphers=cipher_names,
        ))

    def _test_cipher(self, address, *cipher_suites):
        try:
            secure = self._connect(address)
            # Construct accepted ciphers, also include a pseudo cipher
            cipher_suites = list(cipher_suites)
            if not CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV in cipher_suites:
                cipher_suites.append(
                    CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV
                )
            # Consume generator
            for result in secure.handshake(
                    cipher_suites=cipher_suites,
                    server_name=address[0],
                ):
                pass
        except Exception as error:
            log.debug('Cipher failed: {}'.format(error))
            return None
        else:
            log.debug('Cipher accepted: {} chosen by server'.format(
                TLS_CIPHER_SUITE[secure.server_hello.cipher_suite],
            ))
            secure.close()
            return secure.server_hello.cipher_suite


PROBES = (
    CipherSupport,
)
