import socket

from tlsspy.probe.base import Probe
from tlsspy.config import CONFIG
from tlsspy.log import log
from tlsspy.tls.curves import (
    TLS_EC_CURVE_NAME_HEAD,
    TLS_EC_CURVE_NAME_INFO,
    TLS_EC_CURVE_NAME_UNSAFE,
)
from tlsspy.tls.parameters import (
    CertificateStatusType,
    CipherSuite,
    ECCurveType,
    TLS_EC_CURVE_NAME,
    TLS_EC_CURVE_TYPE,
    TLS_EC_POINT_FORMAT,
)


class EllipticCurveSupport(Probe):
    def setup(self):
        self.unsafe_curves = CONFIG.get('unsafe_curves', {})

    def probe(self, address, certificates):
        if address is None:
            raise Probe.Skip('offline; no address supplied')

        support = {}
        status = []
        self._check_elliptic_curves(address, support, status)
        self.merge(dict(
            analysis=dict(
                curves=status,
                features=dict(elliptic_curves=support),
            )
        ))

    def _check_elliptic_curves(self, address, support, status):
        log.debug('Testing Elliptic Curves')
        ciphers = [getattr(CipherSuite, suite)
                   for suite in self.collected['ciphers']
                   if '_EC' in suite]

        if ciphers:
            log.debug('Discovered {} usable cipher suites using EC'.format(
                len(ciphers),
            ))
            elliptic_curves = TLS_EC_CURVE_NAME.keys()
            elliptic_curves.sort()
            ec_point_formats = TLS_EC_POINT_FORMAT.keys()
            ec_point_formats.sort()
        else:
            log.debug('Discovered no cipher suites using EC, skipping feature')
            raise Probe.Skip('no cipher suites supporting elliptic curves')

        try:
            secure = self._connect(address)
            for result in secure.handshake(
                    server_name=address[0],
                    cipher_suites=ciphers,
                    elliptic_curves=elliptic_curves,
                    ec_point_formats=ec_point_formats,
                ):
                pass

        except socket.error as error:
            raise Probe.Skip('Elliptic Curve Point Format handshake failed: {}'.format(
                error
            ))

        # Map out the names of the EC point formats supported by the server
        ec_point_formats = secure.server_hello.ec_point_formats
        support['point_format'] = filter(None, map(
            TLS_EC_POINT_FORMAT.get,
            ec_point_formats
        ))

        support['curve_name'] = []
        support['curve_type'] = None
        if secure.server_key_exchange is not None:
            support['curve_type'] = TLS_EC_CURVE_TYPE.get(
                secure.server_key_exchange.ec_curve_type,
                'unsupported',
            )

            if secure.server_key_exchange.ec_curve_type == ECCurveType.named_curve:
                # Find out what named curves the server supports
                self._probe_named_curves(address, ciphers, elliptic_curves,
                                         support, status)

    def _get_named_curve_info(self, curve):
        info = dict(
            status='unknown',
            reason='Unsupported named curve',
        )

        try:
            info.update(dict(
                zip(TLS_EC_CURVE_NAME_HEAD,
                    TLS_EC_CURVE_NAME_INFO[curve])
            ))
            info.update(dict(
                status='good',
                reason='',
            ))
        except KeyError:
            pass

        if curve in TLS_EC_CURVE_NAME_UNSAFE:
            info.update(dict(
                status='error',
                reason=TLS_EC_CURVE_NAME_UNSAFE[curve][0],
                info=TLS_EC_CURVE_NAME_UNSAFE[curve][1],
            ))

        return info

    def _probe_named_curve(self, address, cipher_suites, elliptic_curves):
        secure = self._connect(address)
        ec_point_formats = TLS_EC_POINT_FORMAT.keys()
        for result in secure.handshake(
                server_name=address[0],
                cipher_suites=cipher_suites,
                elliptic_curves=elliptic_curves,
                ec_point_formats=ec_point_formats,
            ):
            pass

        if secure.server_key_exchange.ec_curve_type != ECCurveType.named_curve:
            raise ValueError('Server did not select a named curve')
        else:
            return secure.server_key_exchange.ec_curve_name

    def _probe_named_curves(self, address, cipher_suites, elliptic_curves,
                            support, status):

        while elliptic_curves:
            try:
                curve = self._probe_named_curve(address, cipher_suites, elliptic_curves)
                if curve is None:
                    break
                else:
                    log.debug('Elliptic Named Curve {} supported'.format(
                        TLS_EC_CURVE_NAME.get(curve),
                    ))
                    name = TLS_EC_CURVE_NAME.get(curve)
                    support['curve_name'].append(name)
                    status.append({
                        name: self._get_named_curve_info(curve)
                    })
                    elliptic_curves.remove(curve)
            except Exception as error:
                log.debug('Error Probing Named Curve: {}'.format(
                    error,
                ))
                break


PROBES = (
    EllipticCurveSupport,
)
