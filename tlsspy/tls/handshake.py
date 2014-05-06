from .buffer import Buffer, Reader
from .parameters import (
    CertificateType,
    CipherSuite,
    ContentType,
    ExtensionType,
    HandshakeType,
    HeartbeatMode,
    NameType,
    TLS_CIPHER_SUITE,
    TLS_CIPHER_SUITE_INFO,
    TLS_CIPHER_SUITE_HEAD,
    TLS_EC_CURVE_NAME,
    TLS_EC_CURVE_TYPE,
    TLS_EXTENSION_TYPE,
)
from ..pki import (
    parse_certificate,
    parse_ocsp_response,
)
from ..log import log


class Handshake(object):
    def __init__(self, handshake_type):
        self.content_type = ContentType.handshake
        self.handshake_type = handshake_type

    def render_header(self, message):
        header = Buffer()
        header.add(self.handshake_type, 1)
        header.add(len(message), 3)
        return header.data + message.data


class Certificate(Handshake):
    def __init__(self, certificate_type):
        super(Certificate, self).__init__(HandshakeType.certificate)
        self.certificate_type = certificate_type
        self.certificate_chain = None

    def parse(self, r):
        r.size_check_start(3)
        if self.certificate_type == CertificateType.x509:
            chain_size = r.get(3)
            pos = 0
            certificates = []
            while pos != chain_size:
                cert = r.get_variable(3)
                x509 = parse_certificate(str(cert))
                certificates.append(x509)
                pos += len(cert) + 3
            if certificates:
                self.certificate_chain = certificates

        else:
            raise AssertionError('Unsupported certificate_type "{}"'.format(
                self.certificate_type,
            ))

        r.size_check_stop()
        return self

    def render(self):
        b = Buffer()
        if self.certificate_type == CertificateType.x509:
            chain_size = 0
            if self.certificate_chain:
                certificates = self.certificate_chain
            else:
                certificates = []

            certificate_data = []
            for certificate in certificates:
                data = certificate.to_der()
                chain_size += len(data) + 3
                certificate_data.append(data)
            b.add(chain_size, 3)
            for certificate in certificate_data:
                b.add_variable(data, 1, 3)
        else:
            raise AssertionError()

        return self.render_header(b)


class CertificateRequest(Handshake):
    def __init__(self):
        super(CertificateRequest, self).__init__(
            HandshakeType.certificate_request
        )
        self.certificate_types = [ClientCertificateType.rsa_sign]
        self.certificate_authorities = []

    def parse(self, r):
        r.size_check_start(3)
        self.certificate_types = r.get_variable_list(1, 1)
        ca_list_length = r.get(2)
        pos = 0
        self.certificate_authorities = []
        while pos != ca_list_length:
            ca_data = r.get_variable(2)
            self.certificate_authorities.append(ca_data)
            pos += len(ca_data) + 2
        r.size_check_stop()
        return self

    def render(self):
        b = Buffer()
        b.add_variable(self.certificate_types, 1, 1)
        ca_size = 0
        for ca_dn in self.certificate_authorities:
            ca_size += len(ca_dn) + 2
        b.add(ca_size)
        for ca_dn in self.certificate_authorities:
            w.add_variable(ca_dn, 1, 2)
        return seld.render_header(b)


class CertificateStatus(Handshake):
    def __init__(self):
        super(CertificateStatus, self).__init__(
            HandshakeType.certificate_status
        )
        self.ocsp_response = None

    def parse(self, r):
        from hexdump import hexdump
        hexdump(str(r.data))
        try:
            self.ocsp_response = parse_ocsp_response(str(r.data))
        except Exception as error:
            log.error('Error parsing OCSP response: {}'.format(error))


class ClientHello(Handshake):
    def __init__(self, v2=False):
        super(ClientHello, self).__init__(HandshakeType.client_hello)
        self.v2 = v2
        self.client_version = (0, 0)
        self.random = bytearray(32)
        self.session_id = bytearray(0)
        self.cipher_suites = []
        self.compression_methods = [0]
        self.certificate_types = [CertificateType.x509] # 0x0009 cert_type
        self.server_name = bytearray(0)     # 0x0000 server_name
        self.status_request = None          # 0x0005 status_request
        self.elliptic_curves = []           # 0x000a elliptic_curves
        self.ec_point_formats = []          # 0x000b ec_point_formats
        self.heartbeat = False              # 0x000f heartbeat
        self.supports_npn = False           # 0x3374 supports_npn
        self.tack = False                   # 0xf300 tack

    def parse(self, r):
        if self.v2:
            self.client_version = (r.get(1), r.get(1))
            cipher_specs_size = r.get(2)
            session_id_size = r.get(2)
            random_size = r.get(2)
            self.cipher_suites = r.get_fixed_list(3, cipher_specs_size // 3)
            self.session_id = r.get_fixed(session_id_size)
            self.random = r.get_fixed(random_size)
            if self.random < 32:
                zeros = 32 - len(self.random)
                self.random = bytearray(zeros) + self.random
            self.compression_methods = [0]

        else:
            r.size_check_start(3)
            self.client_version = (r.get(1), r.get(1))
            self.random = r.get_fixed(32)
            self.session_id = r.get_variable(1)
            self.cipher_suites = r.get_variable_list(2, 2)
            self.compression_methods = r.get_variable_list(1, 1)

            # Parse extensions, if any
            if not r.at_size_check:
                total_size = r.get(2)
                total = 0
                start = r.pos

                while total != total_size:
                    ext_type = p.get(2)
                    ext_size = p.get(1)

                    # 0x0000 server_name
                    if ext_type == ExtensionType.server_name:
                        server_name_data = r.get_fixed(ext_size)
                        r2 = Reader(server_name_data)
                        r2.size_check_start(2)
                        while True:
                            if r2.at_size_check:
                                break  # No luck
                            else:
                                name_type = r2.get(1)
                                host_name = r2.get_variable(2)
                                if name_type == NameType.host_name:
                                    self.server_name = host_name
                                    break

                    # 0x0009 cert_type
                    elif ext_type == ExtensionType.cert_type:
                        self.certificate_types = p.get_variable_list(1, 1)

                    # 0x000f heartbeat
                    elif ext_type == ExtensionType.heartbeat:
                        self.heartbeat = True

                    # 0x3374 supports_npn
                    elif ext_type == ExtensionType.supports_npn:
                        self.supports_npn = True

                    # 0xf300 tack
                    elif ext_type == ExtensionType.tack:
                        self.tack = True

                    else:
                        # Just consume the bytes in the buffer
                        r.get_fixed(ext_size)

                if r.pos - start != ext_size:
                    raise SyntaxError('Odd-size fragment for extension data')

                total += 4 + ext_size

            r.size_check_stop()

        return self

    def render(self):
        b = Buffer()
        b.add(self.client_version[0], 1)
        b.add(self.client_version[1], 1)
        b.add_fixed(self.random, 1)
        b.add_variable(self.session_id, 1, 1)
        b.add_variable(self.cipher_suites, 2, 2)
        b.add_variable(self.compression_methods, 1, 1)

        e = Buffer()  # Extensions

        # 0x0000 server_name
        if self.server_name:
            e.add(ExtensionType.server_name, 2)
            e.add(len(self.server_name) + 5, 2)
            e.add(len(self.server_name) + 3, 2)
            e.add(NameType.host_name, 1)
            e.add_variable(self.server_name, 1, 2)

        # 0x0005 status_request
        if self.status_request:
            e.add(ExtensionType.status_request, 2)
            e.add(5, 2) # Length
            e.add(self.status_request, 1)
            e.add(0, 2) # Request extensions
            e.add(0, 2) # Responder ID

        # 0x0009 cert_types
        if self.certificate_types and self.certificate_types != [CertificateType.x509]:
            e.add(ExtensionType.cert_type, 2)
            e.add(len(self.certificate_types) + 1, 2)
            e.add_variable(self.certificate_types, 1, 1)

        # 0x000a elliptic_curves
        if self.elliptic_curves:
            e.add(ExtensionType.elliptic_curves, 2)
            e.add((len(self.elliptic_curves) + 1) * 2, 2)
            e.add_variable(self.elliptic_curves, 2, 2)

        # 0x000b ec_point_formats
        if self.ec_point_formats:
            e.add(ExtensionType.ec_point_formats, 2)
            e.add(len(self.ec_point_formats) + 1, 2)
            e.add_variable(self.ec_point_formats, 1, 1)

        # 0x000f heartbeat
        if self.heartbeat:
            e.add(ExtensionType.heartbeat, 2)
            e.add(1, 2) # Length
            e.add(HeartbeatMode.peer_allowed_to_send, 1)

        # 0x3374 supports_npn
        if self.supports_npn:
            e.add(ExtensionType.supports_npn, 2)
            e.add(0, 2)

        # 0xf300 tack
        if self.tack:
            e.add(ExtensionType.tack, 2)
            e.add(0, 2)

        if len(e):
            b.add(len(e), 2)
            b.data += e.data

        return self.render_header(b)


class ServerHello(Handshake):
    def __init__(self, v2=False):
        super(ServerHello, self).__init__(HandshakeType.server_hello)
        self.v2 = v2
        self.server_version = (0, 0)
        self.random = bytearray(32)
        self.session_id = bytearray(0)
        self.cipher_suite = 0
        self.certificate_type = CertificateType.x509
        self.compression_method = 0
        self.extensions = set([])
        self.secure_renegotiation = False
        self.ec_point_formats = []              # 0x000b ec_point_formats
        self.heartbeat = False                  # 0x000f heartbeat
        self.session_ticket = False             # 0x0023 session_ticket
        self.next_protos_listed = None          # 0x3374 supports_npn
        self.next_protos = None

    def parse(self, r):
        r.size_check_start(3)
        self.server_version = (r.get(1), r.get(1))
        self.random = r.get_fixed(32)
        self.session_id = r.get_variable(1)
        self.cipher_suite = r.get(2)
        self.compression_method = r.get(1)

        # Parse extensions, if any
        if not r.at_size_check:
            total_size = r.get(2)
            total = 0

            while total != total_size:
                ext_type = r.get(2)
                ext_size = r.get(2)
                log.debug('Parsing extension {} with size {}'.format(
                    TLS_EXTENSION_TYPE.get(ext_type, ext_type),
                    ext_size,
                ))

                self.extensions.add(TLS_EXTENSION_TYPE.get(ext_type, ext_type))

                if ext_type == ExtensionType.cert_type:
                    if ext_size != 1:
                        raise SyntaxError()
                    else:
                        self.certificate_type = r.get(1)

                # 0x0000 server_name
                elif ext_type == ExtensionType.server_name:
                    if ext_size:
                        server_name = r.get_fixed(ext_size)
                        r2 = Reader(server_name)
                        r2.size_check_start(2)
                        while True:
                            if r2.at_size_check:
                                break  # Tough luck
                            else:
                                name_type = r2.get(1)
                                host_name = r2.get_variable(2)
                                if name_type == NameType.host_name:
                                    self.server_name = host_name
                                    break

                # 0x000b ec_point_formats
                elif ext_type == ExtensionType.ec_point_formats:
                    if ext_size:
                        ecp_size = r.get(2)
                        self.ec_point_formats = r.get_variable_list(1, 1)

                # 0x000f heartbeat
                elif ext_type == ExtensionType.heartbeat:
                    r.get_fixed(ext_size)
                    self.heartbeat = True

                elif ext_type == ExtensionType.reneg_info:
                    r.get_fixed(ext_size)
                    self.secure_renegotiation = True

                elif ext_type == ExtensionType.session_ticket:
                    r.get_fixed(ext_size)
                    self.session_ticket = True

                elif ext_type == ExtensionType.status_request:
                    print repr(r.get_fixed(ext_size))

                elif ext_type == ExtensionType.supports_npn:
                    self.next_protos = self._parse_npn(r.get_fixed(ext_size))

                else:
                    log.debug('Extension type {} ({}) not supported'.format(
                        TLS_EXTENSION_TYPE.get(ext_type, ext_type),
                        ext_type,
                    ))
                    # Consume data
                    r.get_fixed(ext_size)

                total += 4 + ext_size

        r.size_check_stop()
        return self

    def render(self):
        b = Buffer()
        b.add(self.server_version[0], 1)
        b.add(self.server_version[1], 1)
        b.add_fixed(self.random, 1)
        b.add_variable(self.session_id, 1, 1)
        b.add(self.cipher_suite, 2)
        b.add(self.compression_method, 1)

        e = Buffer()  # Extensions
        if self.certificate_type and self.certificate_type != CertificateType.x509:
            e.add(ExtensionType.cert_type, 2)
            e.add(1, 2)
            e.add(self.certificate_type, 1)
        if self.next_protos_advertized is not None:
            protos = self._render_npn()
            e.add(ExtensionType.supports_npn, 2)
            e.add(len(protos), 2)
            e.add_fixed(protos, 1)

        if len(e):
            b.add(len(e), 2)
            b.data += e.data

        return self.render_done(b)

    def _parse_npn(self, b):
        protos = []
        while True:
            if len(b) == 0:
                break
            else:
                s = b[0]
                b = b[1:]
                if len(b) < 1:
                    break
                protos.append(b[:s])
                b = b[s:]
        return protos

    def _render_npn(self):
        b = bytearray(0)
        for proto in self.next_protos_advertized:
            if len(proto) > 255 or len(proto) == 0:
                raise SyntaxError('Invalid protocol size {}; allowed is 0 < x'
                                  ' < 256'.format(len(proto)))
            b += bytearray([len(proto)]) + bytearray(proto)
        return b


class ServerHelloDone(Handshake):
    def __init__(self):
        super(ServerHelloDone, self).__init__(HandshakeType.server_hello_done)

    def parse(self, r):
        r.size_check_start(3)
        r.size_check_stop()
        return self

    def render(self):
        b = Buffer()
        return self.render_header(b)


class ServerKeyExchange(Handshake):
    def __init__(self, cipher_suite):
        super(ServerKeyExchange, self).__init__(
            HandshakeType.server_key_exchange
        )
        self.cipher_suite = cipher_suite

        # DH params
        self.dh_p = 0
        self.dh_g = 0
        self.dh_Ys = 0

        # ECDH params
        self.ec_curve_type = None
        self.ec_curve_a = None
        self.ec_curve_b = None

        # Signature
        self.signature = bytearray(0)

    def parse(self, r):
        if self.cipher_suite is None:
            log.warning('No cipher suite, cannot parse key exchange message')
            return self

        cipher_name = TLS_CIPHER_SUITE.get(self.cipher_suite, self.cipher_suite)
        cipher_info = TLS_CIPHER_SUITE_INFO.get(self.cipher_suite, None)
        if cipher_info is None:
            log.warning('Unknown cipher suite 0x{:04x}'.format(
                self.cipher_suite,
            ))
            return self
        else:
            log.debug('Parse key exchange message for cipher suite {}'.format(
                cipher_name,
            ))

        cipher_info = dict(zip(TLS_CIPHER_SUITE_HEAD, cipher_info))

        # Fixed ECDH
        if cipher_info['key_exchange'] == 'ECDH':
            pass

        # Ephemeral ECDH
        elif cipher_info['key_exchange'] == 'ECDHE':
            r.size_check_start(3)
            self.ec_curve_type = r.get(1)
            curve_type = TLS_EC_CURVE_TYPE.get(self.ec_curve_type)
            if curve_type is None:
                log.debug('Unsupported EC curve type {}'.format(
                    self.ec_curve_type
                ))
                return self

            elif curve_type == 'explicit_prime':
                self.ec_curve_a = r.get(1)
                self.ec_curve_b = r.get(1)
                self.ec_point = r.get(1)
                log.info('Elliptic Curve {} (a={}, b={}, point={})'.format(
                    curve_type,
                    self.ec_curve_a,
                    self.ec_curve_b,
                    self.ec_point,
                ))

            elif curve_type == 'named_curve':
                self.ec_curve_name = r.get(2)
                log.info('Elliptic Curve {}'.format(
                    TLS_EC_CURVE_NAME.get(
                        self.ec_curve_name,
                        self.ec_curve_name,
                    )
                ))

        else:
            log.debug('Unsupported key exchange algorithm {}'.format(
                cipher_info['key_exchange']
            ))

        return self
