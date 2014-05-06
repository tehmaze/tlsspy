def dict_key(k):
    k = str(k).replace('.', '_')
    return k


def contribute_to_class(dct):
    def decorated(cls):
        for k, v in dct.iteritems():
            if not v:
                continue
            else:
                setattr(cls, dict_key(v), k)
        return cls
    return decorated


# http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml


TLS_ALERT_DESCRIPTION = {
    0:   'close_notify',
    10:  'unexpected_message',
    20:  'bad_record_mac',
    21:  'decryption_failed',
    22:  'record_overflow',
    30:  'decompression_failure',
    40:  'handshake_failure',
    41:  'no_certificate_RESERVED',
    42:  'bad_certificate',
    43:  'unsupported_certificate',
    44:  'certificate_revoked',
    45:  'certificate_expired',
    46:  'certificate_unknown',
    47:  'illegal_parameter',
    48:  'unknown_ca',
    49:  'access_denied',
    50:  'decode_error',
    51:  'decrypt_error',
    60:  'export_restriction_RESERVED',
    70:  'protocol_version',
    71:  'insufficient_security',
    80:  'internal_error',
    90:  'user_canceled',
    100: 'no_renegotiation',
    110: 'unsupported_extension',
    111: 'certificate_unobtainable',
    112: 'unrecognized_name',
    113: 'bad_certificate_status_response',
    114: 'bad_certificate_hash_value',
    115: 'unknown_psk_identity',
}


@contribute_to_class(TLS_ALERT_DESCRIPTION)
class AlertDescription(object):
    pass


TLS_ALERT_LEVEL = {
    1: 'warning',
    2: 'fatal',
}


@contribute_to_class(TLS_ALERT_LEVEL)
class AlertLevel(object):
    pass


TLS_AUTHORIZATION_DATA = {
    0:  'x509_attr_cert',
    1:  'saml_assertion',
    2:  'x509_attr_cert_url',
    3:  'saml_assertion_url',
    64: 'keynote_assertion_list',
    65: 'keynote_assertion_list_url',
}


@contribute_to_class(TLS_AUTHORIZATION_DATA)
class AuthorizationData(object):
    pass


TLS_CIPHER_SUITE = {
0x000000: 'TLS_NULL_WITH_NULL_NULL',
0x000001: 'TLS_RSA_WITH_NULL_MD5',
0x000002: 'TLS_RSA_WITH_NULL_SHA',
0x000003: 'TLS_RSA_EXPORT_WITH_RC4_40_MD5',
0x000004: 'TLS_RSA_WITH_RC4_128_MD5',
0x000005: 'TLS_RSA_WITH_RC4_128_SHA',
0x000006: 'TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5',
0x000007: 'TLS_RSA_WITH_IDEA_CBC_SHA',
0x000008: 'TLS_RSA_EXPORT_WITH_DES40_CBC_SHA',
0x000009: 'TLS_RSA_WITH_DES_CBC_SHA',
0x00000a: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
0x00000b: 'TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA',
0x00000c: 'TLS_DH_DSS_WITH_DES_CBC_SHA',
0x00000d: 'TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA',
0x00000e: 'TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA',
0x00000f: 'TLS_DH_RSA_WITH_DES_CBC_SHA',
0x000010: 'TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA',
0x000011: 'TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA',
0x000012: 'TLS_DHE_DSS_WITH_DES_CBC_SHA',
0x000013: 'TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA',
0x000014: 'TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA',
0x000015: 'TLS_DHE_RSA_WITH_DES_CBC_SHA',
0x000016: 'TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA',
0x000017: 'TLS_DH_anon_EXPORT_WITH_RC4_40_MD5',
0x000018: 'TLS_DH_anon_WITH_RC4_128_MD5',
0x000019: 'TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA',
0x00001a: 'TLS_DH_anon_WITH_DES_CBC_SHA',
0x00001b: 'TLS_DH_anon_WITH_3DES_EDE_CBC_SHA',
0x00001e: 'TLS_KRB5_WITH_DES_CBC_SHA',
0x00001f: 'TLS_KRB5_WITH_3DES_EDE_CBC_SHA',
0x000020: 'TLS_KRB5_WITH_RC4_128_SHA',
0x000021: 'TLS_KRB5_WITH_IDEA_CBC_SHA',
0x000022: 'TLS_KRB5_WITH_DES_CBC_MD5',
0x000023: 'TLS_KRB5_WITH_3DES_EDE_CBC_MD5',
0x000024: 'TLS_KRB5_WITH_RC4_128_MD5',
0x000025: 'TLS_KRB5_WITH_IDEA_CBC_MD5',
0x000026: 'TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA',
0x000027: 'TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA',
0x000028: 'TLS_KRB5_EXPORT_WITH_RC4_40_SHA',
0x000029: 'TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5',
0x00002a: 'TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5',
0x00002b: 'TLS_KRB5_EXPORT_WITH_RC4_40_MD5',
0x00002c: 'TLS_PSK_WITH_NULL_SHA',
0x00002d: 'TLS_DHE_PSK_WITH_NULL_SHA',
0x00002e: 'TLS_RSA_PSK_WITH_NULL_SHA',
0x00002f: 'TLS_RSA_WITH_AES_128_CBC_SHA',
0x000030: 'TLS_DH_DSS_WITH_AES_128_CBC_SHA',
0x000031: 'TLS_DH_RSA_WITH_AES_128_CBC_SHA',
0x000032: 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA',
0x000033: 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA',
0x000034: 'TLS_DH_anon_WITH_AES_128_CBC_SHA',
0x000035: 'TLS_RSA_WITH_AES_256_CBC_SHA',
0x000036: 'TLS_DH_DSS_WITH_AES_256_CBC_SHA',
0x000037: 'TLS_DH_RSA_WITH_AES_256_CBC_SHA',
0x000038: 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA',
0x000039: 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA',
0x00003a: 'TLS_DH_anon_WITH_AES_256_CBC_SHA',
0x00003b: 'TLS_RSA_WITH_NULL_SHA256',
0x00003c: 'TLS_RSA_WITH_AES_128_CBC_SHA256',
0x00003d: 'TLS_RSA_WITH_AES_256_CBC_SHA256',
0x00003e: 'TLS_DH_DSS_WITH_AES_128_CBC_SHA256',
0x00003f: 'TLS_DH_RSA_WITH_AES_128_CBC_SHA256',
0x000040: 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA256',
0x000041: 'TLS_RSA_WITH_CAMELLIA_128_CBC_SHA',
0x000042: 'TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA',
0x000043: 'TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA',
0x000044: 'TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA',
0x000045: 'TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA',
0x000046: 'TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA',
0x000067: 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256',
0x000068: 'TLS_DH_DSS_WITH_AES_256_CBC_SHA256',
0x000069: 'TLS_DH_RSA_WITH_AES_256_CBC_SHA256',
0x00006a: 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA256',
0x00006b: 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256',
0x00006c: 'TLS_DH_anon_WITH_AES_128_CBC_SHA256',
0x00006d: 'TLS_DH_anon_WITH_AES_256_CBC_SHA256',
0x000084: 'TLS_RSA_WITH_CAMELLIA_256_CBC_SHA',
0x000085: 'TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA',
0x000086: 'TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA',
0x000087: 'TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA',
0x000088: 'TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA',
0x000089: 'TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA',
0x00008a: 'TLS_PSK_WITH_RC4_128_SHA',
0x00008b: 'TLS_PSK_WITH_3DES_EDE_CBC_SHA',
0x00008c: 'TLS_PSK_WITH_AES_128_CBC_SHA',
0x00008d: 'TLS_PSK_WITH_AES_256_CBC_SHA',
0x00008e: 'TLS_DHE_PSK_WITH_RC4_128_SHA',
0x00008f: 'TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA',
0x000090: 'TLS_DHE_PSK_WITH_AES_128_CBC_SHA',
0x000091: 'TLS_DHE_PSK_WITH_AES_256_CBC_SHA',
0x000092: 'TLS_RSA_PSK_WITH_RC4_128_SHA',
0x000093: 'TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA',
0x000094: 'TLS_RSA_PSK_WITH_AES_128_CBC_SHA',
0x000095: 'TLS_RSA_PSK_WITH_AES_256_CBC_SHA',
0x000096: 'TLS_RSA_WITH_SEED_CBC_SHA',
0x000097: 'TLS_DH_DSS_WITH_SEED_CBC_SHA',
0x000098: 'TLS_DH_RSA_WITH_SEED_CBC_SHA',
0x000099: 'TLS_DHE_DSS_WITH_SEED_CBC_SHA',
0x00009a: 'TLS_DHE_RSA_WITH_SEED_CBC_SHA',
0x00009b: 'TLS_DH_anon_WITH_SEED_CBC_SHA',
0x00009c: 'TLS_RSA_WITH_AES_128_GCM_SHA256',
0x00009d: 'TLS_RSA_WITH_AES_256_GCM_SHA384',
0x00009e: 'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256',
0x00009f: 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',
0x0000a0: 'TLS_DH_RSA_WITH_AES_128_GCM_SHA256',
0x0000a1: 'TLS_DH_RSA_WITH_AES_256_GCM_SHA384',
0x0000a2: 'TLS_DHE_DSS_WITH_AES_128_GCM_SHA256',
0x0000a3: 'TLS_DHE_DSS_WITH_AES_256_GCM_SHA384',
0x0000a4: 'TLS_DH_DSS_WITH_AES_128_GCM_SHA256',
0x0000a5: 'TLS_DH_DSS_WITH_AES_256_GCM_SHA384',
0x0000a6: 'TLS_DH_anon_WITH_AES_128_GCM_SHA256',
0x0000a7: 'TLS_DH_anon_WITH_AES_256_GCM_SHA384',
0x0000a8: 'TLS_PSK_WITH_AES_128_GCM_SHA256',
0x0000a9: 'TLS_PSK_WITH_AES_256_GCM_SHA384',
0x0000aa: 'TLS_DHE_PSK_WITH_AES_128_GCM_SHA256',
0x0000ab: 'TLS_DHE_PSK_WITH_AES_256_GCM_SHA384',
0x0000ac: 'TLS_RSA_PSK_WITH_AES_128_GCM_SHA256',
0x0000ad: 'TLS_RSA_PSK_WITH_AES_256_GCM_SHA384',
0x0000ae: 'TLS_PSK_WITH_AES_128_CBC_SHA256',
0x0000af: 'TLS_PSK_WITH_AES_256_CBC_SHA384',
0x0000b0: 'TLS_PSK_WITH_NULL_SHA256',
0x0000b1: 'TLS_PSK_WITH_NULL_SHA384',
0x0000b2: 'TLS_DHE_PSK_WITH_AES_128_CBC_SHA256',
0x0000b3: 'TLS_DHE_PSK_WITH_AES_256_CBC_SHA384',
0x0000b4: 'TLS_DHE_PSK_WITH_NULL_SHA256',
0x0000b5: 'TLS_DHE_PSK_WITH_NULL_SHA384',
0x0000b6: 'TLS_RSA_PSK_WITH_AES_128_CBC_SHA256',
0x0000b7: 'TLS_RSA_PSK_WITH_AES_256_CBC_SHA384',
0x0000b8: 'TLS_RSA_PSK_WITH_NULL_SHA256',
0x0000b9: 'TLS_RSA_PSK_WITH_NULL_SHA384',
0x0000ba: 'TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256',
0x0000bb: 'TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256',
0x0000bc: 'TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256',
0x0000bd: 'TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256',
0x0000be: 'TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256',
0x0000bf: 'TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256',
0x0000c0: 'TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256',
0x0000c1: 'TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256',
0x0000c2: 'TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256',
0x0000c3: 'TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256',
0x0000c4: 'TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256',
0x0000c5: 'TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256',
0x0000ff: 'TLS_EMPTY_RENEGOTIATION_INFO_SCSV',            # pseudo cipher
0x00c001: 'TLS_ECDH_ECDSA_WITH_NULL_SHA',
0x00c002: 'TLS_ECDH_ECDSA_WITH_RC4_128_SHA',
0x00c003: 'TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA',
0x00c004: 'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA',
0x00c005: 'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA',
0x00c006: 'TLS_ECDHE_ECDSA_WITH_NULL_SHA',
0x00c007: 'TLS_ECDHE_ECDSA_WITH_RC4_128_SHA',
0x00c008: 'TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA',
0x00c009: 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA',
0x00c00a: 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA',
0x00c00b: 'TLS_ECDH_RSA_WITH_NULL_SHA',
0x00c00c: 'TLS_ECDH_RSA_WITH_RC4_128_SHA',
0x00c00d: 'TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA',
0x00c00e: 'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA',
0x00c00f: 'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA',
0x00c010: 'TLS_ECDHE_RSA_WITH_NULL_SHA',
0x00c011: 'TLS_ECDHE_RSA_WITH_RC4_128_SHA',
0x00c012: 'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA',
0x00c013: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
0x00c014: 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
0x00c015: 'TLS_ECDH_anon_WITH_NULL_SHA',
0x00c016: 'TLS_ECDH_anon_WITH_RC4_128_SHA',
0x00c017: 'TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA',
0x00c018: 'TLS_ECDH_anon_WITH_AES_128_CBC_SHA',
0x00c019: 'TLS_ECDH_anon_WITH_AES_256_CBC_SHA',
0x00c01a: 'TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA',
0x00c01b: 'TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA',
0x00c01c: 'TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA',
0x00c01d: 'TLS_SRP_SHA_WITH_AES_128_CBC_SHA',
0x00c01e: 'TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA',
0x00c01f: 'TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA',
0x00c020: 'TLS_SRP_SHA_WITH_AES_256_CBC_SHA',
0x00c021: 'TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA',
0x00c022: 'TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA',
0x00c023: 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',
0x00c024: 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',
0x00c025: 'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256',
0x00c026: 'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384',
0x00c027: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
0x00c028: 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
0x00c029: 'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256',
0x00c02a: 'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384',
0x00c02b: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
0x00c02c: 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
0x00c02d: 'TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256',
0x00c02e: 'TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384',
0x00c02f: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
0x00c030: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
0x00c031: 'TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256',
0x00c032: 'TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384',
0x00c033: 'TLS_ECDHE_PSK_WITH_RC4_128_SHA',
0x00c034: 'TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA',
0x00c035: 'TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA',
0x00c036: 'TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA',
0x00c037: 'TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256',
0x00c038: 'TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384',
0x00c039: 'TLS_ECDHE_PSK_WITH_NULL_SHA',
0x00c03a: 'TLS_ECDHE_PSK_WITH_NULL_SHA256',
0x00c03b: 'TLS_ECDHE_PSK_WITH_NULL_SHA384',
0x00c03c: 'TLS_RSA_WITH_ARIA_128_CBC_SHA256',
0x00c03d: 'TLS_RSA_WITH_ARIA_256_CBC_SHA384',
0x00c03e: 'TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256',
0x00c03f: 'TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384',
0x00c040: 'TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256',
0x00c041: 'TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384',
0x00c042: 'TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256',
0x00c043: 'TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384',
0x00c044: 'TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256',
0x00c045: 'TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384',
0x00c046: 'TLS_DH_anon_WITH_ARIA_128_CBC_SHA256',
0x00c047: 'TLS_DH_anon_WITH_ARIA_256_CBC_SHA384',
0x00c048: 'TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256',
0x00c049: 'TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384',
0x00c04a: 'TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256',
0x00c04b: 'TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384',
0x00c04c: 'TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256',
0x00c04d: 'TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384',
0x00c04e: 'TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256',
0x00c04f: 'TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384',
0x00c050: 'TLS_RSA_WITH_ARIA_128_GCM_SHA256',
0x00c051: 'TLS_RSA_WITH_ARIA_256_GCM_SHA384',
0x00c052: 'TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256',
0x00c053: 'TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384',
0x00c054: 'TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256',
0x00c055: 'TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384',
0x00c056: 'TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256',
0x00c057: 'TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384',
0x00c058: 'TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256',
0x00c059: 'TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384',
0x00c05a: 'TLS_DH_anon_WITH_ARIA_128_GCM_SHA256',
0x00c05b: 'TLS_DH_anon_WITH_ARIA_256_GCM_SHA384',
0x00c05c: 'TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256',
0x00c05d: 'TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384',
0x00c05e: 'TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256',
0x00c05f: 'TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384',
0x00c060: 'TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256',
0x00c061: 'TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384',
0x00c062: 'TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256',
0x00c063: 'TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384',
0x00c064: 'TLS_PSK_WITH_ARIA_128_CBC_SHA256',
0x00c065: 'TLS_PSK_WITH_ARIA_256_CBC_SHA384',
0x00c066: 'TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256',
0x00c067: 'TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384',
0x00c068: 'TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256',
0x00c069: 'TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384',
0x00c06a: 'TLS_PSK_WITH_ARIA_128_GCM_SHA256',
0x00c06b: 'TLS_PSK_WITH_ARIA_256_GCM_SHA384',
0x00c06c: 'TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256',
0x00c06d: 'TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384',
0x00c06e: 'TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256',
0x00c06f: 'TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384',
0x00c070: 'TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256',
0x00c071: 'TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384',
0x00c072: 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256',
0x00c073: 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384',
0x00c074: 'TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256',
0x00c075: 'TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384',
0x00c076: 'TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256',
0x00c077: 'TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384',
0x00c078: 'TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256',
0x00c079: 'TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384',
0x00c07a: 'TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256',
0x00c07b: 'TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384',
0x00c07c: 'TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256',
0x00c07d: 'TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384',
0x00c07e: 'TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256',
0x00c07f: 'TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384',
0x00c080: 'TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256',
0x00c081: 'TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384',
0x00c082: 'TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256',
0x00c083: 'TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384',
0x00c084: 'TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256',
0x00c085: 'TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384',
0x00c086: 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256',
0x00c087: 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384',
0x00c088: 'TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256',
0x00c089: 'TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384',
0x00c08a: 'TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256',
0x00c08b: 'TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384',
0x00c08c: 'TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256',
0x00c08d: 'TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384',
0x00c08e: 'TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256',
0x00c08f: 'TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384',
0x00c090: 'TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256',
0x00c091: 'TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384',
0x00c092: 'TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256',
0x00c093: 'TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384',
0x00c094: 'TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256',
0x00c095: 'TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384',
0x00c096: 'TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256',
0x00c097: 'TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384',
0x00c098: 'TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256',
0x00c099: 'TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384',
0x00c09a: 'TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256',
0x00c09b: 'TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384',
0x00c09c: 'TLS_RSA_WITH_AES_128_CCM',
0x00c09d: 'TLS_RSA_WITH_AES_256_CCM',
0x00c09e: 'TLS_DHE_RSA_WITH_AES_128_CCM',
0x00c09f: 'TLS_DHE_RSA_WITH_AES_256_CCM',
0x00c0a0: 'TLS_RSA_WITH_AES_128_CCM_8',
0x00c0a1: 'TLS_RSA_WITH_AES_256_CCM_8',
0x00c0a2: 'TLS_DHE_RSA_WITH_AES_128_CCM_8',
0x00c0a3: 'TLS_DHE_RSA_WITH_AES_256_CCM_8',
0x00c0a4: 'TLS_PSK_WITH_AES_128_CCM',
0x00c0a5: 'TLS_PSK_WITH_AES_256_CCM',
0x00c0a6: 'TLS_DHE_PSK_WITH_AES_128_CCM',
0x00c0a7: 'TLS_DHE_PSK_WITH_AES_256_CCM',
0x00c0a8: 'TLS_PSK_WITH_AES_128_CCM_8',
0x00c0a9: 'TLS_PSK_WITH_AES_256_CCM_8',
0x00c0aa: 'TLS_PSK_DHE_WITH_AES_128_CCM_8',
0x00c0ab: 'TLS_PSK_DHE_WITH_AES_256_CCM_8',
0x00c0ac: 'TLS_ECDHE_ECDSA_WITH_AES_128_CCM',
0x00c0ad: 'TLS_ECDHE_ECDSA_WITH_AES_256_CCM',
0x00c0ae: 'TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8',
0x00c0af: 'TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8',
}

SSL_CIPHER_SUITE = {
0x010080: 'SSL2_RC4_128_WITH_MD5',
0x020080: 'SSL2_RC4_128_EXPORT40_WITH_MD5',
0x030080: 'SSL2_RC2_CBC_128_CBC_WITH_MD5',
0x040080: 'SSL2_RC2_CBC_128_CBC_WITH_MD5',
0x050080: 'SSL2_IDEA_128_CBC_WITH_MD5',
0x060040: 'SSL2_DES_64_CBC_WITH_MD5',
0x0700c0: 'SSL2_DES_192_EDE3_CBC_WITH_MD5',
0x080080: 'SSL2_RC4_64_WITH_MD5',
}

TLS_CIPHER_SUITE_HEAD = ('protocol', 'key_exchange', 'authentication',
                         'encryption', 'encryption_bits', 'mac')
TLS_CIPHER_SUITE_INFO = {
#       Prot  Key exchange  Authentication Encryption        Bits Mac
0x000000:('TLSv1.0',None,         None,          None,             0,   None    ),
0x000001:('TLSv1.0','RSA',        'RSA',         None,             0,   'MD5'   ),
0x000002:('TLSv1.0','RSA',        'RSA',         None,             0,   'SHA'   ),
0x000003:('TLSv1.0','RSA_EXPORT', 'RSA_EXPORT', 'RC4_40',          40,  'MD5'   ),
0x000004:('TLSv1.0','RSA',        'RSA',        'RC4_128',         128, 'MD5'   ),
0x000005:('TLSv1.0','RSA',        'RSA',        'RC4_128',         128, 'SHA'   ),
0x000006:('TLSv1.0','RSA_EXPORT', 'RSA_EXPORT', 'RC2_CBC_40',      40,  'MD5'   ),
0x000007:('TLSv1.0','RSA',        'RSA',        'IDEA_CBC',        128, 'SHA'   ),
0x000008:('TLSv1.0','RSA_EXPORT', 'RSA_EXPORT', 'DES40_CBC',       40,  'SHA'   ),
0x000009:('TLSv1.0','RSA',        'RSA',        'DES_CBC',         56,  'SHA'   ),
0x00000a:('TLSv1.0','RSA',        'RSA',        '3DES_EDE_CBC',    168, 'SHA'   ),
0x00000b:('TLSv1.0','DH',         'DSS',        'DES40_CBC',       40,  'SHA'   ),
0x00000c:('TLSv1.0','DH',         'DSS',        'DES_CBC',         56,  'SHA'   ),
0x00000d:('TLSv1.0','DH',         'DSS',        '3DES_EDE_CBC',    168, 'SHA'   ),
0x00000e:('TLSv1.0','DH',         'RSA',        'DES40_CBC',       40,  'SHA'   ),
0x00000f:('TLSv1.0','DH',         'RSA',        'DES_CBC',         56,  'SHA'   ),
0x000010:('TLSv1.0','DH',         'RSA',        '3DES_EDE_CBC',    168, 'SHA'   ),
0x000011:('TLSv1.0','DHE',        'DSS',        'DES40_CBC',       40,  'SHA'   ),
0x000012:('TLSv1.0','DHE',        'DSS',        'DES_CBC',         56,  'SHA'   ),
0x000013:('TLSv1.0','DHE',        'DSS',        '3DES_EDE_CBC',    168, 'SHA'   ),
0x000014:('TLSv1.0','DHE',        'RSA',        'DES40_CBC',       40,  'SHA'   ),
0x000015:('TLSv1.0','DHE',        'RSA',        'DES_CBC',         56,  'SHA'   ),
0x000016:('TLSv1.0','DHE',        'RSA',        '3DES_EDE_CBC',    168, 'SHA'   ),
0x000017:('TLSv1.0','DH',         None,         'RC4_40',          40,  'MD5'   ),
0x000018:('TLSv1.0','DH',         None,         'RC4_128',         128, 'MD5'   ),
0x000019:('TLSv1.0','DH',         None,         'DES40_CBC',       40,  'SHA'   ),
0x00001a:('TLSv1.0','DH',         None,         'DES_CBC',         56,  'SHA'   ),
0x00001b:('TLSv1.0','DH',         None,         '3DES_EDE_CBC',    168, 'SHA'   ),
0x00001c:('SSLv3',  'FORTEZZA',   'KEA',        None,              0,   'SHA'   ),
0x00001d:('SSLv3',  'FORTEZZA',   'KEA',        'FORTEZZA_CBC',    80,  'SHA'   ),
0x00001e:('TLSv1.0','KRB5',       'KRB5',       'DES_CBC',         56,  'SHA'   ),
0x00001f:('TLSv1.0','KRB5',       'KRB5',       '3DES_EDE_CBC',    168, 'SHA'   ),
0x000020:('TLSv1.0','KRB5',       'KRB5',       'RC4_128',         128, 'SHA'   ),
0x000021:('TLSv1.0','KRB5',       'KRB5',       'IDEA_CBC',        128, 'SHA'   ),
0x000022:('TLSv1.0','KRB5',       'KRB5',       'DES_CBC',         56,  'MD5'   ),
0x000023:('TLSv1.0','KRB5',       'KRB5',       '3DES_EDE_CBC',    168, 'MD5'   ),
0x000024:('TLSv1.0','KRB5',       'KRB5',       'RC4_128',         128, 'MD5'   ),
0x000025:('TLSv1.0','KRB5',       'KRB5',       'IDEA_CBC',        128, 'MD5'   ),
0x000026:('TLSv1.0','KRB5_EXPORT','KRB5_EXPORT','DES_CBC_40',      40,  'SHA'   ),
0x000027:('TLSv1.0','KRB5_EXPORT','KRB5_EXPORT','RC2_CBC_40',      40,  'SHA'   ),
0x000028:('TLSv1.0','KRB5_EXPORT','KRB5_EXPORT','RC4_40',          40,  'SHA'   ),
0x000029:('TLSv1.0','KRB5_EXPORT','KRB5_EXPORT','DES_CBC_40',      40,  'MD5'   ),
0x00002a:('TLSv1.0','KRB5_EXPORT','KRB5_EXPORT','RC2_CBC_40',      40,  'MD5'   ),
0x00002b:('TLSv1.0','KRB5_EXPORT','KRB5_EXPORT','RC4_40',          40,  'MD5'   ),
0x00002c:('TLSv1.0','PSK',        'PSK',        None,              0,   'SHA'   ),
0x00002d:('TLSv1.0','DHE',        'PSK',        None,              0,   'SHA'   ),
0x00002e:('TLSv1.0','RSA',        'PSK',        None,              0,   'SHA'   ),
0x00002f:('TLSv1.0','RSA',        'RSA',        'AES_128_CBC',     128, 'SHA'   ),
0x000030:('TLSv1.0','DH',         'DSS',        'AES_128_CBC',     128, 'SHA'   ),
0x000031:('TLSv1.0','DH',         'RSA',        'AES_128_CBC',     128, 'SHA'   ),
0x000032:('TLSv1.0','DHE',        'DSS',        'AES_128_CBC',     128, 'SHA'   ),
0x000033:('TLSv1.0','DHE',        'RSA',        'AES_128_CBC',     128, 'SHA'   ),
0x000034:('TLSv1.0','DH',         None,         'AES_128_CBC',     128, 'SHA'   ),
0x000035:('TLSv1.0','RSA',        'RSA',        'AES_256_CBC',     256, 'SHA'   ),
0x000036:('TLSv1.0','DH',         'DSS',        'AES_256_CBC',     256, 'SHA'   ),
0x000037:('TLSv1.0','DH',         'RSA',        'AES_256_CBC',     256, 'SHA'   ),
0x000038:('TLSv1.0','DHE',        'DSS',        'AES_256_CBC',     256, 'SHA'   ),
0x000039:('TLSv1.0','DHE',        'RSA',        'AES_256_CBC',     256, 'SHA'   ),
0x00003a:('TLSv1.0','DH',         None,         'AES_256_CBC',     256, 'SHA'   ),
0x00003b:('TLSv1.2','RSA',        'RSA',        None,              0,   'SHA256'),
0x00003c:('TLSv1.2','RSA',        'RSA',        'AES_128_CBC',     128, 'SHA256'),
0x00003d:('TLSv1.2','RSA',        'RSA',        'AES_256_CBC',     256, 'SHA256'),
0x00003e:('TLSv1.2','DH',         'DSS',        'AES_128_CBC',     128, 'SHA256'),
0x00003f:('TLSv1.2','DH',         'RSA',        'AES_128_CBC',     128, 'SHA256'),
0x000040:('TLSv1.2','DHE',        'DSS',        'AES_128_CBC',     128, 'SHA256'),
0x000041:('TLSv1.0','RSA',        'RSA',        'CAMELLIA_128_CBC',128, 'SHA'   ),
0x000042:('TLSv1.0','DH',         'DSS',        'CAMELLIA_128_CBC',128, 'SHA'   ),
0x000043:('TLSv1.0','DH',         'RSA',        'CAMELLIA_128_CBC',128, 'SHA'   ),
0x000044:('TLSv1.0','DHE',        'DSS',        'CAMELLIA_128_CBC',128, 'SHA'   ),
0x000045:('TLSv1.0','DHE',        'RSA',        'CAMELLIA_128_CBC',128, 'SHA'   ),
0x000046:('TLSv1.0','DH',         None,         'CAMELLIA_128_CBC',128, 'SHA'   ),
0x000047:('TLSv1.0','ECDH',       'ECDSA',      None,              0,   'SHA'   ),
0x000048:('TLSv1.0','ECDH',       'ECDSA',      'RC4_128',         128, 'SHA'   ),
0x000049:('TLSv1.0','ECDH',       'ECDSA',      'DES_CBC',         56,  'SHA'   ),
0x00004a:('TLSv1.0','ECDH',       'ECDSA',      '3DES_EDE_CBC',    168, 'SHA'   ),
0x00004b:('TLSv1.0','ECDH',       'ECDSA',      'AES_128_CBC',     128, 'SHA'   ),
0x00004c:('TLSv1.0','ECDH',       'ECDSA',      'AES_256_CBC',     256, 'SHA'   ),
0x000060:('TLSv1.0','RSA_EXPORT', 'RSA_EXPORT', 'RC4_56',          56,  'MD5'   ),
0x000061:('TLSv1.0','RSA_EXPORT', 'RSA_EXPORT', 'RC2_CBC_56',      56,  'MD5'   ),
0x000062:('TLSv1.0','RSA_EXPORT', 'RSA_EXPORT', 'DES_CBC',         56,  'SHA'   ),
0x000063:('TLSv1.0','DHE',        'DSS',        'DES_CBC',         56,  'SHA'   ),
0x000064:('TLSv1.0','RSA_EXPORT', 'RSA_EXPORT', 'RC4_56',          56,  'SHA'   ),
0x000065:('TLSv1.0','DHE',        'DSS',        'RC4_56',          56,  'SHA'   ),
0x000066:('TLSv1.0','DHE',        'DSS',        'RC4_128',         128, 'SHA'   ),
0x000067:('TLSv1.2','DHE',        'RSA',        'AES_128_CBC',     128, 'SHA256'),
0x000068:('TLSv1.2','DH',         'DSS',        'AES_256_CBC',     256, 'SHA256'),
0x000069:('TLSv1.2','DH',         'RSA',        'AES_256_CBC',     256, 'SHA256'),
0x00006a:('TLSv1.2','DHE',        'DSS',        'AES_256_CBC',     256, 'SHA256'),
0x00006b:('TLSv1.2','DHE',        'RSA',        'AES_256_CBC',     256, 'SHA256'),
0x00006c:('TLSv1.2','DH',         None,         'AES_128_CBC',     128, 'SHA256'),
0x00006d:('TLSv1.2','DH',         None,         'AES_256_CBC',     256, 'SHA256'),
0x000084:('TLSv1.0','RSA',        'RSA',        'CAMELLIA_256_CBC',256, 'SHA'   ),
0x000085:('TLSv1.0','DH',         'DSS',        'CAMELLIA_256_CBC',256, 'SHA'   ),
0x000086:('TLSv1.0','DH',         'RSA',        'CAMELLIA_256_CBC',256, 'SHA'   ),
0x000087:('TLSv1.0','DHE',        'DSS',        'CAMELLIA_256_CBC',256, 'SHA'   ),
0x000088:('TLSv1.0','DHE',        'RSA',        'CAMELLIA_256_CBC',256, 'SHA'   ),
0x000089:('TLSv1.0','DH',         None,         'CAMELLIA_256_CBC',256, 'SHA'   ),
0x00008a:('TLSv1.0','PSK',        'PSK',        'RC4_128',         128, 'SHA'   ),
0x00008b:('TLSv1.0','PSK',        'PSK',        '3DES_EDE_CBC',    168, 'SHA'   ),
0x00008c:('TLSv1.0','PSK',        'PSK',        'AES_128_CBC',     128, 'SHA'   ),
0x00008d:('TLSv1.0','PSK',        'PSK',        'AES_256_CBC',     256, 'SHA'   ),
0x00008e:('TLSv1.0','DHE',        'PSK',        'RC4_128',         128, 'SHA'   ),
0x00008f:('TLSv1.0','DHE',        'PSK',        '3DES_EDE_CBC',    168, 'SHA'   ),
0x000090:('TLSv1.0','DHE',        'PSK',        'AES_128_CBC',     128, 'SHA'   ),
0x000091:('TLSv1.0','DHE',        'PSK',        'AES_256_CBC',     256, 'SHA'   ),
0x000092:('TLSv1.0','RSA',        'PSK',        'RC4_128',         128, 'SHA'   ),
0x000093:('TLSv1.0','RSA',        'PSK',        '3DES_EDE_CBC',    168, 'SHA'   ),
0x000094:('TLSv1.0','RSA',        'PSK',        'AES_128_CBC',     128, 'SHA'   ),
0x000095:('TLSv1.0','RSA',        'PSK',        'AES_256_CBC',     256, 'SHA'   ),
0x000096:('TLSv1.0','RSA',        'RSA',        'SEED_CBC',        128, 'SHA'   ),
0x000097:('TLSv1.0','DH',         'DSS',        'SEED_CBC',        128, 'SHA'   ),
0x000098:('TLSv1.0','DH',         'RSA',        'SEED_CBC',        128, 'SHA'   ),
0x000099:('TLSv1.0','DHE',        'DSS',        'SEED_CBC',        128, 'SHA'   ),
0x00009a:('TLSv1.0','DHE',        'RSA',        'SEED_CBC',        128, 'SHA'   ),
0x00009b:('TLSv1.0','DH',         None,         'SEED_CBC',        128, 'SHA'   ),
0x00009c:('TLSv1.2','RSA',        'RSA',        'AES_128_GCM',     128, 'SHA256'),
0x00009d:('TLSv1.2','RSA',        'RSA',        'AES_256_GCM',     256, 'SHA384'),
0x00009e:('TLSv1.2','DHE',        'RSA',        'AES_128_GCM',     128, 'SHA256'),
0x00009f:('TLSv1.2','DHE',        'RSA',        'AES_256_GCM',     256, 'SHA384'),
0x0000a0:('TLSv1.2','DH',         'RSA',        'AES_128_GCM',     128, 'SHA256'),
0x0000a1:('TLSv1.2','DH',         'RSA',        'AES_256_GCM',     256, 'SHA384'),
0x0000a2:('TLSv1.2','DHE',        'DSS',        'AES_128_GCM',     128, 'SHA256'),
0x0000a3:('TLSv1.2','DHE',        'DSS',        'AES_256_GCM',     256, 'SHA384'),
0x0000a4:('TLSv1.2','DH',         'DSS',        'AES_128_GCM',     128, 'SHA256'),
0x0000a5:('TLSv1.2','DH',         'DSS',        'AES_256_GCM',     256, 'SHA384'),
0x0000a6:('TLSv1.2','DH',         None,         'AES_128_GCM',     128, 'SHA256'),
0x0000a7:('TLSv1.2','DH',         None,         'AES_256_GCM',     256, 'SHA384'),
0x0000a8:('TLSv1.2','PSK',        'PSK',        'AES_128_GCM',     128, 'SHA256'),
0x0000a9:('TLSv1.2','PSK',        'PSK',        'AES_256_GCM',     256, 'SHA384'),
0x0000aa:('TLSv1.2','DHE',        'PSK',        'AES_128_GCM',     128, 'SHA256'),
0x0000ab:('TLSv1.2','DHE',        'PSK',        'AES_256_GCM',     256, 'SHA384'),
0x0000ac:('TLSv1.2','RSA',        'PSK',        'AES_128_GCM',     128, 'SHA256'),
0x0000ad:('TLSv1.2','RSA',        'PSK',        'AES_256_GCM',     256, 'SHA384'),
0x0000ae:('TLSv1.2','PSK',        'PSK',        'AES_128_CBC',     128, 'SHA256'),
0x0000af:('TLSv1.2','PSK',        'PSK',        'AES_256_CBC',     256, 'SHA384'),
0x0000b0:('TLSv1.2','PSK',        'PSK',        None,              0,   'SHA256'),
0x0000b1:('TLSv1.2','PSK',        'PSK',        None,              0,   'SHA384'),
0x0000b2:('TLSv1.2','DHE',        'PSK',        'AES_128_CBC',     128, 'SHA256'),
0x0000b3:('TLSv1.2','DHE',        'PSK',        'AES_256_CBC',     256, 'SHA384'),
0x0000b4:('TLSv1.2','DHE',        'PSK',        None,              0,   'SHA256'),
0x0000b5:('TLSv1.2','DHE',        'PSK',        None,              0,   'SHA384'),
0x0000b6:('TLSv1.2','RSA',        'PSK',        'AES_128_CBC',     128, 'SHA256'),
0x0000b7:('TLSv1.2','RSA',        'PSK',        'AES_256_CBC',     256, 'SHA384'),
0x0000b8:('TLSv1.2','RSA',        'PSK',        None,              0,   'SHA256'),
0x0000b9:('TLSv1.2','RSA',        'PSK',        None,              0,   'SHA384'),
0x0000ba:('TLSv1.2','RSA',        'RSA',        'CAMELLIA_128_CBC',128, 'SHA256'),
0x0000bb:('TLSv1.2','DH',         'DSS',        'CAMELLIA_128_CBC',128, 'SHA256'),
0x0000bc:('TLSv1.2','DH',         'RSA',        'CAMELLIA_128_CBC',128, 'SHA256'),
0x0000bd:('TLSv1.2','DHE',        'DSS',        'CAMELLIA_128_CBC',128, 'SHA256'),
0x0000be:('TLSv1.2','DHE',        'RSA',        'CAMELLIA_128_CBC',128, 'SHA256'),
0x0000bf:('TLSv1.2','DH',         None,         'CAMELLIA_128_CBC',128, 'SHA256'),
0x0000c0:('TLSv1.2','RSA',        'RSA',        'CAMELLIA_256_CBC',256, 'SHA256'),
0x0000c1:('TLSv1.2','DH',         'DSS',        'CAMELLIA_256_CBC',256, 'SHA256'),
0x0000c2:('TLSv1.2','DH',         'RSA',        'CAMELLIA_256_CBC',256, 'SHA256'),
0x0000c3:('TLSv1.2','DHE',        'DSS',        'CAMELLIA_256_CBC',256, 'SHA256'),
0x0000c4:('TLSv1.2','DHE',        'RSA',        'CAMELLIA_256_CBC',256, 'SHA256'),
0x0000c5:('TLSv1.2','DH',         None,         'CAMELLIA_256_CBC',256, 'SHA256'),
0x0000ff:('TLSv1.0',None,         None,         None,              0,   None    ),
0x00c001:('TLSv1.2','ECDH',       'ECDSA',      None,              0,   'SHA'   ),
0x00c002:('TLSv1.2','ECDH',       'ECDSA',      'RC4_128',         128, 'SHA'   ),
0x00c003:('TLSv1.2','ECDH',       'ECDSA',      '3DES_EDE_CBC',    168, 'SHA'   ),
0x00c004:('TLSv1.2','ECDH',       'ECDSA',      'AES_128_CBC',     128, 'SHA'   ),
0x00c005:('TLSv1.2','ECDH',       'ECDSA',      'AES_256_CBC',     256, 'SHA'   ),
0x00c006:('TLSv1.2','ECDHE',      'ECDSA',      None,              0,   'SHA'   ),
0x00c007:('TLSv1.2','ECDHE',      'ECDSA',      'RC4_128',         128, 'SHA'   ),
0x00c008:('TLSv1.2','ECDHE',      'ECDSA',      '3DES_EDE_CBC',    168, 'SHA'   ),
0x00c009:('TLSv1.2','ECDHE',      'ECDSA',      'AES_128_CBC',     128, 'SHA'   ),
0x00c00a:('TLSv1.2','ECDHE',      'ECDSA',      'AES_256_CBC',     256, 'SHA'   ),
0x00c00b:('TLSv1.2','ECDH',       'RSA',        None,              0,   'SHA'   ),
0x00c00c:('TLSv1.2','ECDH',       'RSA',        'RC4_128',         128, 'SHA'   ),
0x00c00d:('TLSv1.2','ECDH',       'RSA',        '3DES_EDE_CBC',    168, 'SHA'   ),
0x00c00e:('TLSv1.2','ECDH',       'RSA',        'AES_128_CBC',     128, 'SHA'   ),
0x00c00f:('TLSv1.2','ECDH',       'RSA',        'AES_256_CBC',     256, 'SHA'   ),
0x00c010:('TLSv1.2','ECDHE',      'RSA',        None,              0,   'SHA'   ),
0x00c011:('TLSv1.2','ECDHE',      'RSA',        'RC4_128',         128, 'SHA'   ),
0x00c012:('TLSv1.2','ECDHE',      'RSA',        '3DES_EDE_CBC',    168, 'SHA'   ),
0x00c013:('TLSv1.2','ECDHE',      'RSA',        'AES_128_CBC',     128, 'SHA'   ),
0x00c014:('TLSv1.2','ECDHE',      'RSA',        'AES_256_CBC',     256, 'SHA'   ),
0x00c015:('TLSv1.2','ECDH',       None,         None,              0,   'SHA'   ),
0x00c016:('TLSv1.2','ECDH',       None,         'RC4_128',         128, 'SHA'   ),
0x00c017:('TLSv1.2','ECDH',       None,         '3DES_EDE_CBC',    168, 'SHA'   ),
0x00c018:('TLSv1.2','ECDH',       None,         'AES_128_CBC',     128, 'SHA'   ),
0x00c019:('TLSv1.2','ECDH',       None,         'AES_256_CBC',     256, 'SHA'   ),
0x00c01a:('TLSv1.2','SRP',        'SHA',        '3DES_EDE_CBC',    168, 'SHA'   ),
0x00c01b:('TLSv1.2','SRP',        'SHA',        '3DES_EDE_CBC',    168, 'SHA'   ),
0x00c01c:('TLSv1.2','SRP',        'SHA',        '3DES_EDE_CBC',    168, 'SHA'   ),
0x00c01d:('TLSv1.2','SRP',        'SHA',        'AES_128_CBC',     128, 'SHA'   ),
0x00c01e:('TLSv1.2','SRP',        'SHA',        'AES_128_CBC',     128, 'SHA'   ),
0x00c01f:('TLSv1.2','SRP',        'SHA',        'AES_128_CBC',     128, 'SHA'   ),
0x00c020:('TLSv1.2','SRP',        'SHA',        'AES_256_CBC',     256, 'SHA'   ),
0x00c021:('TLSv1.2','SRP',        'SHA',        'AES_256_CBC',     256, 'SHA'   ),
0x00c022:('TLSv1.2','SRP',        'SHA',        'AES_256_CBC',     256, 'SHA'   ),
0x00c023:('TLSv1.2','ECDHE',      'ECDSA',      'AES_128_CBC',     128, 'SHA256'),
0x00c024:('TLSv1.2','ECDHE',      'ECDSA',      'AES_256_CBC',     256, 'SHA384'),
0x00c025:('TLSv1.2','ECDH',       'ECDSA',      'AES_128_CBC',     128, 'SHA256'),
0x00c026:('TLSv1.2','ECDH',       'ECDSA',      'AES_256_CBC',     256, 'SHA384'),
0x00c027:('TLSv1.2','ECDHE',      'RSA',        'AES_128_CBC',     128, 'SHA256'),
0x00c028:('TLSv1.2','ECDHE',      'RSA',        'AES_256_CBC',     256, 'SHA384'),
0x00c029:('TLSv1.2','ECDH',       'RSA',        'AES_128_CBC',     128, 'SHA256'),
0x00c02a:('TLSv1.2','ECDH',       'RSA',        'AES_256_CBC',     256, 'SHA384'),
0x00c02b:('TLSv1.2','ECDHE',      'ECDSA',      'AES_128_GCM',     128, 'SHA256'),
0x00c02c:('TLSv1.2','ECDHE',      'ECDSA',      'AES_256_GCM',     256, 'SHA384'),
0x00c02d:('TLSv1.2','ECDH',       'ECDSA',      'AES_128_GCM',     128, 'SHA256'),
0x00c02e:('TLSv1.2','ECDH',       'ECDSA',      'AES_256_GCM',     256, 'SHA384'),
0x00c02f:('TLSv1.2','ECDHE',      'RSA',        'AES_128_GCM',     128, 'SHA256'),
0x00c030:('TLSv1.2','ECDHE',      'RSA',        'AES_256_GCM',     256, 'SHA384'),
0x00c031:('TLSv1.2','ECDH',       'RSA',        'AES_128_GCM',     128, 'SHA256'),
0x00c032:('TLSv1.2','ECDH',       'RSA',        'AES_256_GCM',     256, 'SHA384'),
0x00c033:('TLSv1.2','ECDHE',      'PSK',        'RC4_128',         128, 'SHA'   ),
0x00c034:('TLSv1.2','ECDHE',      'PSK',        '3DES_EDE_CBC',    168, 'SHA'   ),
0x00c035:('TLSv1.2','ECDHE',      'PSK',        'AES_128_CBC',     128, 'SHA'   ),
0x00c036:('TLSv1.2','ECDHE',      'PSK',        'AES_256_CBC',     256, 'SHA'   ),
0x00c037:('TLSv1.2','ECDHE',      'PSK',        'AES_128_CBC',     128, 'SHA256'),
0x00c038:('TLSv1.2','ECDHE',      'PSK',        'AES_256_CBC',     256, 'SHA384'),
0x00c039:('TLSv1.2','ECDHE',      'PSK',        None,              0,   'SHA'   ),
0x00c03a:('TLSv1.2','ECDHE',      'PSK',        None,              0,   'SHA256'),
0x00c03b:('TLSv1.2','ECDHE',      'PSK',        None,              0,   'SHA384'),
0x00c03c:('TLSv1.2','RSA',        None,         'ARIA_128_CBC',    128, 'SHA256'),
0x00c03d:('TLSv1.2','RSA',        None,         'ARIA_256_CBC',    256, 'SHA384'),
0x00c03e:('TLSv1.2','DH',         'DSS',        'ARIA_128_CBC',    128, 'SHA256'),
0x00c03f:('TLSv1.2','DH',         'DSS',        'ARIA_256_CBC',    256, 'SHA384'),
0x00c040:('TLSv1.2','DH',         'RSA',        'ARIA_128_CBC',    128, 'SHA256'),
0x00c041:('TLSv1.2','DH',         'RSA',        'ARIA_256_CBC',    256, 'SHA384'),
0x00c042:('TLSv1.2','DHE',        'DSS',        'ARIA_128_CBC',    128, 'SHA256'),
0x00c043:('TLSv1.2','DHE',        'DSS',        'ARIA_256_CBC',    256, 'SHA384'),
0x00c044:('TLSv1.2','DHE',        'RSA',        'ARIA_128_CBC',    128, 'SHA256'),
0x00c045:('TLSv1.2','DHE',        'RSA',        'ARIA_256_CBC',    256, 'SHA384'),
0x00c046:('TLSv1.2','DH',         None,         'ARIA_128_CBC',    128, 'SHA256'),
0x00c047:('TLSv1.2','DH',         None,         'ARIA_256_CBC',    256, 'SHA384'),
0x00c048:('TLSv1.2','ECDHE',      'ECDSA',      'ARIA_128_CBC',    128, 'SHA256'),
0x00c049:('TLSv1.2','ECDHE',      'ECDSA',      'ARIA_256_CBC',    256, 'SHA384'),
0x00c04a:('TLSv1.2','ECDH',       'ECDSA',      'ARIA_128_CBC',    128, 'SHA256'),
0x00c04b:('TLSv1.2','ECDH',       'ECDSA',      'ARIA_256_CBC',    256, 'SHA384'),
0x00c04c:('TLSv1.2','ECDHE',      'RSA',        'ARIA_128_CBC',    128, 'SHA256'),
0x00c04d:('TLSv1.2','ECDHE',      'RSA',        'ARIA_256_CBC',    256, 'SHA384'),
0x00c04e:('TLSv1.2','ECDH',       'RSA',        'ARIA_128_CBC',    128, 'SHA256'),
0x00c04f:('TLSv1.2','ECDH',       'RSA',        'ARIA_256_CBC',    256, 'SHA384'),
0x00c050:('TLSv1.2','RSA',        'RSA',        'ARIA_128_GCM',    128, 'SHA256'),
0x00c051:('TLSv1.2','RSA',        'RSA',        'ARIA_256_GCM',    256, 'SHA384'),
0x00c052:('TLSv1.2','DHE',        'RSA',        'ARIA_128_GCM',    128, 'SHA256'),
0x00c053:('TLSv1.2','DHE',        'RSA',        'ARIA_256_GCM',    256, 'SHA384'),
0x00c054:('TLSv1.2','DH',         'RSA',        'ARIA_128_GCM',    128, 'SHA256'),
0x00c055:('TLSv1.2','DH',         'RSA',        'ARIA_256_GCM',    256, 'SHA384'),
0x00c056:('TLSv1.2','DHE',        'DSS',        'ARIA_128_GCM',    128, 'SHA256'),
0x00c057:('TLSv1.2','DHE',        'DSS',        'ARIA_256_GCM',    256, 'SHA384'),
0x00c058:('TLSv1.2','DH',         'DSS',        'ARIA_128_GCM',    128, 'SHA256'),
0x00c059:('TLSv1.2','DH',         'DSS',        'ARIA_256_GCM',    256, 'SHA384'),
0x00c05a:('TLSv1.2','DH',         None,         'ARIA_128_GCM',    128, 'SHA256'),
0x00c05b:('TLSv1.2','DH',         None,         'ARIA_256_GCM',    256, 'SHA384'),
0x00c05c:('TLSv1.2','ECDHE',      'ECDSA',      'ARIA_128_GCM',    128, 'SHA256'),
0x00c05d:('TLSv1.2','ECDHE',      'ECDSA',      'ARIA_256_GCM',    256, 'SHA384'),
0x00c05e:('TLSv1.2','ECDH',       'ECDSA',      'ARIA_128_GCM',    128, 'SHA256'),
0x00c05f:('TLSv1.2','ECDH',       'ECDSA',      'ARIA_256_GCM',    256, 'SHA384'),
0x00c060:('TLSv1.2','ECDHE',      'RSA',        'ARIA_128_GCM',    128, 'SHA256'),
0x00c061:('TLSv1.2','ECDHE',      'RSA',        'ARIA_256_GCM',    256, 'SHA384'),
0x00c062:('TLSv1.2','ECDH',       'RSA',        'ARIA_128_GCM',    128, 'SHA256'),
0x00c063:('TLSv1.2','ECDH',       'RSA',        'ARIA_256_GCM',    256, 'SHA384'),
0x00c064:('TLSv1.2','PSK',        'PSK',        'ARIA_128_CBC',    128, 'SHA256'),
0x00c065:('TLSv1.2','PSK',        'PSK',        'ARIA_256_CBC',    256, 'SHA384'),
0x00c066:('TLSv1.2','DHE',        'PSK',        'ARIA_128_CBC',    128, 'SHA256'),
0x00c067:('TLSv1.2','DHE',        'PSK',        'ARIA_256_CBC',    256, 'SHA384'),
0x00c068:('TLSv1.2','RSA',        'PSK',        'ARIA_128_CBC',    128, 'SHA256'),
0x00c069:('TLSv1.2','RSA',        'PSK',        'ARIA_256_CBC',    256, 'SHA384'),
0x00c06a:('TLSv1.2','PSK',        'PSK',        'ARIA_128_GCM',    128, 'SHA256'),
0x00c06b:('TLSv1.2','PSK',        'PSK',        'ARIA_256_GCM',    256, 'SHA384'),
0x00c06c:('TLSv1.2','DHE',        'PSK',        'ARIA_128_GCM',    128, 'SHA256'),
0x00c06d:('TLSv1.2','DHE',        'PSK',        'ARIA_256_GCM',    256, 'SHA384'),
0x00c06e:('TLSv1.2','RSA',        'PSK',        'ARIA_128_GCM',    128, 'SHA256'),
0x00c06f:('TLSv1.2','RSA',        'PSK',        'ARIA_256_GCM',    256, 'SHA384'),
0x00c070:('TLSv1.2','ECDHE',      'PSK',        'ARIA_128_CBC',    128, 'SHA256'),
0x00c071:('TLSv1.2','ECDHE',      'PSK',        'ARIA_256_CBC',    256, 'SHA384'),
0x00c072:('TLSv1.2','ECDHE',      'ECDSA',      'CAMELLIA_128_CBC',128, 'SHA256'),
0x00c073:('TLSv1.2','ECDHE',      'ECDSA',      'CAMELLIA_256_CBC',256, 'SHA384'),
0x00c074:('TLSv1.2','ECDH',       'ECDSA',      'CAMELLIA_128_CBC',128, 'SHA256'),
0x00c075:('TLSv1.2','ECDH',       'ECDSA',      'CAMELLIA_256_CBC',256, 'SHA384'),
0x00c076:('TLSv1.2','ECDHE',      'RSA',        'CAMELLIA_128_CBC',128, 'SHA256'),
0x00c077:('TLSv1.2','ECDHE',      'RSA',        'CAMELLIA_256_CBC',256, 'SHA384'),
0x00c078:('TLSv1.2','ECDH',       'RSA',        'CAMELLIA_128_CBC',128, 'SHA256'),
0x00c079:('TLSv1.2','ECDH',       'RSA',        'CAMELLIA_256_CBC',256, 'SHA384'),
0x00c07a:('TLSv1.2','RSA',        'RSA',        'CAMELLIA_128_GCM',128, 'SHA256'),
0x00c07b:('TLSv1.2','RSA',        'RSA',        'CAMELLIA_256_GCM',256, 'SHA384'),
0x00c07c:('TLSv1.2','DHE',        'RSA',        'CAMELLIA_128_GCM',128, 'SHA256'),
0x00c07d:('TLSv1.2','DHE',        'RSA',        'CAMELLIA_256_GCM',256, 'SHA384'),
0x00c07e:('TLSv1.2','DH',         'RSA',        'CAMELLIA_128_GCM',128, 'SHA256'),
0x00c07f:('TLSv1.2','DH',         'RSA',        'CAMELLIA_256_GCM',256, 'SHA384'),
0x00c080:('TLSv1.2','DHE',        'DSS',        'CAMELLIA_128_GCM',128, 'SHA256'),
0x00c081:('TLSv1.2','DHE',        'DSS',        'CAMELLIA_256_GCM',256, 'SHA384'),
0x00c082:('TLSv1.2','DH',         'DSS',        'CAMELLIA_128_GCM',128, 'SHA256'),
0x00c083:('TLSv1.2','DH',         'DSS',        'CAMELLIA_256_GCM',256, 'SHA384'),
0x00c084:('TLSv1.2','DH',         None,         'CAMELLIA_128_GCM',128, 'SHA256'),
0x00c085:('TLSv1.2','DH',         None,         'CAMELLIA_256_GCM',256, 'SHA384'),
0x00c086:('TLSv1.2','ECDHE',      'ECDSA',      'CAMELLIA_128_GCM',128, 'SHA256'),
0x00c087:('TLSv1.2','ECDHE',      'ECDSA',      'CAMELLIA_256_GCM',256, 'SHA384'),
0x00c088:('TLSv1.2','ECDH',       'ECDSA',      'CAMELLIA_128_GCM',128, 'SHA256'),
0x00c089:('TLSv1.2','ECDH',       'ECDSA',      'CAMELLIA_256_GCM',256, 'SHA384'),
0x00c08a:('TLSv1.2','ECDHE',      'RSA',        'CAMELLIA_128_GCM',128, 'SHA256'),
0x00c08b:('TLSv1.2','ECDHE',      'RSA',        'CAMELLIA_256_GCM',256, 'SHA384'),
0x00c08c:('TLSv1.2','ECDH',       'RSA',        'CAMELLIA_128_GCM',128, 'SHA256'),
0x00c08d:('TLSv1.2','ECDH',       'RSA',        'CAMELLIA_256_GCM',256, 'SHA384'),
0x00c08e:('TLSv1.2','PSK',        'PSK',        'CAMELLIA_128_GCM',128, 'SHA256'),
0x00c08f:('TLSv1.2','PSK',        'PSK',        'CAMELLIA_256_GCM',256, 'SHA384'),
0x00c090:('TLSv1.2','DHE',        'PSK',        'CAMELLIA_128_GCM',128, 'SHA256'),
0x00c091:('TLSv1.2','DHE',        'PSK',        'CAMELLIA_256_GCM',256, 'SHA384'),
0x00c092:('TLSv1.2','RSA',        'PSK',        'CAMELLIA_128_GCM',128, 'SHA256'),
0x00c093:('TLSv1.2','RSA',        'PSK',        'CAMELLIA_256_GCM',256, 'SHA384'),
0x00c094:('TLSv1.2','PSK',        'PSK',        'CAMELLIA_128_CBC',128, 'SHA256'),
0x00c095:('TLSv1.2','PSK',        'PSK',        'CAMELLIA_256_CBC',256, 'SHA384'),
0x00c096:('TLSv1.2','DHE',        'PSK',        'CAMELLIA_128_CBC',128, 'SHA256'),
0x00c097:('TLSv1.2','DHE',        'PSK',        'CAMELLIA_256_CBC',256, 'SHA384'),
0x00c098:('TLSv1.2','RSA',        'PSK',        'CAMELLIA_128_CBC',128, 'SHA256'),
0x00c099:('TLSv1.2','RSA',        'PSK',        'CAMELLIA_256_CBC',256, 'SHA384'),
0x00c09a:('TLSv1.2','ECDHE',      'PSK',        'CAMELLIA_128_CBC',128, 'SHA256'),
0x00c09b:('TLSv1.2','ECDHE',      'PSK',        'CAMELLIA_256_CBC',256, 'SHA384'),
0x00c09c:('TLSv1.2','RSA',        'RSA',        'AES_128',         128, 'CCM'   ),
0x00c09d:('TLSv1.2','RSA',        'RSA',        'AES_256',         256, 'CCM'   ),
0x00c09e:('TLSv1.2','DHE',        'RSA',        'AES_128',         128, 'CCM'   ),
0x00c09f:('TLSv1.2','DHE',        'RSA',        'AES_256',         256, 'CCM'   ),
0x00c0a0:('TLSv1.2','RSA',        'RSA',        'AES_128',         128, 'CCM_8' ),
0x00c0a1:('TLSv1.2','RSA',        'RSA',        'AES_256',         256, 'CCM_8' ),
0x00c0a2:('TLSv1.2','DHE',        'RSA',        'AES_128',         128, 'CCM_8' ),
0x00c0a3:('TLSv1.2','DHE',        'RSA',        'AES_256',         256, 'CCM_8' ),
0x00c0a4:('TLSv1.2','PSK',        'PSK',        'AES_128',         128, 'CCM'   ),
0x00c0a5:('TLSv1.2','PSK',        'PSK',        'AES_256',         256, 'CCM'   ),
0x00c0a6:('TLSv1.2','DHE',        'PSK',        'AES_128',         128, 'CCM'   ),
0x00c0a7:('TLSv1.2','DHE',        'PSK',        'AES_256',         256, 'CCM'   ),
0x00c0a8:('TLSv1.2','PSK',        'PSK',        'AES_128',         128, 'CCM_8' ),
0x00c0a9:('TLSv1.2','PSK',        'PSK',        'AES_256',         256, 'CCM_8' ),
0x00c0aa:('TLSv1.2','PSK',        'DHE',        'AES_128',         128, 'CCM_8' ),
0x00c0ab:('TLSv1.2','PSK',        'DHE',        'AES_256',         256, 'CCM_8' ),
0x00c0ac:('TLSv1.2','ECDHE',      'ECDSA',      'AES_128',         128, 'CCM'   ),
0x00c0ad:('TLSv1.2','ECDHE',      'ECDSA',      'AES_256',         256, 'CCM'   ),
0x00c0ae:('TLSv1.2','ECDHE',      'ECDSA',      'AES_128',         128, 'CCM_8' ),
0x00c0af:('TLSv1.2','ECDHE',      'ECDSA',      'AES_256',         256, 'CCM_8' ),
0x00fefe:('SSLv3',  'RSA_FIPS',   'RSA_FIPS',   'DES_CBC',         56,  'SHA'   ),
0x00feff:('SSLv3',  'RSA_FIPS',   'RSA_FIPS',   '3DES_EDE_CBC',    168, 'SHA'   ),
0x00ffe0:('SSLv3',  'RSA_FIPS',   'RSA_FIPS',   '3DES_EDE_CBC',    168, 'SHA'   ),
0x00ffe1:('SSLv3',  'RSA_FIPS',   'RSA_FIPS',   'DES_CBC',         56,  'SHA'   ),
}

'''
0x0080    TLS VKO GOST R 34.10-94 VKO GOST R 34.10-94 GOST28147   256,GOST28147
0x0081    TLS VKO GOST R 34.10-2001   VKO GOST R 34.10-2001   GOST28147   256,GOST28147
0x0082    TLS VKO GOST R 34.10-94 VKO GOST R 34.10-94 NULL    0   GOSTR3411
0x0083    TLS VKO GOST R 34.10-2001   VKO GOST R 34.10-2001   NULL    0   GOSTR3411
'''

@contribute_to_class(TLS_CIPHER_SUITE)
class CipherSuite(object):
    @classmethod
    def filter(cls, **filters):
        indices = []
        ciphers = TLS_CIPHER_SUITE.keys()
        for key in filters:
            index = TLS_CIPHER_SUITE_HEAD.index(key)
            value = filters[key]
            if isinstance(value, (list, tuple, set)):
                ciphers = [
                    cipher
                    for cipher in ciphers
                    if TLS_CIPHER_SUITE_INFO[cipher][index] in value
                ]
            elif callable(value):
                ciphers = [
                    cipher
                    for cipher in ciphers
                    if value(TLS_CIPHER_SUITE_INFO[cipher][index])
                ]
            else:
                ciphers = [
                    cipher
                    for cipher in ciphers
                    if TLS_CIPHER_SUITE_INFO[cipher][index] == value
                ]
        return ciphers


TLS_CERTIFICATE_TYPE = {
    0: 'x509',
    1: 'openpgp',
    2: 'raw',
}


@contribute_to_class(TLS_CERTIFICATE_TYPE)
class CertificateType(object):
    pass


TLS_CERTIFICATE_STATUS_TYPE = {
    1: 'ocsp',
}


@contribute_to_class(TLS_CERTIFICATE_STATUS_TYPE)
class CertificateStatusType(object):
    pass


TLS_CLIENT_CERTIFICATE_TYPE = {
    1:  'rsa_sign',
    2:  'dss_sign',
    3:  'rsa_fixed_dh',
    4:  'dss_fixed_dh',
    5:  'rsa_ephemeral_dh',
    6:  'dss_ephemeral_dh',
    20: 'fortezza_dms',
    64: 'ecdsa_sign',
    65: 'rsa_fixed_ecdh',
    66: 'ecdsa_fixed_ecdh',
}


@contribute_to_class(TLS_CLIENT_CERTIFICATE_TYPE)
class ClientCertificateType(object):
    pass


TLS_CONTENT_TYPE = {
    20: 'change_cipher_spec',
    21: 'alert',
    22: 'handshake',
    23: 'application_data',
    24: 'heartbeat',
}


@contribute_to_class(TLS_CONTENT_TYPE)
class ContentType(object):
    all = tuple(TLS_CONTENT_TYPE)


TLS_EC_CURVE_NAME = {
    0x0001: 'sect163k1',                        # RFC 4492
    0x0002: 'sect163r1',                        # RFC 4492
    0x0003: 'sect163r2',                        # RFC 4492
    0x0004: 'sect193r1',                        # RFC 4492
    0x0005: 'sect193r2',                        # RFC 4492
    0x0006: 'sect233k1',                        # RFC 4492
    0x0007: 'sect233r1',                        # RFC 4492
    0x0008: 'sect239k1',                        # RFC 4492
    0x0009: 'sect283k1',                        # RFC 4492
    0x000a: 'sect283r1',                        # RFC 4492
    0x000b: 'sect409k1',                        # RFC 4492
    0x000c: 'sect409r1',                        # RFC 4492
    0x000d: 'sect571k1',                        # RFC 4492
    0x000e: 'sect571r1',                        # RFC 4492
    0x000f: 'secp160k1',                        # RFC 4492
    0x0010: 'secp160r1',                        # RFC 4492
    0x0011: 'secp160r2',                        # RFC 4492
    0x0012: 'secp192k1',                        # RFC 4492
    0x0013: 'secp192r1',                        # RFC 4492
    0x0014: 'secp224k1',                        # RFC 4492
    0x0015: 'secp224r1',                        # RFC 4492
    0x0016: 'secp256k1',                        # RFC 4492
    0x0017: 'secp256r1',                        # RFC 4492
    0x0018: 'secp384r1',                        # RFC 4492
    0x0019: 'secp521r1',                        # RFC 4492
    0x001a: 'brainpoolP256r1',                  # RFC 7027
    0x001b: 'brainpoolP384r1',                  # RFC 7027
    0x001c: 'brainpoolP512r1',                  # RFC 7027
    0xff01: 'arbitrary_explicit_prime_curves',  # RFC 4492
    0xff02: 'arbitrary_explicit_char2_curves',  # RFC 4492
}


@contribute_to_class(TLS_EC_CURVE_NAME)
class ECCurveName(object):
    pass


TLS_EC_POINT_FORMAT = {
    0x00: 'uncompressed',               # RFC 4492
    0x01: 'ansiX962_compressed_prime',  # RFC 4492
    0x02: 'ansiX962_compressed_char2',  # RFC 4492
}


@contribute_to_class(TLS_EC_POINT_FORMAT)
class ECPointFormat(object):
    pass


TLS_EC_CURVE_TYPE = {
    0x01: 'explicit_prime',             # RFC 4492
    0x02: 'explicit_char2',             # RFC 4492
    0x03: 'named_curve',                # RFC 4492
}


@contribute_to_class(TLS_EC_CURVE_TYPE)
class ECCurveType(object):
    pass


TLS_EXTENSION_TYPE = {
    0x0000: 'server_name',                  # RFC 6066
    0x0001: 'max_fragment_length',          # RFC 6066
    0x0002: 'client_cerficicate_url',       # RFC 6066
    0x0003: 'trusted_ca_keys',              # RFC 6066
    0x0004: 'truncated_hmac',               # RFC 6066
    0x0005: 'status_request',               # RFC 6066
    0x0006: 'user_mapping',                 # RFC 4681
    0x0007: 'client_authz',                 # RFC 5878
    0x0008: 'server_authz',                 # RFC 5878
    0x0009: 'cert_type',                    # RFC 6091
    0x000a: 'elliptic_curves',              # RFC 4492
    0x000b: 'ec_point_formats',             # RFC 4492
    0x000c: 'srp',                          # RFC 5054
    0x000d: 'signature_algorithms',         # RFC 6066
    0x000e: 'use_srtp',                     # RFC 5764
    0x000f: 'heartbeat',                    # RFC 6520
    0x0010: 'alpn',                         # draft-iets-tls-applayerprotoneg
    0x0011: 'status_request_v2',            # RFC 6961
    0x0012: 'signed_certificate_timestamp', # RFC 6962
    0x0013: 'client_certificate_type',      # draft-iets-tls-oob-pubkey
    0x0014: 'server_certificate_type',      # draft-iets-tls-oob-pubkey
    0x0023: 'session_ticket',               # RFC 5077
    0x3374: 'supports_npn',                 # draft-agl-tls-nextprotoneg
    0x754f: 'channel_id',                   # draft-balfanz-tls-channelid
    0xf300: 'tack',                         # draft-perrin-tls-tack
    0xff01: 'reneg_info',                   # RFC 5746
}


@contribute_to_class(TLS_EXTENSION_TYPE)
class ExtensionType(object):
    pass


TLS_HEARTBEAT_TYPE = {
    1:  'heartbeat_request',
    2:  'heartbeat_response',
}


@contribute_to_class(TLS_HEARTBEAT_TYPE)
class HeartbeatType(object):
    pass


TLS_HEARTBEAT_MODE = {
    1:  'peer_allowed_to_send',
    2:  'peer_not_allowed_to_send',
}


@contribute_to_class(TLS_HEARTBEAT_MODE)
class HeartbeatMode(object):
    pass


TLS_HANDSHAKE_TYPE = {
    0:  'hello_request',
    1:  'client_hello',
    2:  'server_hello',
    3:  'hello_verify_request',
    4:  'new_session_ticket',
    11: 'certificate',
    12: 'server_key_exchange',
    13: 'certificate_request',
    14: 'server_hello_done',
    15: 'certificate_verify',
    16: 'client_key_exchange',
    20: 'finished',
    21: 'certificate_url',
    22: 'certificate_status',
    23: 'supplemental_data',
    67: 'next_protocol',            # draft-agl-tls-nextprotoneg
}


@contribute_to_class(TLS_HANDSHAKE_TYPE)
class HandshakeType(object):
    pass


TLS_HASH_ALGORITHM = {
    0:  None,
    1:  'md5',
    2:  'sha1',
    3:  'sha224',
    4:  'sha256',
    5:  'sha384',
    6:  'sha512',
}


@contribute_to_class(TLS_HASH_ALGORITHM)
class HashAlgorithm(object):
    pass


TLS_NAME_TYPE = {
    0: 'host_name',
}


@contribute_to_class(TLS_NAME_TYPE)
class NameType(object):
    pass


TLS_VERSION = {
    (0x03, 0x00): 'SSLv3',
    (0x03, 0x01): 'TLSv1.0',
    (0x03, 0x02): 'TLSv1.1',
    (0x03, 0x03): 'TLSv1.2',
}


@contribute_to_class(TLS_VERSION)
class Version(object):
    pass
