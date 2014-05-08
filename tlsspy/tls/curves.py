TLS_EC_CURVE_NAME_HEAD = (
    'name',
    'type',
    'field',
    'key_size'
)  #: Field header names for :attr:`TLS_EC_CURVE_NAME_INFO`
TLS_EC_CURVE_NAME_INFO = {
    # RFC 4492
    0x0001: ('sect163k1',       'NIST/SECG/WTLS', 'binary', 163),
    0x0002: ('sect163r1',       'SECG',           'binary', 163),
    0x0003: ('sect163r2',       'NIST/SECG',      'binary', 163),
    0x0004: ('sect193r1',       'SECG',           'binary', 193),
    0x0005: ('sect193r2',       'SECG',           'binary', 193),
    0x0006: ('sect233k1',       'NIST/SECG/WTLS', 'binary', 233),
    0x0007: ('sect233r1',       'NIST/SECG/WTLS', 'binary', 233),
    0x0008: ('sect239k1',       'SECG',           'binary', 239),
    0x0009: ('sect283k1',       'NIST/SECG',      'binary', 283),
    0x000a: ('sect283r1',       'NIST/SECG',      'binary', 283),
    0x000b: ('sect409k1',       'NIST/SECG',      'binary', 409),
    0x000c: ('sect409r1',       'NIST/SECG',      'binary', 409),
    0x000d: ('sect571k1',       'NIST/SECG',      'binary', 571),
    0x000e: ('sect571r1',       'NIST/SECG',      'binary', 571),
    0x000f: ('secp160k1',       'SECG',           'prime',  160),
    0x0010: ('secp160r1',       'SECG',           'prime',  160),
    0x0011: ('secp160r2',       'SECG/WTLS',      'prime',  160),
    0x0012: ('secp192k1',       'SECG',           'prime',  192),
    0x0013: ('secp192r1',       'SECG',           'prime',  192),
    0x0014: ('secp224k1',       'SECG',           'prime',  224),
    0x0015: ('secp224r1',       'NIST/SECG',      'prime',  224),
    0x0016: ('secp256k1',       'SECG',           'prime',  256),
    0x0017: ('secp256r1',       'NIST/SECG',      'prime',  256),
    0x0018: ('secp384r1',       'NIST/SECG',      'prime',  384),
    0x0019: ('secp521r1',       'NIST/SECG',      'prime',  521),
    # RFC 7027
    0x001a: ('brainpoolP256r1', 'ECC',            'prime',  256),
    0x001b: ('brainpoolP384r1', 'ECC',            'prime',  384),
    0x001c: ('brainpoolP512r1', 'ECC',            'prime',  512),
}  #: Named elliptic curve information

# Unsafe criteria, are as follows:
# 1. Key size should be at least suitable for "medium-term protection", main
#    source at http://www.keylength.com/
# 2. Safe Curves should mark the curve as safe, http://safecurves.cr.yp.to/
#
# NB: Although the curve may not be listed here, in no way you should assume it
#     is safe to use in the field. Do proper research before you start using
#     any form of Elliptic Curve Cryptography
TLS_EC_CURVE_NAME_UNSAFE = {
    0x0001: ('Key size too small',
             'http://csrc.nist.gov/groups/ST/toolkit/key_management.html'),
    0x0002: ('Key size too small',
             'http://csrc.nist.gov/groups/ST/toolkit/key_management.html'),
    0x0003: ('Key size too small',
             'http://csrc.nist.gov/groups/ST/toolkit/key_management.html'),
    0x0004: ('Key size too small',
             'http://csrc.nist.gov/groups/ST/toolkit/key_management.html'),
    0x0005: ('Key size too small',
             'http://csrc.nist.gov/groups/ST/toolkit/key_management.html'),
    0x000f: ('Key size too small',
             'http://csrc.nist.gov/groups/ST/toolkit/key_management.html'),
    0x0010: ('Key size too small',
             'http://csrc.nist.gov/groups/ST/toolkit/key_management.html'),
    0x0011: ('Key size too small',
             'http://csrc.nist.gov/groups/ST/toolkit/key_management.html'),
    0x0012: ('Key size too small',
             'http://csrc.nist.gov/groups/ST/toolkit/key_management.html'),
    0x0013: ('Key size too small',
             'http://csrc.nist.gov/groups/ST/toolkit/key_management.html'),
    0x0015: ('Unsafe ECDLP and ECC security (curve AKA NIST P-224)',
             'http://safecurves.cr.yp.to/'),
    0x0016: ('Unsafe ECDLP and ECC security',
             'http://safecurves.cr.yp.to/'),
    0x0017: ('Unsafe ECDLP and ECC security (curve AKA NIST P-256)',
             'http://safecurves.cr.yp.to/'),
    0x0018: ('Unsafe ECDLP and ECC security (curve AKA NIST P-384)',
             'http://safecurves.cr.yp.to/'),
    0x001a: ('Unsafe ECC security',
             'http://safecurves.cr.yp.to/'),
    0x001b: ('Unsafe ECC security',
             'http://safecurves.cr.yp.to/'),
}  #: Unsafe named elliptic curves
