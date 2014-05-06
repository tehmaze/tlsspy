from tlsspy.oids import friendly_oid
from tlsspy.parser.generic import parse_hex


# http://www.mozilla.org/projects/security/pki/nss/tech-notes/tn3.html
NETSCAPE_CERT_TYPES = (
    'SSLClient',
    'SSLServer',
    'email',
    'objectSigning',
    'reserved',
    'SSLCA',
    'emailCA',
    'objectSigningCA',
)



def parse_authority_info_access(sequence):
    parsed = dict()

    for item in sequence:
        method = friendly_oid(
            item.getComponentByName('accessMethod')
        )
        location = str(
            item.getComponentByName('accessLocation').getComponent()
        )
        parsed[method] = location

    return parsed


def parse_authority_key_identifier(sequence):
    parsed = dict()

    parsed['keyIdentifier'] = parse_hex(sequence.getComponentByName(
        'keyIdentifier'
    ))
    parsed['authorityCertIssuer'] = sequence.getComponentByName(
        'authorityCertIssuer'
    )
    parsed['authorityCertSerialNumber'] = sequence.getComponentByName(
        'authorityCertSerialNumber'
    )

    return parsed


def parse_basic_constraints(sequence):
    parsed = dict()
    parsed['ca'] = bool(sequence.getComponentByName('cA'))
    try:
        parsed['path_len'] = sequence.getComponentByName('pathLenConstraint')._value
    except AttributeError:
        pass
    return parsed


def parse_distribution_point(sequence):
    parsed = {}
    for attr in sequence.componentType:
        name = attr.getName()
        item = sequence.getComponentByName(name)
        if item is not None:
            parsed[name] = item.to_python()
    return parsed


def parse_ext_key_usage(sequence):
    parsed = []
    for item in sequence:
        parsed.append(friendly_oid(item))
    return parsed


def parse_key_usage(sequence):
    parsed = []
    for bit, enabled in enumerate(sequence._value):
        if bool(enabled):
            parsed.append(sequence.namedValues[bit][0])
    return parsed


def parse_netscape_cert_type(sequence):
    parsed = []
    for bit, enabled in enumerate(sequence._value):
        if bool(enabled):
            parsed.append(NETSCAPE_CERT_TYPES[bit])
    return parsed


def parse_policy_information(sequence):
    parsed = {}
    parsed['identifier'] = friendly_oid(
        sequence.getComponentByName('policyIdentifier')
    )
    if 'policyQualifiers' in sequence:
        parsed['qualifiers'] = [
            item.to_python()
            for item in sequence.getComponentByName('policyQualifiers')
        ]
    return parsed
