from pyasn1.type import (
    namedtype,
    namedval,
    tag,
    univ
)

from .x509 import (
    AlgorithmIdentifier,
    CertificateSerialNumber,
    Extensions,
)


class CertID(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('hashAlgorithm', AlgorithmIdentifier()),
        namedtype.NamedType('issuerNameHash', univ.OctetString()),
        namedtype.NamedType('issuerKeyHash', univ.OctetString()),
        namedtype.NamedType('serialNumber', CertificateSerialNumber()),
    )


class ResponseBytes(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('responseType', univ.ObjectIdentifier()),
        namedtype.NamedType('response', univ.OctetString()),
    )


class OCSPResponseStatus(univ.Enumerated):
    namedValues = namedval.NamedValues(
        ('successful', 0),
        ('malformedRequest', 1),
        ('internalError', 2),
        ('tryLater', 3),
        ('undefinedStatus', 4),
        ('sigRequired', 5),
        ('unauthorized', 6)
    )


class OCSPResponse(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('responseStatus', OCSPResponseStatus()),
        namedtype.OptionalNamedType(
            'responseBytes',
            ResponseBytes().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
            )
        )
    )
