from pyasn1.type import (
    char,
    constraint,
    namedtype,
    namedval,
    tag,
    univ,
    useful,
)

from tlsspy.asn1_models.generic import ConvertableBitString
from tlsspy.oids import friendly_oid
from tlsspy.parser import extension, generic

# "*sigh* this ASN.1 parsing is impossible! Although the ASN.1 specifications
# have been very well defined in RFCs" "No it's not, check out pyasn1, they
# have mapped out virtually every possible use case and documented it properly!"
#
# Really guys, you rock :-)
#
# This document implements data structures from:
#  * RFC5280, Internet X.509 Public Key Infrastructure Certificate and
#             Certificate Revocation List (CRL) Profile

# Upper bounds
MAX                                      = 128
ub_name                                  = univ.Integer(32768)
ub_common_name                           = univ.Integer(64)
ub_locality_name                         = univ.Integer(128)
ub_state_name                            = univ.Integer(128)
ub_organization_name                     = univ.Integer(64)
ub_organizational_unit_name              = univ.Integer(64)
ub_title                                 = univ.Integer(64)
ub_match                                 = univ.Integer(128)
ub_emailaddress_length                   = univ.Integer(128)
ub_common_name_length                    = univ.Integer(64)
ub_country_name_alpha_length             = univ.Integer(2)
ub_country_name_numeric_length           = univ.Integer(3)
ub_domain_defined_attributes             = univ.Integer(4)
ub_domain_defined_attribute_type_length  = univ.Integer(8)
ub_domain_defined_attribute_value_length = univ.Integer(128)
ub_domain_name_length                    = univ.Integer(16)
ub_extension_attributes                  = univ.Integer(256)
ub_e163_4_number_length                  = univ.Integer(15)
ub_e163_4_sub_address_length             = univ.Integer(40)
ub_generation_qualifier_length           = univ.Integer(3)
ub_given_name_length                     = univ.Integer(16)
ub_initials_length                       = univ.Integer(5)
ub_integer_options                       = univ.Integer(256)
ub_numeric_user_id_length                = univ.Integer(32)
ub_organization_name_length              = univ.Integer(64)
ub_organizational_unit_name_length       = univ.Integer(32)
ub_organizational_units                  = univ.Integer(4)
ub_pds_name_length                       = univ.Integer(16)
ub_pds_parameter_length                  = univ.Integer(30)
ub_pds_physical_address_lines            = univ.Integer(6)
ub_postal_code_length                    = univ.Integer(16)
ub_surname_length                        = univ.Integer(40)
ub_terminal_id_length                    = univ.Integer(24)
ub_unformatted_address_length            = univ.Integer(180)
ub_x121_address_length                   = univ.Integer(16)

# Object identifiers
id_ka_dsa                        = univ.ObjectIdentifier('1.2.840.10040.4.1')
id_ka_dsa_with_sha1              = univ.ObjectIdentifier('1.2.840.10040.4.3')
id_ka_rsa                        = univ.ObjectIdentifier('1.2.840.113549.1.1.1')
id_ka_md2_with_rsa               = univ.ObjectIdentifier('1.2.840.113549.1.1.2')
id_ka_md5_with_rsa               = univ.ObjectIdentifier('1.2.840.113549.1.1.4')
id_ka_sha1_with_rsa              = univ.ObjectIdentifier('1.2.840.113549.1.1.5')
id_ps_emailAddress               = univ.ObjectIdentifier('1.2.840.113549.1.9.1')
id_ps_unstructuredName           = univ.ObjectIdentifier('1.2.840.113549.1.9.2')
id_ps_contentType                = univ.ObjectIdentifier('1.2.840.113549.1.9.3')
id_ps_messageDigest              = univ.ObjectIdentifier('1.2.840.113549.1.9.4')
id_ps_signingTime                = univ.ObjectIdentifier('1.2.840.113549.1.9.5')
id_ps_challengePassword          = univ.ObjectIdentifier('1.2.840.113549.1.9.7')
id_ps_unstructuredAddress        = univ.ObjectIdentifier('1.2.840.113549.1.9.8')
id_ps_signingDescription         = univ.ObjectIdentifier('1.2.840.113549.1.9.13')
id_ps_extensionRequest           = univ.ObjectIdentifier('1.2.840.113549.1.9.14')
id_pkix                          = univ.ObjectIdentifier('1.3.6.1.5.5.7')
id_pe                            = univ.ObjectIdentifier('1.3.6.1.5.5.7.1')
id_pe_authorityInfoAccess        = univ.ObjectIdentifier('1.3.6.1.5.5.7.1.1')
id_pe_biometricInfo              = univ.ObjectIdentifier('1.3.6.1.5.5.7.1.2')
id_pe_qcStatements               = univ.ObjectIdentifier('1.3.6.1.5.5.7.1.3')
id_pe_logotype                   = univ.ObjectIdentifier('1.3.6.1.5.5.7.1.12')
id_qt                            = univ.ObjectIdentifier('1.3.6.1.5.5.7.2')
id_qt_cps                        = univ.ObjectIdentifier('1.3.6.1.5.5.7.2.1')
id_qt_unotice                    = univ.ObjectIdentifier('1.3.6.1.5.5.7.2.2')
id_kp                            = univ.ObjectIdentifier('1.3.6.1.5.5.7.3')
id_kp_serverAuth                 = univ.ObjectIdentifier('1.3.6.1.5.5.7.3.1')
id_kp_clientAuth                 = univ.ObjectIdentifier('1.3.6.1.5.5.7.3.2')
id_kp_codeSigning                = univ.ObjectIdentifier('1.3.6.1.5.5.7.3.3')
id_kp_emailProtection            = univ.ObjectIdentifier('1.3.6.1.5.5.7.3.4')
id_kp_ipsecEndSystem             = univ.ObjectIdentifier('1.3.6.1.5.5.7.3.5')
id_kp_ipsecTunnel                = univ.ObjectIdentifier('1.3.6.1.5.5.7.3.6')
id_kp_ipsecUser                  = univ.ObjectIdentifier('1.3.6.1.5.5.7.3.7')
id_kp_timeStamping               = univ.ObjectIdentifier('1.3.6.1.5.5.7.3.8')
id_kp_OCSPSigning                = univ.ObjectIdentifier('1.3.6.1.5.5.7.3.9')
id_ad_caIssuers                  = univ.ObjectIdentifier('1.3.6.1.5.5.7.48.2')
id_ad_ocsp                       = univ.ObjectIdentifier('1.3.6.1.5.5.7.48.1')
id_ad                            = univ.ObjectIdentifier('1.3.6.1.5.5.7.48')
id_holdinstruction_none          = univ.ObjectIdentifier('2.2.840.10040.2.1')
id_holdinstruction_callissuer    = univ.ObjectIdentifier('2.2.840.10040.2.2')
id_holdinstruction_reject        = univ.ObjectIdentifier('2.2.840.10040.2.3')
id_at                            = univ.ObjectIdentifier('2.5.4')
id_at_commonName                 = univ.ObjectIdentifier('2.5.4.3')
id_at_surname                    = univ.ObjectIdentifier('2.5.4.4')
id_at_serialNumber               = univ.ObjectIdentifier('2.5.4.5')
id_at_countryName                = univ.ObjectIdentifier('2.5.4.6')
id_at_localityName               = univ.ObjectIdentifier('2.5.4.7')
id_at_stateOrProvinceName        = univ.ObjectIdentifier('2.5.4.8')
id_at_streetAddress              = univ.ObjectIdentifier('2.5.4.9')
id_at_organizationName           = univ.ObjectIdentifier('2.5.4.10')
id_at_organizationalUnitName     = univ.ObjectIdentifier('2.5.4.11')
id_at_title                      = univ.ObjectIdentifier('2.5.4.12')
id_at_description                = univ.ObjectIdentifier('2.5.4.13')
id_at_businessCategory           = univ.ObjectIdentifier('2.5.4.15')
id_at_postalAddress              = univ.ObjectIdentifier('2.5.4.16')
id_at_postalCode                 = univ.ObjectIdentifier('2.5.4.17')
id_at_postOfficeBox              = univ.ObjectIdentifier('2.5.4.18')
id_at_telephoneNumber            = univ.ObjectIdentifier('2.5.4.20')
id_at_telexNumber                = univ.ObjectIdentifier('2.5.4.21')
id_at_facsimileTelephoneNumber   = univ.ObjectIdentifier('2.5.4.23')
id_at_name                       = univ.ObjectIdentifier('2.5.4.41')
id_at_givenName                  = univ.ObjectIdentifier('2.5.4.42')
id_at_initials                   = univ.ObjectIdentifier('2.5.4.43')
id_at_generationQualifier        = univ.ObjectIdentifier('2.5.4.44')
id_at_dnQualifier                = univ.ObjectIdentifier('2.5.4.46')
id_ce_subjectDirectoryAttributes = univ.ObjectIdentifier('2.5.29.9')
id_ce_subjectKeyIdentifier       = univ.ObjectIdentifier('2.5.29.14')
id_ce_keyUsage                   = univ.ObjectIdentifier('2.5.29.15')
id_ce_subjectAltName             = univ.ObjectIdentifier('2.5.29.17')
id_ce_issuerAltName              = univ.ObjectIdentifier('2.5.29.18')
id_ce_basicConstraints           = univ.ObjectIdentifier('2.5.29.19')
id_ce_cRLNumber                  = univ.ObjectIdentifier('2.5.29.20')
id_ce_cRLReasons                 = univ.ObjectIdentifier('2.5.29.21')
id_ce_holdInstructionCode        = univ.ObjectIdentifier('2.5.29.23')
id_ce_invalidityDate             = univ.ObjectIdentifier('2.5.29.24')
id_ce_deltaCRLIndicator          = univ.ObjectIdentifier('2.5.29.27')
id_ce_issuingDistributionPoint   = univ.ObjectIdentifier('2.5.29.28')
id_ce_certificateIssuer          = univ.ObjectIdentifier('2.5.29.29')
id_ce_nameConstraints            = univ.ObjectIdentifier('2.5.29.30')
id_ce_cRLDistributionPoints      = univ.ObjectIdentifier('2.5.29.31')
id_ce_certificatePolicies        = univ.ObjectIdentifier('2.5.29.32')
id_ce_policyMappings             = univ.ObjectIdentifier('2.5.29.33')
id_ce_authorityKeyIdentifier     = univ.ObjectIdentifier('2.5.29.35')
id_ce_policyConstraints          = univ.ObjectIdentifier('2.5.29.36')
id_ce_extKeyUsage                = univ.ObjectIdentifier('2.5.29.37')
id_ce_freshestCRL                = univ.ObjectIdentifier('2.5.29.46')
id_ce_inhibitAnyPolicy           = univ.ObjectIdentifier('2.5.29.54')


# Human friendly formats
ID_AT_MAP = {
    id_at_commonName:               'CN',
    id_at_surname:                  'surname',
    id_at_serialNumber:             'serialNumber',
    id_at_countryName:              'C',
    id_at_localityName:             'L',
    id_at_stateOrProvinceName:      'ST',
    id_at_streetAddress:             'street',
    id_at_organizationName:         'O',
    id_at_organizationalUnitName:   'OU',
    id_at_title:                    'T',
    id_at_description:              'description',
    id_at_businessCategory:         'businessCategory',
    id_at_postalAddress:            'postalAddress',
    id_at_postalCode:               'postalCode',
    id_at_telephoneNumber:          'telephoneNumber',
    id_at_telexNumber:              'telexNumber',
    id_at_facsimileTelephoneNumber: 'facsimileTelephoneNumber',
    id_at_name:                     'N',
    id_at_givenName:                'GN',
    id_at_initials:                 'initials',
    id_at_generationQualifier:      'generationQualifier',
    id_at_dnQualifier:              'dnQualifier',
    id_ps_emailAddress:             'emailAddress',
    id_ps_unstructuredName:         'unstructuredName',
    id_ps_contentType:              'contentType',
}

ID_CE_MAP = {
    id_ce_subjectDirectoryAttributes: 'subjectDirectoryAttributes',
    id_ce_subjectKeyIdentifier:       'subjectKeyIdentifier',
    id_ce_keyUsage:                   'keyUsage',
    id_ce_subjectAltName:             'subjectAltName',
    id_ce_issuerAltName:              'issuerAltName',
    id_ce_basicConstraints:           'basicConstraints',
    id_ce_cRLNumber:                  'CRLNumber',
    id_ce_cRLReasons:                 'CRLReasons',
    id_ce_holdInstructionCode:        'holdInstructionCode',
    id_ce_invalidityDate:             'invalidtyDate',
    id_ce_deltaCRLIndicator:          'deltaCRLIndicator',
    id_ce_issuingDistributionPoint:   'issuingDistributionPoint',
    id_ce_certificateIssuer:          'certificateIssuer',
    id_ce_nameConstraints:            'nameConstraints',
    id_ce_cRLDistributionPoints:      'CRLDistributionPoints',
    id_ce_certificatePolicies:        'certificatePolicies',
    id_ce_policyMappings:             'policyMappings',
    id_ce_authorityKeyIdentifier:     'authorityKeyIdentifier',
    id_ce_extKeyUsage:                'extendedKeyUsage',
    id_ce_freshestCRL:                'freshestCRL',
    id_ce_inhibitAnyPolicy:           'inhibitAnyPolicy',
    id_pe_authorityInfoAccess:        'authorityInfoAccess',
}

ID_KA_MAP = {
    id_ka_dsa:           'DSA',
    id_ka_dsa_with_sha1: 'DSA+SHA1',
    id_ka_rsa:           'RSA',
    id_ka_md2_with_rsa:  'RSA+MD2',
    id_ka_md5_with_rsa:  'RSA+MD5',
    id_ka_sha1_with_rsa: 'RSA+SHA1',
}

ID_KP_MAP = {
    id_kp_serverAuth:      'serverAuth',
    id_kp_clientAuth:      'clientAuth',
    id_kp_codeSigning:     'codeSigning',
    id_kp_emailProtection: 'emailProtection',
    id_kp_timeStamping:    'timeStamping',
    id_kp_OCSPSigning:     'OCSPSigning',
}


# Required for EV certificates (yarly ..)
id_ev_jurisdictionOfIncorporationLocalityName = \
    univ.ObjectIdentifier('1.3.6.1.4.1.311.60.2.1.1')
id_ev_jurisdictionOfIncorporationStateOrProvinceName = \
    univ.ObjectIdentifier('1.3.6.1.4.1.311.60.2.1.2')
id_ev_jurisdictionOfIncorporationCountryName = \
    univ.ObjectIdentifier('1.3.6.1.4.1.311.60.2.1.3')

ID_AT_MAP[id_ev_jurisdictionOfIncorporationLocalityName] = \
    'jurisdictionOfIncorporationLocalityName'
ID_AT_MAP[id_ev_jurisdictionOfIncorporationStateOrProvinceName] = \
    'jurisdictionOfIncorporationStateOrProvinceName'
ID_AT_MAP[id_ev_jurisdictionOfIncorporationCountryName] = \
    'jurisdictionOfIncorporationCountryName'


class DirectoryString(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'teletexString', 
            char.TeletexString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(1,  MAX)
            )
        ),
        namedtype.NamedType(
            'printableString', 
            char.PrintableString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(1, MAX)
            )
        ),
        namedtype.NamedType(
            'universalString', 
            char.UniversalString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(1, MAX)
            )
        ),
        namedtype.NamedType(
            'utf8String', 
            char.UTF8String().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(1, MAX)
            )
        ),
        namedtype.NamedType(
            'bmpString', 
            char.BMPString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(1, MAX)
            )
        ),
        namedtype.NamedType(
            'ia5String', 
            char.IA5String().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(1, MAX)
            )
        ) # hm, this should not be here!? XXX
    )
    to_python = generic.parse_directory_string


class AttributeValue(DirectoryString):
    def to_rfc2253(self):
        return self.getComponent()._value


class AttributeType(univ.ObjectIdentifier):
    to_python = friendly_oid

    def to_rfc2253(self):
        return friendly_oid(self, short=True)


class AttributeTypeAndValue(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', AttributeType()),
        namedtype.NamedType('value', AttributeValue()),
    )

    def to_python(self):
        return {
            self.getComponentByName('type').to_python():
                self.getComponentByName('value').to_python()
        }

    def to_rfc2253(self):
        return '='.join([
            self.getComponentByName('type').to_rfc2253(),
            self.getComponentByName('value').to_rfc2253(),
        ])


class Attribute(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', AttributeType()),
        namedtype.NamedType('vals', univ.SetOf(componentType=AttributeValue())),
    )


class RelativeDistinguishedName(univ.SetOf):
    componentType = AttributeTypeAndValue()

    def to_python(self):
        return self.componentType.to_python()


class RDNSequence(univ.SequenceOf):
    componentType = RelativeDistinguishedName()
    to_python = generic.parse_sequence_dict


class Name(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('', RDNSequence())
    )

    def to_python(self):
        name = {}
        rdn  = self[0]  # RelativeDistinguishedName

        for obj in rdn:
            atv = obj[0]  # AttributeTypeAndValue
            name.update(atv.to_python())

        return name

    def to_rfc2253(self):
        name = []
        rdn  = self[0]  # RelativeDistinguishedName

        for obj in rdn:
            atv = obj[0]  # AttributeTypeAndValue
            name.append(atv.to_rfc2253())

        return '/'.join(name)


class AlgorithmIdentifier(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('algorithm', univ.ObjectIdentifier()),
        namedtype.OptionalNamedType('parameters', univ.Any())
    )


class Extension(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('extnID', univ.ObjectIdentifier()),
        namedtype.DefaultedNamedType('critical', univ.Boolean('False')),
        namedtype.NamedType('extnValue', univ.OctetString())
    )


class Extensions(univ.SequenceOf):
    componentType = Extension()
    sizeSpec = univ.SequenceOf.sizeSpec + constraint.ValueSizeConstraint(1, MAX)


class SubjectPublicKeyInfo(univ.Sequence):
     componentType = namedtype.NamedTypes(
         namedtype.NamedType('algorithm', AlgorithmIdentifier()),
         namedtype.NamedType('subjectPublicKey', ConvertableBitString())
     )


class UniqueIdentifier(univ.BitString):
    pass


class Time(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('utcTime', useful.UTCTime()),
        namedtype.NamedType('generalTime', useful.GeneralizedTime())
    )
    to_python = generic.parse_time


class Validity(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('notBefore', Time()),
        namedtype.NamedType('notAfter', Time())
    )


class OptionalValidity(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('notBefore', Time()),
        namedtype.OptionalNamedType('notAfter', Time())
    )


class CertificateSerialNumber(univ.Integer):
    to_python = lambda self: self._value


class Version(univ.Integer):
    namedValues = namedval.NamedValues(
        ('v1', 0), ('v2', 1), ('v3', 2)
    )


class TBSCertificate(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.DefaultedNamedType(
            'version',
            Version('v1').subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
            )
        ),
        namedtype.NamedType('serialNumber', CertificateSerialNumber()),
        namedtype.NamedType('signature', AlgorithmIdentifier()),
        namedtype.NamedType('issuer', Name()),
        namedtype.NamedType('validity', Validity()),
        namedtype.NamedType('subject', Name()),
        namedtype.NamedType('subjectPublicKeyInfo', SubjectPublicKeyInfo()),
        namedtype.OptionalNamedType(
            'issuerUniqueID',
            UniqueIdentifier().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
            )
        ),
        namedtype.OptionalNamedType(
            'subjectUniqueID',
            UniqueIdentifier().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)
            )
        ),
        namedtype.OptionalNamedType(
            'extensions',
            Extensions().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3)
            )
        )
    )


class Certificate(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('tbsCertificate', TBSCertificate()),
        namedtype.NamedType('signatureAlgorithm', AlgorithmIdentifier()),
        namedtype.NamedType('signatureValue', ConvertableBitString()),
    )


class ExtensionAttribute(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'extension-attribute-type', 
            univ.Integer().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(
                    0, ub_extension_attributes
                ),
                explicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 0
                )
            )
        ),
        namedtype.NamedType(
            'extension-attribute-value', 
            univ.Any().subtype(
                explicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 1
                )
            )
        )
    )


class ExtensionAttributes(univ.SetOf):
    componentType = ExtensionAttribute()
    subtypeSpec = univ.SetOf.subtypeSpec + constraint.ValueSizeConstraint(
        1, ub_extension_attributes
    )


class BuiltInDomainDefinedAttribute(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'type',
            char.PrintableString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(
                    1, ub_domain_defined_attribute_type_length
                )
            )
        ),
        namedtype.NamedType(
            'value',
            char.PrintableString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(
                    1, ub_domain_defined_attribute_value_length
                )
            )
        ),
    )


class BuiltInDomainDefinedAttributes(univ.SequenceOf):
    componentType = BuiltInDomainDefinedAttribute()
    subtypeSpec = univ.SequenceOf.subtypeSpec + constraint.ValueSizeConstraint(
        1, ub_domain_defined_attributes
    )


class OrganizationalUnitName(char.PrintableString):
    subtypeSpec = univ.SequenceOf.subtypeSpec + constraint.ValueSizeConstraint(
        1, ub_organizational_unit_name_length
    )


class OrganizationalUnitNames(univ.SequenceOf):
    componentType = OrganizationalUnitName()
    subtypeSpec = univ.SequenceOf.subtypeSpec + constraint.ValueSizeConstraint(
        1, ub_organizational_units
    )


class PersonalName(univ.Set):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'surname', 
            char.PrintableString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(
                    1, ub_surname_length
                ),
                explicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 0
                )
            )
        ),
        namedtype.OptionalNamedType(
            'given-name', 
            char.PrintableString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(
                    1, ub_given_name_length
                ),
                explicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 1
                )
            )
        ),
        namedtype.OptionalNamedType(
            'initials', 
            char.PrintableString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(
                    1, ub_initials_length
                ),
                explicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 2
                )
            )
        ),
        namedtype.OptionalNamedType(
            'generation-qualifier', 
            char.PrintableString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(
                    1, ub_generation_qualifier_length
                ), 
                explicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 3
                )
            )
        )
    )


class NumericUserIdentifier(char.NumericString):
    subtypeSpec = char.NumericString.subtypeSpec + constraint.ValueSizeConstraint(
        1, ub_numeric_user_id_length
    )


class OrganizationName(char.PrintableString):
    subtypeSpec = char.PrintableString.subtypeSpec + constraint.ValueSizeConstraint(
        1, ub_organization_name_length
    )


class PrivateDomainName(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'numeric', 
            char.NumericString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(
                    1, ub_domain_name_length
                )
            )
        ),
        namedtype.NamedType(
            'printable',
            char.PrintableString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(
                    1, ub_domain_name_length
                )
            )
        )
    )


class TerminalIdentifier(char.PrintableString):
    subtypeSpec = char.PrintableString.subtypeSpec + constraint.ValueSizeConstraint(
        1, ub_terminal_id_length
    )


class X121Address(char.NumericString):
    subtypeSpec = char.NumericString.subtypeSpec + constraint.ValueSizeConstraint(
        1, ub_x121_address_length
    )


class NetworkAddress(X121Address):
    pass


class AdministrationDomainName(univ.Choice):
    tagSet = univ.Choice.tagSet.tagExplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 2)
    )
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'numeric', 
            char.NumericString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(
                    0,  ub_domain_name_length
                )
            )
        ),
        namedtype.NamedType(
            'printable', 
            char.PrintableString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(
                    0, ub_domain_name_length
                )
            )
        )
    )


class CountryName(univ.Choice):
    tagSet = univ.Choice.tagSet.tagExplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 1)
    )
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'x121-dcc-code',
            char.NumericString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(
                    ub_country_name_numeric_length,
                    ub_country_name_numeric_length
                )
            )
        ),
        namedtype.NamedType(
            'iso-3166-alpha2-code', 
            char.PrintableString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(
                    ub_country_name_alpha_length,
                    ub_country_name_alpha_length
                )
            )
        )
    )



class OtherName(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type-id', univ.ObjectIdentifier()),
        namedtype.NamedType('value', univ.Any()),
    )


class BuiltInStandardAttributes(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType(
            'country-name',
            CountryName()
        ),
        namedtype.OptionalNamedType(
            'administration-domain-name',
            AdministrationDomainName()
        ),
        namedtype.OptionalNamedType(
            'network-address',
            NetworkAddress().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
            )
        ),
        namedtype.OptionalNamedType(
            'terminal-identifier',
            TerminalIdentifier().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
            )
        ),
        namedtype.OptionalNamedType(
            'private-domain-name', 
            PrivateDomainName().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)
            )
        ),
        namedtype.OptionalNamedType(
            'organization-name', 
            OrganizationName().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3)
            )
        ),
        namedtype.OptionalNamedType(
            'numeric-user-identifier', 
            NumericUserIdentifier().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4)
            )
        ),
        namedtype.OptionalNamedType(
            'personal-name', 
            PersonalName().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 5)
            )
        ),
        namedtype.OptionalNamedType(
            'organizational-unit-names', 
            OrganizationalUnitNames().subtype(
                explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6)
            )
        )
    )


class ORAddress(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'built-in-standard-attributes',
            BuiltInStandardAttributes()
        ),
        namedtype.NamedType(
            'built-in-domain-defined-attributes',
            BuiltInDomainDefinedAttributes()
        ),
        namedtype.OptionalNamedType(
            'extension-attributes',
            ExtensionAttributes()
        )
    )


class SubjectDirectoryAttributes(univ.SequenceOf):
    componentType = Attribute()
    subtypeSpec = univ.SequenceOf.subtypeSpec + constraint.ValueSizeConstraint(
        1, MAX
    )


class EDIPartyName(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType(
            'nameAssigner', 
            DirectoryString().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 0
                )
            )
        ),
        namedtype.NamedType(
            'partyName', 
            DirectoryString().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 1
                )
            )
        )
    )


class AnotherName(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'type-id',
            univ.ObjectIdentifier()
        ),
        namedtype.NamedType(
            'value', 
            univ.Any().subtype(
                explicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 0
                )
            )
        )
    )


class GeneralName(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'otherName', 
            AnotherName().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 0
                )
            )
        ),
        namedtype.NamedType(
            'rfc822Name', 
            char.IA5String().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 1
                )
            )
        ),
        namedtype.NamedType(
            'dNSName', 
            char.IA5String().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 2
                )
            )
        ),
        namedtype.NamedType(
            'x400Address', 
            ORAddress().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 3
                )
            )
        ),
        namedtype.NamedType(
            'directoryName', 
            Name().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 4
                )
            )
        ),
        namedtype.NamedType(
            'ediPartyName', 
            EDIPartyName().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 5
                )
            )
        ),
        namedtype.NamedType(
            'uniformResourceIdentifier', 
            char.IA5String().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 6
                )
            )
        ),
        namedtype.NamedType(
            'iPAddress', 
            univ.OctetString().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 7
                )
            )
        ),
        namedtype.NamedType(
            'registeredID', 
            univ.ObjectIdentifier().subtype(
                implicitTag=tag.Tag(
                    tag.tagClassContext, tag.tagFormatSimple, 8
                )
            )
        )
    )


class GeneralNames(univ.SequenceOf):
    componentType = GeneralName()
    to_python = generic.parse_general_names
    subtypeSpec = univ.SequenceOf.subtypeSpec + constraint.ValueSizeConstraint(
        1, MAX
    )
