import hashlib
import warnings

from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.error import PyAsn1Error
from pyasn1.type import univ

from tlsspy.asn1_models import (
    dsa,
    rsa,
    ocsp,
    x509,
    x509_extension,
)
from tlsspy.crypto import md2, ripemd160
from tlsspy.log import log
from tlsspy.oids import friendly_oid

try:
    from OpenSSL.crypto import verify as SSLVerify
except ImportError:
    log.warning('Please upgrade your pyOpenSSL installation, this version has '
                'no support for certificate verification!')
    SSLVerify = None


def parse_pem(obj, marker):
    '''
    Retrieve all maching data blocks in a PEM formatted file.

    :arg marker: PEM block marker (eg ``'CERTIFICATE'``)

    :return: generator
    '''

    if isinstance(obj, basestring):
        obj = obj.splitlines()

    begin_marker = '-----BEGIN {0}-----'.format(marker.upper())
    end_marker = '-----END {0}-----'.format(marker.upper())
    keep = 0
    data = []
    for line in obj:
        line = line.strip()
        if keep:
            if line == end_marker:
                yield ''.join(data).decode('base64')
                data = []
                keep = 0
            else:
                data.append(line)

        elif line == begin_marker:
            keep = 1


def parse_certificate(substrate):
    '''
    Parse the internal structure of a DER encoded substrate.

    :arg substrate: DER encoded certificate substrate
    :return: :class:`Certificate` object
    '''
    decoded, leftover = der_decoder.decode(
        substrate,
        asn1Spec=x509.Certificate()
    )
    assert not leftover
    return Certificate(decoded)


def parse_ocsp_response(substrate):
    decoded, leftover = der_decoder.decode(
        substrate,
        asn1Spec=ocsp.OCSPResponse(),
    )
    print decoded
    assert not leftover


class Sequence(object):
    '''
    Base class for ASN.1 encoded sequence objects.

    :ivar spec: ASN.1 specification
    '''
    spec = None

    def __init__(self, sequence):
        if isinstance(sequence, basestring):
            self.sequence = der_decoder.decode(sequence, asn1Spec=self.spec)
        else:
            self.sequence = sequence

    def to_der(self):
        '''
        :return: DER encoded sequence
        '''
        return der_encoder.encode(self.sequence)

    def to_pem(self, name=None):
        '''
        :return: PEM encoded sequence
        '''
        name = name or self.__class__.__name__.upper()
        data = []
        data.append('-----BEGIN {0}-----'.format(name))
        data.append(der_encoder.encode(self.sequence).encode('base64').rstrip())
        data.append('-----END {0}-----'.format(name))
        return '\n'.join(data)


class Certificate(Sequence):
    '''
    X.509 certificate object.

    :arg sequence: ASN.1 encoded sequence object
    '''
    spec = x509.Certificate()

    def __init__(self, sequence):
        super(Certificate, self).__init__(sequence)
        self.tbsCertificate = self.sequence.getComponentByName('tbsCertificate')
        self.validity = self.tbsCertificate.getComponentByName('validity')
        #self.extensions = self.get_extensions()

    def __repr__(self):
        subject = self.get_subject()
        if 'commonName' in subject:
            return '<Certificate CN={0}>'.format(subject['commonName'])
        elif 'organizationName' in subject:
            return '<Certificate O={0}>'.format(subject['organizationName'])
        else:
            return '<Certificate {0}>'.format(self.get_subject_str())

    def get_certificate_der(self):
        '''
        :return: DER encoded tbsCertificate sequence.
        '''
        return der_encoder.encode(self.tbsCertificate)

    def get_extension(self, index):
        '''
        :arg index: extension index
        :return: :class:`Extension` object
        '''
        return Extension(
            self.sequence['tbsCertificate']['extensions'][index]
        )

    def get_extensions(self):
        '''
        :return: a list of :class:`Extension` objects
        '''
        if hasattr(self, 'extensions'):
            return self.extensions
        else:
            extensions = {}
            for i in xrange(self.get_extension_count()):
                try:
                    extension = self.get_extension(i)
                except Warning as message:
                    log.info('Failed to parse extension: {0}'.format(w))
                    extension = None

                if extension is not None:
                    extensions[extension.name] = extension

            return extensions

    def get_extension_count(self):
        '''
        :return: the number of extensions in the certificate
        '''
        try:
            return len(self.tbsCertificate.getComponentByName('extensions'))
        except PyAsn1Error:
            return 0
        except TypeError:
            return 0

    def get_hash(self):
        '''
        :return: cryptographic hash of the tbsCertificate sequence
        '''
        signature_algorithm = self.get_signature_algorithm()
        algorithm = signature_algorithm.replace('WithRSAEncryption', '')
        log.debug('Generating hashed value for {0}'.format(
            algorithm,
        ))

        data = der_encoder.encode(self.tbsCertificate)
        if algorithm == 'md2':
            return md2.MD2(data).digest()
        elif algorithm == 'md5':
            return hashlib.md5(data).digest()
        elif algorithm == 'ripemd160':
            return ripemd160.RIPEMD160(data).digest()
        elif algorithm == 'sha1':
            return hashlib.sha1(data).digest()
        elif algorithm == 'sha224':
            return hashlib.sha224(data).digest()
        elif algorithm == 'sha256':
            return hashlib.sha256(data).digest()
        elif algorithm == 'sha384':
            return hashlib.sha384(data).digest()
        elif algorithm == 'sha512':
            return hashlib.sha512(data).digest()
        else:
            log.error('Unsupported signature algorithm: {0}'.format(
                signature_algorithm,
            ))
            return None

    def get_issuer(self):
        '''
        :return: dictionary of issuer components
        '''
        return self.tbsCertificate.getComponentByName('issuer').to_python()

    def get_issuer_der(self):
        '''
        :return: DER encoded issuer sequence
        '''
        return der_encoder.encode(
            self.tbsCertificate.getComponentByName('issuer')
        )

    def get_issuer_hash(self):
        '''
        :return: SHA1 hash of the DER encoded issuer sequence
        '''
        return hashlib.sha1(self.get_issuer_der()).hexdigest()

    def get_issuer_hash_old(self):
        return hashlib.md5(self.get_issuer_der()).hexdigest()

    def get_issuer_str(self):
        return self.tbsCertificate.getComponentByName('issuer').to_rfc2253()

    def get_not_after(self):
        '''
        :return: :py:class:`datetime.date`
        '''
        return self.validity.getComponentByName('notAfter').to_python()

    def get_not_before(self):
        '''
        :return: :py:class:`datetime.date`
        '''
        return self.validity.getComponentByName('notBefore').to_python()

    def get_public_key(self):
        '''
        :return: :class:`PublicKey` object
        '''
        if not hasattr(self, 'public_key'):
            self.public_key = PublicKey(
                self.tbsCertificate.getComponentByName('subjectPublicKeyInfo')
            )
        return self.public_key

    def get_serial_number(self):
        '''
        :return: certificate serial number
        '''
        self.tbsCertificate.getComponentByName('serialNumber').to_python()

    def get_signature(self):
        '''
        :return: certificate signature
        '''
        return self.sequence.getComponentByName('signatureValue').to_bytes()

    def get_signature_algorithm(self):
        '''
        :return: human readable signature algorithm
        '''
        signature = self.sequence.getComponentByName('signatureAlgorithm')
        algorithm = signature['algorithm']
        return friendly_oid(algorithm)

    def get_signature_der(self):
        '''
        :return: DER encoded signature sequence
        '''
        return der_encoder.encode(
            self.sequence.getComponentByName('signatureValue')
        )

    def get_subject(self):
        '''
        :return: dictionary of subject components
        '''
        return self.tbsCertificate.getComponentByName('subject').to_python()

    def get_subject_alternative(self, types=('dNSName', 'iPAddress')):
        '''
        :return: list of alternative names
        '''
        extensions = self.get_extensions()
        subject = self.get_subject()
        skips = []
        if 'commonName' in subject:
            skips.append(subject['commonName'].lower())
        names = []
        if 'subjectAltName' in extensions:
            for item in extensions['subjectAltName'].to_python():
                for typ, name in item.iteritems():
                    name = name.lower()
                    if typ in types and name not in skips:
                        names.append(name)
        return names

    def get_subject_der(self):
        '''
        :return: DER encoded subject sequence
        '''
        return der_encoder.encode(
            self.tbsCertificate.getComponentByName('subject')
        )

    def get_subject_hash(self):
        return hashlib.sha1(self.get_subject_der()).hexdigest()

    def get_subject_hash_old(self):
        return hashlib.md5(self.get_subject_der()).hexdigest()

    def get_subject_str(self):
        return self.tbsCertificate.getComponentByName('subject').to_rfc2253()

    @property
    def is_ca(self):
        extensions = self.get_extensions()
        if 'basicConstraints' in extensions:
            basicConstraints = extensions['basicConstraints'].to_python()
            return basicConstraints.get('ca', False)
        else:
            return False

    def to_json(self):
        '''
        :return: certificate information ready to be serialized
        '''
        extensions = {}

        for name, extension in self.get_extensions().iteritems():
            extensions[name] = extension.to_json()

        return dict(
            data                = self.to_pem(),
            extensions          = extensions,
            issuer              = self.get_issuer(),
            issuer_hash         = self.get_issuer_hash(),
            issuer_str          = self.get_issuer_str(),
            not_after           = self.get_not_after(),
            not_before          = self.get_not_before(),
            serial              = self.get_serial_number(),
            signature           = self.get_signature().encode('hex'),
            signature_algorithm = self.get_signature_algorithm(),
            subject             = self.get_subject(),
            subject_alternative = self.get_subject_alternative(),
            subject_hash        = self.get_subject_hash(),
            subject_string      = self.get_subject_str(),
            public_key          = self.get_public_key().to_json(),
        )

    def verify(self, certificate):
        '''
        Verify the signature of ``certificate`` using the public key listed for
        this certificate.

        >>> issuer = Certificate(...)
        >>> victim = Certificate(...)
        >>> issuer.verify(victim)
        True
        '''
        # Don't bother verifying if we're not a CA certificate
        if not self.is_ca:
            log.debug('Attempted to verify from non-CA certificate')
            return False

        # Make sure this certificate is suitable for signing
        extensions = dict((k, v.to_python())
                          for k, v in self.get_extensions().iteritems())
        if not 'keyCertSign' in extensions.get('keyUsage', []):
            log.debug(
                'Attempted to verify from certificate not suitable for signing'
            )
            return False

        return self.get_public_key().verify(
            certificate.get_signature(),
            certificate.get_hash(),
            certificate.get_signature_algorithm(),
        )


class PublicKey(Sequence):
    '''
    Public key object.
    '''
    spec = x509.SubjectPublicKeyInfo()

    def __init__(self, sequence):
        super(PublicKey, self).__init__(sequence)

        algorithm = self.sequence.getComponentByName('algorithm')['algorithm']
        self.algorithm = x509.ID_KA_MAP.get(algorithm)

        if self.algorithm is None:
            raise TypeError('Unable to handle {0} keys'.format(str(algorithm)))

        key_bits = self.sequence.getComponentByName('subjectPublicKey')
        key_type = self.get_type()

        if key_type == 'DSA':
            self.key, _ = self._get_DSA_public_key(key_bits)
        elif key_type == 'RSA':
            self.key, _ = self._get_RSA_public_key(key_bits)

    def get_bits(self):
        '''
        Get the number of encryption bits for this key.

        :return: int
        '''
        return self.key.get_bits()

    def get_type(self):
        '''
        Get the algorithm name.
        '''
        return self.algorithm.split('+')[0]

    def to_json(self):
        '''
        :return: public key information ready to be serialized
        '''
        key_type = self.get_type()
        key_info = dict(
            bits=self.get_bits(),
            data=self.to_pem(),
            type=key_type,
        )

        if key_type == 'DSA':
            key_info.update(dict(
                modulus='{:x}'.format(self.key._value),
            ))

        elif key_type == 'RSA':
            key_info.update(dict(
                modulus=self.key.getComponentByName('modulus')._value.encode('hex'),
                exponent=self.key.getComponentByName('exponent')._value,
            ))

        return key_info

    def to_pem(self):
        '''
        :return: PEM encoded public key
        '''
        return super(PublicKey, self).to_pem(
            '{0} PUBLIC KEY'.format(
                self.get_type()
            )
        )

    def _get_DSA_public_key(self, key_bits):
        key = dsa.DSAPublicKey()
        pub = key_bits.to_bytes()
        return der_decoder.decode(pub, asn1Spec=key)

    def _get_RSA_public_key(self, key_bits):
        key = rsa.RSAPublicKey()
        pub = key_bits.to_bytes()
        return der_decoder.decode(pub, asn1Spec=key)

    def verify(self, signature, value, signature_algorithm):
        '''
        Verify the signature of ``value`` using this public key.

        :return: bool
        '''
        return self.key.verify(signature, value, signature_algorithm)


class Extension(Sequence):
    '''
    Certificate extension object.
    '''

    _decoders = dict(
        authorityInfoAccess    = x509_extension.AuthorityInfoAccess(),
        authorityKeyIdentifier = x509_extension.AuthorityKeyIdentifier(),
        basicConstraints       = x509_extension.BasicConstraints(),
        certificatePolicies    = x509_extension.CertificatePolicies(),
        cRLDistributionPoints  = x509_extension.CRLDistributionPoints(),
        extKeyUsage            = x509_extension.ExtKeyUsageSyntax(),
        issuerAltName          = x509_extension.IssuerAltName(),
        keyUsage               = x509_extension.KeyUsage(),
        netscapeCertType       = x509_extension.NetscapeCertType(),
        netscapeComment        = x509_extension.NetscapeComment(),
        subjectAltName         = x509_extension.SubjectAltName(),
        subjectKeyIdentifier   = x509_extension.SubjectKeyIdentifier(),
    )

    def __init__(self, sequence):
        self.sequence = sequence

        self.name = friendly_oid(self.sequence['extnID'])
        self.critical = bool(self.sequence['critical']._value)

        log.debug('Parsing extension {0}'.format(self.name))
        if self.name in self._decoders:
            self.encoded = self.sequence.getComponentByName('extnValue')._value
            self.decoded = der_decoder.decode(
                self.encoded,
                asn1Spec=self._decoders[self.name]
            )[0]

        else:
            warnings.warn('Not able to decode extension {0}'.format(self.name))
            self.decoded = None

        self.parsed = self.to_python()

    def get(self, key, default=None):
        return self.parsed.get(key, default)

    def to_json(self):
        return self.to_python()

    def to_python(self):
        if hasattr(self, 'parsed'):
            return self.parsed
        else:
            if self.decoded is None:
                return None
            else:
                try:
                    return self.decoded.to_python()
                except AttributeError, e:
                    log.error('Oops: {0}'.format(e))
                    return None
