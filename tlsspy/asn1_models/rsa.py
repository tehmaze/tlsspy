import math

from pyasn1.type import namedtype, tag, univ

from tlsspy.log import log
from tlsspy.util import (
    bytes_to_long,
    num_bytes,
    long_to_bytes,
    pow_mod,
)


PKCS1_PREFIX = dict(
    # RFC 4337 section 9
    md2       = '3020300c06082a864886f70d020205000410'.decode('hex'),
    md5       = '3020300c06082a864886f70d020505000410'.decode('hex'),
    sha1      = '3021300906052b0e03021a05000414'.decode('hex'),
    sha224    = '302d300d06096086480165030402040500041c'.decode('hex'),
    sha256    = '3031300d060960864801650304020105000420'.decode('hex'),
    sha384    = '3041300d060960864801650304020205000430'.decode('hex'),
    sha512    = '3051300d060960864801650304020305000440'.decode('hex'),
    ripemd160 = '3021300906052B2403020105000414'.decode('hex'),
)


class Modulus(univ.OctetString):
    tagSet = univ.OctetString.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassUniversal, tag.tagFormatSimple, 0x02)
    )


class RSAPublicKey(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('modulus', Modulus()),
        namedtype.NamedType('exponent', univ.Integer()),
    )

    def get_bits(self):
        # The modulus is always padded with a NULL byte, so here we calculate
        # the number of data bytes and convert them to bits
        #return 8 * (len(self.getComponentByName('modulus')._value) - 1)
        modulus = self.get_modulus()[1:]
        return 8 * len(modulus)

    def get_exponent(self):
        return self.getComponentByName('exponent')._value

    def get_modulus(self):
        return self.getComponentByName('modulus')._value

    def get_modulus_long(self):
        return bytes_to_long(bytearray(self.get_modulus()))

    def verify(self, signature, data, signature_algorithm):
        exponent = self.get_exponent()
        modulus = self.get_modulus_long()
        modulus_size = num_bytes(modulus)
        signature_size = len(signature)
        if modulus_size != signature_size:
            log.debug(
                'Signature length {0} does not match our key size {1}'.format(
                    signature_size,
                    modulus_size,
                )
            )
            return False

        prefix = self._add_pkcs1_prefix(data, signature_algorithm)
        padded = self._add_pkcs1_padding(prefix, 1)
        c = bytes_to_long(bytearray(signature))
        if c >= modulus:
            log.debug('Signature data exceeds modulus')
            return False

        m = pow_mod(c, exponent, modulus)
        check = long_to_bytes(m, modulus_size)
        return check == padded

    def _add_pkcs1_prefix(self, data, signature_algorithm):
        signature_algorithm = signature_algorithm.lower()
        signature_algorithm = signature_algorithm.replace('withrsaencryption', '')
        return bytearray(PKCS1_PREFIX.get(signature_algorithm, 0)) + data

    def _add_pkcs1_padding(self, value, block_type):
        modulus = self.get_modulus_long()
        modulus_size = num_bytes(modulus)
        pad_size = (modulus_size - (len(value) + 3))

        if block_type == 1:  # signature padding
            pad = [0xff] * pad_size

        elif block_type == 2:  # encryption padding
            pad = bytearray(0)
            while len(pad) < pad_size:
                pad_bytes = get_random_bytes(pad_size * 2)
                pad = filter(None, pad_bytes)
                pad = pad[:pad_size]

        else:
            raise TypeError('Invalid block type')

        padding = bytearray([0, block_type] + pad + [0])
        padded_value = padding + value
        return padded_value
