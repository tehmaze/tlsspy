from pyasn1.type import namedtype, tag, univ


class DSAPublicKey(univ.Integer):
    def get_bits(self):
        return len('{:x}'.format(self._value))


class DSSParms(univ.Sequence):
    '''
    Dss-Parms  ::=  SEQUENCE  {
            p       OCTET STRING,
            q       OCTET STRING,
            g       OCTET STRING  }
    '''
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('p', univ.Integer()),
        namedtype.NamedType('q', univ.Integer()),
        namedtype.NamedType('g', univ.Integer()),
    )
