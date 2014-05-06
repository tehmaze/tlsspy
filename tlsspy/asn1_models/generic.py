from pyasn1.type import univ


class ConvertableBitString(univ.BitString):
    def to_bytes(self):
        def _tuple_to_byte(tup):
            return chr(int(''.join(map(str, tup)), 2))

        b = ''
        l = len(self._value) / 8
        for byte_idx in xrange(l):
            bits_idx = byte_idx * 8
            byte_tup = self._value[bits_idx:bits_idx + 8]
            byte = _tuple_to_byte(byte_tup)
            b += byte

        return b
