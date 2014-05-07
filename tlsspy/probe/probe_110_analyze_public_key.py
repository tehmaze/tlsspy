from collections import defaultdict

from tlsspy.probe.base import Probe
from tlsspy.log import log
from tlsspy.config import CONFIG


B1023 = 1 << 1023


class AnalyzePubKey(Probe):
    def setup(self):
        self.config = CONFIG.get('analyze', {}).get('public_key', {})

    def probe(self, address, certificates):
        '''
        Analyze the public key for each certificate in the ``certificates`` set.

        Provides the following keys:

        * ``analysis.public_keys``

        Uses the following configuration keys:

        * ``analyze.public_key.key_sizes``, which is a dictionary, containing:

          * key type, which is a dictionary, containing:

            * ``bits``, minimal number of security bits in the key
            * ``docs``, reference to the minimal size documentation
        '''
        key_infos = []
        warnings  = defaultdict(list)
        errors    = defaultdict(list)

        for certificate in certificates:
            public_key = certificate.get_public_key()
            log.debug('Analyzing {0} bit {1} key'.format(
                public_key.get_bits(),
                public_key.get_type(),
            ))

            key_info = dict(status='good')
            key_bits = public_key.get_bits()
            key_type = public_key.get_type()
            key_conf = self.config.get('key_sizes', {}).get(key_type)
            key_name = '{0} {1} bits'.format(key_type, key_bits)
            if key_conf:
                if key_bits < key_conf['bits']:
                    key_info = dict(
                        status='error',
                        reason='{0} bits {1} key is less than {2}: {3}'.format(
                            key_bits,
                            key_type,
                            key_conf['bits'],
                            key_conf['docs'],
                        )
                    )

                elif key_type == 'rsa':
                    modulus = public_key.get_modulus()
                    exponent = public_key.get_exponent()
                    if modulus < B1023:
                        key_info = dict(
                            status='error',
                            reason='Weak key',
                        )
                    elif exponent < 65537:
                        key_info = dict(
                            status='error',
                            reason='Weak exponent used 0x{:04x}'.format(
                                exponent,
                            )
                        )

            else:
                key_info = dict(
                    status='error',
                    reason='Unsupported public key algorithm',
                )

            key_infos.append({key_name: key_info})

        return self.merge(dict(
            analysis=dict(public_keys=key_infos),
            errors=errors,
            warnings=warnings,
        ))


PROBES = (
    AnalyzePubKey,
)
