from collections import defaultdict
import os
import socket

from tlsspy.remote import Remote
from tlsspy.tls.connection import Connection
from tlsspy.util import merge


class Skip(Exception):
    '''
    Exception that can be raised anywhere from within the :func:`Probe.probe`
    function. Will mark the probe as skipped. Can be used if for example a
    non-fatal network error occurs or if any test criteria stop the probe from
    functioning.
    '''
    pass


class Probe(object):
    '''
    Probe base class, to be used by all probes.
    '''

    Skip = Skip

    def __init__(self, collected):
        self.collected = collected

        if not 'warnings' in self:
            self['warnings'] = defaultdict(list)
        if not 'errors' in self:
            self['errors'] = defaultdict(list)

        self.setup()

    def __contains__(self, item):
        return item in self.collected

    def __getitem__(self, item):
        return self.collected[item]

    def __setitem__(self, item, value):
        self.merge({item: value})

    def __repr__(self):
        return '{}.{}'.format(
            os.path.basename(os.path.splitext(__file__)[0]),
            self.__class__.__name__,
        )

    @classmethod
    def all(cls):
        '''
        Returns all subclasses.
        '''
        return cls.__subclasses__()

    def _connect(self, address):
        '''
        Setup a skeleton TLS connection without doing a handshake.
        '''
        try:
            remote = Remote(address)
            remote.connect()
            return Connection(remote)
        except socket.error as error:
            raise Probe.Skip('Network error: {}'.format(error))

    def merge(self, collected, base=None):
        '''
        Merge new findings into the set of collected findings. This routine
        does a recursive hash/list merge.
        '''
        base = base or self.collected

        assert isinstance(collected, dict), [collected, base]
        assert isinstance(base, dict), base

        for key in collected:
            if key in base:
                if isinstance(base[key], (list, tuple, set)):
                    base[key] = list(base[key]) + list(collected[key])
                if isinstance(base[key], set):
                    base[key].update(collected[key])
                elif isinstance(base[key], dict):
                    self.merge(collected[key], base[key])
                else:
                    base[key] = collected[key]  # Overwrites previous value
            else:
                base[key] = collected[key]

        return base

    def setup(self):
        '''
        Called by the initializor, does nothing by default.
        '''
        pass

    def probe(self, address, certificates):
        '''
        Run the probe against the target.

        :arg address: Host tuple with (``host``, ``port``), where ``host`` is an IP
                  address in dot quad (IPv4) or hextet (IPv6 notation) and
                  ``port`` is in numeric form.

        :arg certificates: Set of :class:`tlsspy.pki.Certificate` objects.
        '''
        return self.merge({})

    def warning(self, category, message):
        self.collected['warnings'][category].append(message)

    warn = warning  # alias

    def error(self, category, message):
        self.collected['errors'][category].append(message)
