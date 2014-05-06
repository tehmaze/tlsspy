from collections import defaultdict
import os
import socket

from tlsspy.remote import Remote
from tlsspy.tls.connection import Connection
from tlsspy.util import merge


class Skip(Exception):
    pass


class Probe(object):
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
        return cls.__subclasses__()

    def _connect(self, address):
        try:
            remote = Remote(address)
            remote.connect()
            return Connection(remote)
        except socket.error as error:
            raise Probe.Skip('Network error: {}'.format(error))

    def merge(self, collected, base=None):
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
        pass

    def probe(self, address, certificates):
        return self.merge({})

    def warning(self, category, message):
        self.collected['warnings'][category].append(message)

    warn = warning  # alias

    def error(self, category, message):
        self.collected['errors'][category].append(message)
