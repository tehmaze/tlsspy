from .buffer import Buffer
from .parameters import (
    ContentType,
    TLS_ALERT_DESCRIPTION,
    TLS_ALERT_LEVEL,
)


class Alert(object):
    def __init__(self):
        self.content_type = ContentType.alert
        self.level = 0
        self.description = 0

    def parse(self, r):
        r.size_check_set(2)
        self.level = r.get(1)
        self.description = r.get(1)
        r.size_check_stop()
        return self

    def render(self):
        b = Buffer()
        b.add(self.level, 1)
        b.add(self.description, 1)
        return b.data

    def throw(self):
        if self.description in TLS_ALERT_DESCRIPTION:
            description = TLS_ALERT_DESCRIPTION[self.description]
            description = description.replace('_', ' ').title()
        else:
            description = 'Unknown Error {}'.format(self.description)
        if self.level in TLS_ALERT_LEVEL:
            level = TLS_ALERT_LEVEL[self.level]
        else:
            level = 'unknown'

        raise Exception('{} TLS alert: {}'.format(level, description))


class ChangeCipherSpec(object):
    def __init__(self):
        self.content_type = ContentType.change_cipher_spec
        self.type = 1

    def parse(self, r):
        r.size_check_set(1)
        self.type = r.get(1)
        r.size_check_stop()
        return self

    def render(self):
        b = Buffer()
        b.add(self.type, 1)
        return b.data


class RecordHeader3(object):
    def __init__(self):
        self.content_type = 0
        self.version = (0, 0)
        self.size = 0
        self.v2 = False

    def __len__(self):
        return self.size

    def render(self):
        b = Buffer()
        b.add(self.content_type, 1)
        b.add(self.version[0], 1)
        b.add(self.version[1], 1)
        b.add(self.size, 2)
        return b.data

    def parse(self, r):
        self.content_type = r.get(1)
        self.version = (r.get(1), r.get(1))
        self.size = r.get(2)
        self.v2 = False
        return self
