import select
import socket
import struct
import time

from tlsspy.log import log
from tlsspy.probe.base import Probe


def h2bin(x):
    return x.replace(' ', '').replace('\n', '').decode('hex')


# TODO incorporate in our TLS client
TLS_HELLO = h2bin('''
16 03 02 00  dc 01 00 00 d8 03 02 53
43 5b 90 9d 9b 72 0b bc  0c bc 2b 92 a8 48 97 cf
bd 39 04 cc 16 0a 85 03  90 9f 77 04 33 d4 de 00
00 66 c0 14 c0 0a c0 22  c0 21 00 39 00 38 00 88
00 87 c0 0f c0 05 00 35  00 84 c0 12 c0 08 c0 1c
c0 1b 00 16 00 13 c0 0d  c0 03 00 0a c0 13 c0 09
c0 1f c0 1e 00 33 00 32  00 9a 00 99 00 45 00 44
c0 0e c0 04 00 2f 00 96  00 41 c0 11 c0 07 c0 0c
c0 02 00 05 00 04 00 15  00 12 00 09 00 14 00 11
00 08 00 06 00 03 00 ff  01 00 00 49 00 0b 00 04
03 00 01 02 00 0a 00 34  00 32 00 0e 00 0d 00 19
00 0b 00 0c 00 18 00 09  00 0a 00 16 00 17 00 08
00 06 00 07 00 14 00 15  00 04 00 05 00 12 00 13
00 01 00 02 00 03 00 0f  00 10 00 11 00 23 00 00
00 0f 00 01 01
''')

TLS_HEARTBEAT = h2bin('''
18 03 02 00 03
01 40 00
''')


class ProbeHeartbleed(Probe):
    def probe(self, address, certificates):
        if address is None:
            raise Probe.Skip('offline; no address supplied')

        weakness = {}
        weakness['status'] = 'good'
        weakness['exists'] = False
        weakness['reason'] = 'Heartbeat not enabled'

        try:
            remote = socket.create_connection(address)
        except socket.error as error:
            raise Probe.Skip('network error: {0}'.format(error))

        if remote:
            remote.send(TLS_HELLO)
            while True:
                try:
                    typ, version, payload = self._get_msg(remote)
                except ValueError as error:
                    log.debug('Oops: {0}'.format(error))
                    remote = None
                    break
                else:
                    if typ == 22 and ord(payload[0]) == 0x0e:
                        break

        if remote:
            remote.send(TLS_HEARTBEAT)
            while True:
                remote.send(TLS_HEARTBEAT)
                try:
                    typ, version, payload = self._get_msg(remote)
                except ValueError as error:
                    log.debug('Oops: {0}'.format(error))
                    break
                else:
                    if typ == 24:
                        log.debug('Received heartbeat response')
                        if len(payload) > 3:
                            weakness['status'] = 'error'
                            weakness['exists'] = True
                            weakness['reason'] = 'Server returned more data ' +\
                                                 'than it should have'
                        else:
                            weakness['reason'] = 'Server-side fixed'

                        break

                    elif typ == 21:
                        # Alert
                        break

            remote.close()

        self.merge(dict(weakness=dict(heartbleed=weakness)))

    def _get_all(self, remote, size, timeout=5):
        endtime = time.time() + timeout
        rdata = ''
        remain = size
        while remain > 0:
            rtime = endtime - time.time()
            if rtime < 0:
                return

            r, w, e = select.select([remote], [], [], timeout)
            if remote in r:
                data = remote.recv(remain)
                if not data:
                    return
                rdata += data
                remain -= len(data)
        return rdata

    def _get_msg(self, remote):
        header = self._get_all(remote, 5)
        if header is None:
            raise ValueError('Unexpected EOF while receiving record header')

        typ, version, size = struct.unpack('>BHH', header)
        payload = self._get_all(remote, size, 10)
        if payload is None:
            raise ValueError('Unexpected EOF while receiving record payload')

        return typ, version, payload

PROBES = (ProbeHeartbleed,)
