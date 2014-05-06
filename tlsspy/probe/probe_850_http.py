import datetime
import socket
import ssl
import time

from tlsspy.log import log
from tlsspy.probe.base import Probe
from tlsspy.remote import Remote


class ProbeHTTP(Probe):
    '''
    Does a full HTTP request to gather information about the web server.
    '''
    def probe(self, address, certificates):
        if address is None:
            raise Probe.Skip('offline; no address supplied')

        try:
            remote = Remote(address)
            remote.connect()
        except socket.error as error:
            raise Probe.Skip('network error: {}'.format(
                error,
            ))

        try:
            remote = ssl.wrap_socket(remote)
        except socket.error as error:
            raise Probe.Skip('TLS error: {}'.format(
                error,
            ))

        header = []
        header.append('Host: {}'.format(address[0]))
        header.append('Accept: */*')
        header.append('Accept-Encoding: ')
        header.append('Cache-Control: no-cache')
        header.append('Connection: close')
        header.append('Date: {}'.format(
            datetime.datetime.now().strftime('%a, %d %b %Y %H:%M:%S %Z'),
        ))
        header.append('Referer: https://maze.io/')
        header.append('User-Agent: Mozilla/5.0 (TLSSpy; https://github.com/tehmaze/tlsspy)')
        packet = 'GET /?tlsspy_probe_850_http HTTP/1.1\r\n{}\r\n\r\n'.format(
            '\r\n'.join(header),
        )

        try:
            while packet:
                sent = remote.send(packet)
                if sent == 0:
                    raise Probe.Skip('network error: remote host disconnected')
                else:
                    packet = packet[sent:]

            packet = ''
            while True:
                data = remote.recv(8192)
                if data == '':
                    break
                elif len(packet) >= 0xffff:  # I'm sure that's enough
                    break
                else:
                    packet += data

            remote.close()

        except socket.error as error:
            raise Probe.Skip('network error: {}'.format(
                error,
            ))

        features = {}
        http = dict()
        header = packet.splitlines()
        if header:
            status = header.pop(0)
            if ' ' in status:
                features['http_status'] = status.split()[1]

            for line in header:
                line = line.strip()
                if line == '':
                    break

                elif ': ' in line:
                    key, value = line.split(': ', 1)
                    http[key.lower()] = value

        features['http_htst'] = http.get('strict-transport-security')
        features['http_server'] = http.get('server')

        self.merge(dict(features=dict(http=features)))


PROBES = (ProbeHTTP,)
