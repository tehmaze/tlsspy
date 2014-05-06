import socket
import ssl
import struct

from OpenSSL.SSL import (
    Context,
    SSLv2_METHOD,
    SSLv3_METHOD,
    SSLv23_METHOD,
    TLSv1_METHOD,
    TLSv1_1_METHOD,
    TLSv1_2_METHOD,
)
from OpenSSL.SSL import Connection as SSLConnection

METHOD_NAME = {
    SSLv2_METHOD:   'SSLv2',
    SSLv3_METHOD:   'SSLv3',
    TLSv1_METHOD:   'TLSv1.0',
    TLSv1_1_METHOD: 'TLSv1.1',
    TLSv1_2_METHOD: 'TLSv1.2',
}


class Connection(object):
    def __init__(self, address, timeout=15):
        self.remote = socket.create_connection(address, timeout=timeout)
        self.timeout = timeout

    def handshake(self, method=SSLv23_METHOD, ciphers=None, compression=None,
                        hostname=None):

        if method == SSLv2_METHOD:
            # We have to resort to using ssl.wrap_socket, because pyOpenSSL
            # has dropped support for SSLv2
            self.secure = ssl.wrap_socket(
                self.remote,
                ssl_version=ssl.PROTOCOL_SSLv2,
            )
        else:
            self.context = Context(method)

            # Server Name Indication support
            if hostname is not None:
                self.context.set_tlsext_servername_callback(lambda c: hostname)

            self.secure = SSLConnection(self.context, self.remote)
            self.secure.setblocking(1)

        return self.secure
