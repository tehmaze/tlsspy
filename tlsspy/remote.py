import os
import socket
import urlparse


def parse_host(host, family=socket.AF_INET):
    '''
    Returns an IP address.

    >>> parse_host('localhost')
    '127.0.0.1'
    >>> parse_host('localhost', socket.AF_INET6)
    '::1'
    '''
    try:
        socket.inet_pton(family, host)
        return host
    except socket.error:
        pass

    for info in socket.getaddrinfo(host, 0, family, 0):
        _family, socktype, proto, canonname, sockaddr = info
        if _family == family:
            return sockaddr[0]


def parse_port(port, protocol='tcp'):
    '''
    Returns a port number.

    >>> parse_port(80)
    80
    >>> parse_port('80')
    80
    >>> parse_port('www')
    80
    '''
    if isinstance(port, basestring):
        if port.isdigit():
            return int(port)
        else:
            return socket.getservbyname(port, protocol)
    else:
        return int(port)


def parse_address(address, port=0, protocol='tcp', family=socket.AF_INET,
                  resolve=False):
    '''
    Returns an address and port number.

    >>> parse_address('localhost')
    ('127.0.0.1', 0)
    >>> parse_address('localhost:80')
    ('127.0.0.1', 80)
    >>> parse_address('127.0.0.1:www')
    ('127.0.0.1', 80)
    '''

    parsed_host = None
    parsed_port = None

    if isinstance(address, basestring):
        if ':' in address:
            parsed_host, parsed_port = address.split(':', 1)
        else:
            parsed_host = address
            parsed_port = port

    elif isinstance(address, tuple):
        if len(address) == 1:
            parsed_host = address[0]
            parsed_port = port
        else:
            parsed_host, parsed_port = address

    else:
        raise ValueError('Unable to parse address {0!r} with type {1}'.format(
            address,
            type(address),
        ))

    if resolve:
        parsed_host = parse_host(host)

    parsed_port = parse_port(port)
    return (parsed_host, parsed_port)


class Remote(object):
    def __init__(self, address, proxy=None, timeout=15):
        self.address = address
        self.timeout = timeout

        if proxy is None:
            proxy = os.environ.get('https_proxy')
        if proxy is None:
            proxy = os.environ.get('HTTPS_PROXY')

        if proxy:
            parsed = urlparse.urlparse(proxy)
            if parsed.scheme == 'http':
                self.proxy = HTTPProxy(parsed.netloc)
            else:
                raise TypeError('Unsupported proxy method {0}'.format(
                    parsed.scheme,
                ))
        else:
            self.proxy = None

    def connect(self):
        if self.proxy:
            self.socket = self.proxy.connect(self.address)
        else:
            self.socket = socket.create_connection(self.address, self.timeout)
            self.socket.settimeout(self.timeout)

        # Actual socket object
        self._sock = self.socket._sock

    def send_all(self, data):
        total = 0
        while data:
            sent = self.send(data)
            total += sent
            if sent == 0:
                raise socket.error('Remote closed connection')
            else:
                data = data[sent:]
        return total

    close      = lambda self, *a, **k: self.socket.close(*a, **k)
    recv       = lambda self, *a, **k: self.socket.recv(*a, **k)
    send       = lambda self, *a, **k: self.socket.send(*a, **k)
    settimeout = lambda self, *a, **k: self.socket.settimeout(*a, **k)
    shutdown   = lambda self, *a, **k: self.socket.shutdown(*a, **k)


class HTTPProxy(Remote):
    def __init__(self, address, timeout=15):
        self.address = parse_address(address, port=3128)
        self.timeout = timeout

    def connect(self, address):
        address = parse_address(address)
        self.socket = socket.create_connection(self.address, self.timeout)
        self.socket.settimeout(self.timeout)
        self.send('CONNECT {0}:{1} HTTP/1.0\r\n\r\n'.format(
            address[0],
            address[1],
        ))
        data = self.recv(1024)
        print data
        http, status, message = data.splitlines()[0].split(' ', 2)
        if status != '200':
            raise ValueError('Got HTTP {0}: {1}'.format(status, message))
        
        return self
