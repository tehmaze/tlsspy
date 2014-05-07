import codecs
import socket
import sys

try:
    from dns import resolver, reversename
    have_dns = True
except ImportError:
    have_dns = False

from tlsspy.config import CONFIG
from tlsspy.log import log
from tlsspy.remote import parse_host, parse_port


class Report(object):
    report_types = {}
    report_type = None

    def __init__(self, address):
        self.address = address
        self.setup()
        self.filename = self.get_filename()

    def setup(self):
        self.config = CONFIG.get('report', {})
        self.separator = self.config.get(
            'separator',
            '-'
        )
        self.template = self.config.get(
            'template',
            '{host}{port_special}.{type}'
        )
        ip_addresses = self.get_host_addrs(*self.address)
        if ip_addresses:
            ip_address = ip_addresses[0]
        else:
            ip_address = None
        self.options = dict(
            address=self.address,
            host=self.address[0],
            host_name=self.get_host_name(*self.address),
            ip_address=ip_address,
            ip_addresses=ip_addresses,
            port=self.address[1],
            port_name=self.get_port_name(self.address[1]),
            port_special=self.get_port_special(self.address[1]),
            separator=self.separator,
            type=self.report_type,
        )
        self.options['host_special'] = self.get_host_special()

    def get_filename(self):
        return self.template.format(**self.options)

    def get_host_addrs(self, host, port=0):
        # Try IPv6
        try:
            socket.inet_pton(socket.AF_INET6, host)
            return [host]
        except socket.error:
            pass

        # Try IPv4
        try:
            socket.inet_pton(socket.AF_INET, host)
            return [host]
        except socket.error:
            pass

        # So it's a hostname, try to resolve
        try:
            info = socket.getaddrinfo(host, port, 0, 0, 0, socket.AI_CANONNAME)
            ips = []
            for family, socktype, proto, canonname, sockaddr in info:
                ips.append(sockaddr[0])
            return ips
        except (socket.error, IndexError):
            pass

        # All failed
        return []

    def get_host_name(self, host, port=0):
        # Try IPv6 resolving
        try:
            socket.inet_pton(socket.AF_INET6, host)
            if have_dns:
                try:
                    name = reversename.from_address(host)
                    name = str(resolver.query(name, 'PTR')[0]).rstrip('.')
                    log.debug('{0} resolved to {1}'.format(host, name))
                    return name
                except Exception as error:
                    log.debug('{0} failed to resolve: {1}'.format(host, error))
                    return host
            else:
                return host
        except socket.error:
            pass

        # Try IPv4 resolving
        try:
            socket.inet_pton(socket.AF_INET, host)
            if have_dns:
                try:
                    name = reversename.from_address(host)
                    name = str(resolver.query(name, 'PTR')[0]).rstrip('.')
                    log.debug('{0} resolved to {1}'.format(host, name))
                    return name
                except Exception as error:
                    log.debug('{0} failed to resolve: {1}'.format(host, error))
                    return host
            else:
                name = socket.gethostbyaddr(host)[0]
                if name:
                    log.debug('{0} resolved to {1}'.format(host, name))
                    return name
        except socket.error:
            pass

        # Give up
        log.debug('{0} failed to resolve: not an IP'.format(host))
        return host

    def get_host_special(self):
        if self.options['host_name'] and \
            self.options['host_name'] not in self.options['ip_addresses']:

            return '{host_name}{separator}{ip_address}'.format(**self.options)

        else:
            return self.options['host']

    def get_port_name(self, port):
        if isinstance(port, basestring):
            if port.isdigit():
                return self.get_port_name(int(port))
            else:
                return port

        else:
            try:
                return socket.getservbyport(port)
            except socket.error:
                return str(int(port))

    def get_port_special(self, port):
        if port == 443:
            return ''

        else:
            return '{separator}{port}'.format(
                separator=self.separator,
                port=port,
            )

    @classmethod
    def register(cls, report):
        cls.report_types[report.report_type] = report

    def render(self, results):
        raise NotImplementedError()

    def open(self, encoding='ascii'):
        log.debug('opening report {0}'.format(
            self.filename,
        ))
        if self.filename and self.filename != '-':
            return codecs.open(self.filename, 'wb', encoding)
        else:
            return sys.stdout


def make_report(report_type, address, result):
    report = Report.report_types[report_type](address)
    report.render(result)
