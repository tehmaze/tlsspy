import os
import re

from tlsspy.log import log
from tlsspy.pki import parse_certificate, parse_pem


RE_CKA_LABEL_UTF8            = re.compile(r'^CKA_LABEL UTF8 "(.*)"')
RE_CKA_VALUE_MULTILINE_OCTAL = re.compile(r'^CKA_VALUE MULTILINE_OCTAL')
RE_CKA_TRUSTED               = re.compile(
    r'^CKA_TRUST_SERVER_AUTH\s+CK_TRUST\s+CKT_NSS_TRUSTED_DELEGATOR'
)


class TrustStore(dict):
    def add_trust(self, substrate):
        certificate = parse_certificate(substrate)
        self[certificate.get_subject_hash()] = certificate
        log.info('Added {} ({})'.format(
            certificate.get_subject_str(),
            certificate.get_subject_hash(),
        ))

    def add_trust_from_ca_dir(self, directory):
        for filename in os.listdir(directory):
            path = os.path.join(directory, filename)
            while os.path.islink(path):
                path = os.readlink(path)
            if os.path.isfile(path):
                self.add_trust_from_ca_file(path)

    def add_trust_from_ca_file(self, filename):
        for substrate in parse_pem(file(filename), 'CERTIFICATE'):
            try:
                self.add_trust(substrate)
            except:
                pass

    def add_trust_from_certdata(self, filename):
        start_of_cert = False
        lineiter = iter(file(filename))
        while True:
            try:
                line = lineiter.next().rstrip()
            except StopIteration:
                break

            if line == '' or line.startswith('#'):
                continue

            if line.startswith('CKA_CLASS CK_OBJECT_CLASS CKO_CERTIFICATE'):
                start_of_cert = True
                continue

            untrusted = True
            if start_of_cert:
                test = RE_CKA_VALUE_MULTILINE_OCTAL.search(line)
                if test:
                    data = []
                    while True:
                        line = lineiter.next().rstrip()
                        if line == 'END':
                            break
                        for octet in line.split('\\'):
                            if not octet:
                                continue
                            data.append(chr(int(octet, 8)))

                    # Scan forwards until the trust part
                    while True:
                        line = lineiter.next()
                        if line.startswith('CKA_CLASS CK_OBJECT_CLASS CKO_NSS_TRUST'):
                            break

                    # Scan the trust part for untrusted certs
                    while True:
                        line = lineiter.next()
                        if line.startswith('#'):
                            break
                        if RE_CKA_TRUSTED.search(line):
                            untrusted = False

                    if not untrusted:
                        der = ''.join(data)
                        try:
                            self.add_trust(der)
                        except:  # meh
                            pass
                        start_of_cert = False


TRUST_STORE = TrustStore()
