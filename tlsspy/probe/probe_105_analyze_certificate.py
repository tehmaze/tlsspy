from collections import OrderedDict
import datetime

from tlsspy.log import log
from tlsspy.probe.base import Probe
from tlsspy.trust import TRUST_STORE


class AnalyzeCertificate(Probe):
    '''
    Analyze the certificat trust chain. We validate the chain of trust, parsing
    the chain top-down (by reversing the certificates set):

    1. reverse the set
    2. check for trust anchors in our trust store
    3. a. if good, proceed to next one
       b. if untrusted, stop iteration
    '''

    def probe(self, address, certificates):
        self.chain      = []
        self.chain_hash = []
        self.trust      = []
        self.expiry     = []

        # We walk the certificate chain in reverse order
        self.check = [c for c in reversed(certificates)]
        while self.check:
            for item in self.check_trust(self.check.pop(0)):
                self.trust.append(item)

        def _certsort(a, b):
            ai_hash = a.get_issuer_hash()
            as_hash = a.get_subject_hash()
            bi_hash = b.get_issuer_hash()
            bs_hash = b.get_subject_hash()

            # If cert a is signed by b, prefer b
            if as_hash == bi_hash:
                return -1

            # If cert b is signed by a, prefer a
            elif bs_hash == ai_hash:
                return 1

            # Else, we don't care
            else:
                return 0

        self.chain.sort(_certsort)

        for certificate in self.chain:
            self.expiry.append(self.check_expiry(certificate))

        return self.merge(dict(
            analysis=dict(
                trust=self.trust[::-1],
                expiry=self.expiry[::-1],
            ),
            certificates=self._certificates_json(certificates),
        ))

    def check_expiry(self, certificate):
        now = datetime.datetime.utcnow()
        if now < certificate.get_not_before():
            return dict(
                status='error',
                reason='Certificate not yet valid',
            )
        elif now > certificate.get_not_after():
            return dict(
                status='error',
                reason='Certificate no longer valid',
            )
        else:
            return dict(status='good')

    def check_trust(self, certificate):
        log.debug('Analyzing {}'.format(certificate.get_subject_str()))

        subject_hash = certificate.get_subject_hash()
        issuer = certificate.get_issuer()
        issuer_hash = certificate.get_issuer_hash()
        issuer_name = issuer.get(
            'commonName',
            issuer.get('organizationName', issuer_hash)
        )
        trusted = (subject_hash in TRUST_STORE)

        if subject_hash not in self.chain_hash:
            self.chain.append(certificate)
            self.chain_hash.append(subject_hash)

        if self.trust and self.trust[-1]['status'] != 'good':
            yield dict(
                status='error',
                reason='Invalid chain',
            )
            return

        # Self-signed certificate
        if subject_hash == issuer_hash:
            if subject_hash in TRUST_STORE:
                # Certificate should be able to verify itself
                issuer = TRUST_STORE[subject_hash]
                status = issuer.verify(certificate)
                if status is True:
                    log.debug('Issuer "{}" in trust store'.format(
                        issuer_name,
                    ))
                    yield dict(
                        status='good',
                        reason='In trust store',
                    )
                    return

                elif status is None:
                    yield dict(
                        status='unknown',
                        reason='Unable to verify (local issue)',
                    )

            # Untrusted self-signed certificate
            log.debug('Self-signed certificate in chain')
            yield dict(trust=dict(
                status='error',
                reason='Self-signed certificate in chain',
            ))
            return

        also_check = []
        if issuer_hash in TRUST_STORE:
            issuer = TRUST_STORE[issuer_hash]
            log.debug('Issuer "{}" in trust store'.format(issuer_name))
            if issuer_hash not in self.chain_hash:
                also_check.append(issuer)

            if issuer.verify(certificate):
                yield dict(
                    status='good',
                    reason='In trust store',
                )
            else:
                yield dict(
                    status='error',
                    reason='Verification failed',
                )

        elif issuer_hash in self.chain_hash:
            log.debug('Issuer {} in trust chain'.format(issuer_name))
            issuer = self.chain[self.chain_hash.index(issuer_hash)]
            if issuer.verify(certificate):
                yield dict(
                    status='good',
                    reason='In trust chain',
                )
            else:
                yield dict(
                    status='error',
                    reason='Verification failed',
                )

        else:
            yield dict(
                status='error',
                reason='Issuer {} unknown'.format(issuer_name),
            )

        for check in also_check:
            for trust in self.check_trust(check):
                yield trust

    def _certificates_json(self, certificates_set):
        # Transform all certificates in the chain to a ready-to-be-serialized
        # structure
        certificates = []
        for certificate in self.chain[::-1]:
            jsonfied = certificate.to_json()
            jsonfied.update(dict(
                sent_by_server=certificate in certificates_set
            ))
            certificates.append(jsonfied)

        # Now update the certificates_set to list all certificates in the chain
        while certificates_set:
            certificates_set.pop()
        for certificate in self.chain[::-1]:
            certificates_set.add(certificate)

        return certificates


PROBES = (
    AnalyzeCertificate,
)
