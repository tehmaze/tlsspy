TLS Spy
=======

TLS Analysis Toolkit, inspired by [Qualys'](https://www.qualys.com/) excellent
SSL Server Test. If you're looking for a quick tool to do online analysis, using
their tools is highly recommended.

Project status
--------------

Getting there :)

Features
--------

We support various SSL and TLS versions:

 * SSLv2 (only basic handshake)
 * SSLv3 (only basic handshake)
 * TLSv1.0 (full handshake)
 * TLSv1.1 (most handshake parts)
 * TLSv1.2 (most handshake parts)

We support various TLS extensions:

 * [RFC 4492][rfc-4492]: Elliptic Curves, EC Point Formats
 * [RFC 4507][rrc-4507]: Session Ticket
 * [RFC 5246][rfc-5246]: Signature Algorithms
 * [RFC 5746][rfc-5746]: Renegotiation
 * [RFC 6066][rfc-6066]: Server Name Indication (SNI), Status Request
 * [RFC 6520][rfc-6520]: Heartbeat

[rfc-4492]: https://tools.ietf.org/html/rfc4492
[rfc-4507]: https://tools.ietf.org/html/rfc4507
[rfc-5246]: https://tools.ietf.org/html/rfc5246
[rfc-5746]: https://tools.ietf.org/html/rfc5746
[rfc-6066]: https://tools.ietf.org/html/rfc6066
[rfc-6520]: https://tools.ietf.org/html/rfc6520

We support testing for various vulnerabilities:

 * Browser Exploit Against SSL/TLS (BEAST)
 * Compression Ratio Info-leak Made Easy (CRIME)
 * OpenSSL heartbeat information disclosue (Heartbleed)
