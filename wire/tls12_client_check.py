"""TLS 1.2 client transitions against an independent Python TLS 1.2 oracle.

A synthetic server flight is built here with the cryptography package
(X.509, ECDSA/RSA signatures, X25519/P-256 ECDH) and the RFC 5246 PRF over
Python hmac; the Bend production transition functions consume it through
tls12_client_cli. Accepted flights check the client's ClientKeyExchange,
Finished and both key-block epochs byte for byte (RFC 5246 6.3, 7.4.9;
RFC 7627 session hash); rejected ones check the RFC alert and reason.
Covers ServerHello negotiation (version, DOWNGRD sentinels, suites,
compression, extensions, required EMS), Certificate, ServerKeyExchange
parsing/signature input, CertificateRequest, ordering and Finished.
"""
import argparse
import datetime
import hashlib
import hmac
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, x25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = Path(__file__).resolve().parent
CIVIL_OFFSET = 62135596800
SUITES = {  # suite: (ecdsa, sha384, chacha)
    0xC02B: (True, False, False), 0xC02F: (False, False, False),
    0xC02C: (True, True, False), 0xC030: (False, True, False),
    0xCCA9: (True, False, True), 0xCCA8: (False, False, True),
}
ALPN = b'\x00\x09\x08http/1.1'
X25519_SCALAR = bytes.fromhex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a')
P256_SCALAR = bytes.fromhex('c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721')
CLIENT_RANDOM = bytes(range(32))


def prf(sha384, secret, label, seed, length):
    digest = hashlib.sha384 if sha384 else hashlib.sha256
    seed, a, out = label + seed, label + seed, b''
    while len(out) < length:
        a = hmac.new(secret, a, digest).digest()
        out += hmac.new(secret, a + seed, digest).digest()
    return out[:length]


def hs(kind, body):
    return bytes([kind]) + len(body).to_bytes(3, 'big') + body


def ext(kind, data):
    return kind.to_bytes(2, 'big') + len(data).to_bytes(2, 'big') + data


def u16(data):
    return len(data).to_bytes(2, 'big') + data


def certificates(directory):
    now = datetime.datetime.now(datetime.timezone.utc)

    def name(text):
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, text)])

    def root(label):
        key = ec.generate_private_key(ec.SECP256R1())
        cert = (x509.CertificateBuilder().subject_name(name(label)).issuer_name(name(label))
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=30))
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
                .sign(key, hashes.SHA256()))
        return key, cert

    ca_key, ca = root('M7 synthetic TLS 1.2 root')
    _, other = root('M7 unrelated root')
    leaves = {}
    for kind, key in (('p256', ec.generate_private_key(ec.SECP256R1())), ('p384', ec.generate_private_key(ec.SECP384R1())),
                      ('rsa', rsa.generate_private_key(public_exponent=65537, key_size=2048))):
        cert = (x509.CertificateBuilder().subject_name(name('M7 synthetic leaf')).issuer_name(ca.subject)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(hours=1)).not_valid_after(now + datetime.timedelta(days=7))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]), critical=False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
                .sign(ca_key, hashes.SHA256()))
        leaves[kind] = (key, cert.public_bytes(serialization.Encoding.DER))
    (directory / 'anchor.der').write_bytes(ca.public_bytes(serialization.Encoding.DER))
    (directory / 'other.der').write_bytes(other.public_bytes(serialization.Encoding.DER))
    return leaves


def sign(key, scheme, data):
    hash_of = {0x0403: hashes.SHA256(), 0x0503: hashes.SHA384(), 0x0603: hashes.SHA512(),
               0x0804: hashes.SHA256(), 0x0805: hashes.SHA384(), 0x0806: hashes.SHA512(),
               0x0401: hashes.SHA256(), 0x0501: hashes.SHA384(), 0x0601: hashes.SHA512()}[scheme]
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return key.sign(data, ec.ECDSA(hash_of))
    if scheme >> 8 == 8:
        return key.sign(data, padding.PSS(padding.MGF1(hash_of), hash_of.digest_size), hash_of)
    return key.sign(data, padding.PKCS1v15(), hash_of)


class Flight:
    """One synthetic server conversation and its expected client results."""

    def __init__(self, leaves, suite=0xC02B, leaf='p256', scheme=0x0403, group=29, request=False, **change):
        self.suite, self.group, self.request, self.change = suite, group, request, change
        self.ecdsa, self.sha384, self.chacha = SUITES.get(suite, (True, False, False))
        key, der = leaves[leaf]
        self.client_hello = hs(1, b'\x03\x03' + CLIENT_RANDOM + b'\x00' + u16(b'\x13\x01\xc0\x2b') + b'\x01\x00'
                               + u16(ext(43, b'\x04\x03\x04\x03\x03') + ext(23, b'')))
        self.server_random = change.get('random', bytes(range(100, 132)))
        extensions = change.get('extensions', ext(0xff01, b'\x00') + ext(23, b'') + ext(11, b'\x02\x00\x01') + ext(16, ALPN) + ext(0, b''))
        tail = b'' if extensions is None else u16(extensions)
        self.server_hello = hs(2, change.get('version', b'\x03\x03') + self.server_random + b'\x20' + bytes(32)
                               + suite.to_bytes(2, 'big') + bytes([change.get('compression', 0)]) + tail)
        self.certificate = hs(11, (lambda body: len(body).to_bytes(3, 'big') + body)(
            b''.join(len(c).to_bytes(3, 'big') + c for c in change.get('chain', [der]))))
        if group == 29:
            self.server_share = x25519.X25519PrivateKey.generate()
            point = self.server_share.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            client_public = x25519.X25519PrivateKey.from_private_bytes(X25519_SCALAR).public_key()
            self.client_point = client_public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            self.premaster = self.server_share.exchange(client_public)
        else:
            self.server_share = ec.generate_private_key(ec.SECP256R1())
            point = self.server_share.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
            client_public = ec.derive_private_key(int.from_bytes(P256_SCALAR, 'big'), ec.SECP256R1()).public_key()
            self.client_point = client_public.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
            self.premaster = self.server_share.exchange(ec.ECDH(), client_public)
        point = change.get('point', point)
        params = bytes([change.get('curve', 3)]) + change.get('named', group).to_bytes(2, 'big') + bytes([len(point)]) + point
        signed = change.get('signed_randoms', CLIENT_RANDOM + self.server_random) + params
        signature = sign(change.get('signer', key), change.get('sign_scheme', scheme), signed)
        if change.get('tamper'):
            signature = signature[:-1] + bytes([signature[-1] ^ 1])
        self.exchange = hs(12, params + scheme.to_bytes(2, 'big') + u16(signature))
        self.request_message = hs(13, b'\x02\x01\x40' + u16(b'\x04\x03\x08\x04') + u16(b''))
        self.done = hs(14, b'')

    def server_messages(self):
        return [self.server_hello, self.certificate, self.exchange] + ([self.request_message] if self.request else []) + [self.done]

    def expected(self):
        """Lines up to the client flight, the flight itself and the server Finished."""
        transcript = self.client_hello + b''.join(self.server_messages())
        exchange = hs(16, bytes([len(self.client_point)]) + self.client_point)
        plain = (hs(11, b'\x00\x00\x00') if self.request else b'') + exchange
        transcript += plain
        digest = hashlib.sha384 if self.sha384 else hashlib.sha256
        session_hash = digest(transcript).digest()
        master = prf(self.sha384, self.premaster, b'extended master secret', session_hash, 48)
        key_size, iv_size = (32 if self.sha384 or self.chacha else 16), (12 if self.chacha else 4)
        block = prf(self.sha384, master, b'key expansion', self.server_random + CLIENT_RANDOM, 2 * key_size + 2 * iv_size)
        ck, sk = block[:key_size], block[key_size:2 * key_size]
        civ, siv = block[2 * key_size:2 * key_size + iv_size], block[2 * key_size + iv_size:]
        finished = hs(20, prf(self.sha384, master, b'client finished', session_hash, 12))
        server_finished = hs(20, prf(self.sha384, master, b'server finished', digest(transcript + finished).digest(), 12))
        keygen = ['keygen'] if self.group == 23 else []
        lines = ['continue', 'continue'] + keygen + ['continue'] + (['continue'] if self.request else [])
        lines += [f'flight:{plain.hex()}', f'finished:{finished.hex()}', f'write:{ck.hex()}:{civ.hex()}']
        return lines, server_finished, f'read:{sk.hex()}:{siv.hex()}'


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--report', type=Path)
    p.add_argument('command', nargs='+')
    a = p.parse_args()
    rows = []
    civil = int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + CIVIL_OFFSET
    with tempfile.TemporaryDirectory(prefix='grounds-tls12-client-') as folder:
        directory = Path(folder)
        leaves = certificates(directory)
        serial = 0

        def put(data):
            nonlocal serial
            serial += 1
            path = directory / f'm{serial}'
            path.write_bytes(data)
            return str(path)

        def run(name, flight, messages, expected, anchor='anchor.der', identity='localhost', now=civil):
            command = a.command + ['run', str(ROOT.parent / 'crypto/unicode32_nfkc.bin'), str(ROOT.parent / 'crypto/unicode32_prepare.bin'),
                                   str(directory / anchor), identity, str(now), put(X25519_SCALAR), put(P256_SCALAR), put(CLIENT_RANDOM),
                                   put(flight.client_hello)] + [put(m) for m in messages]
            r = subprocess.run(command, capture_output=True, text=True, timeout=120)
            got = r.stdout.splitlines()
            assert r.returncode == 0 and got == expected, (name, got, expected, r.stderr[-2000:])
            rows.append(dict(name=name, lines=len(got), last=got[-1] if got else None))

        def accept(name, flight, alpn='true'):
            lines, server_finished, read = flight.expected()
            run(name, flight, flight.server_messages() + [b'', server_finished],
                lines + [read, f'established:{flight.suite}:{flight.group}:{alpn}'])
            return lines, server_finished, read

        def reject(name, flight, at, alert, reason, messages=None):
            """at = number of accepted messages before the failing one."""
            lines = flight.expected()[0]
            keygen = 1 if flight.group == 23 and at >= 3 else 0
            run(name, flight, messages if messages is not None else flight.server_messages(),
                lines[:at + keygen] + [f'fail:{alert}:{reason}'])

        # Accepted: every suite with a matching leaf, both groups, every scheme.
        for suite, (is_ecdsa, sha384, chacha) in SUITES.items():
            for leaf, scheme in ((('p256', 0x0403), ('p384', 0x0503), ('p256', 0x0503), ('p384', 0x0403)) if is_ecdsa else
                                 (('rsa', 0x0804), ('rsa', 0x0805), ('rsa', 0x0806), ('rsa', 0x0401), ('rsa', 0x0501), ('rsa', 0x0601))):
                for group in (29, 23):
                    if group == 23 and (leaf, scheme) not in (('p256', 0x0403), ('rsa', 0x0401)):
                        continue
                    accept(f'accept-{suite:04x}-{leaf}-{scheme:04x}-{group}', Flight(leaves, suite, leaf, scheme, group))
        accept('accept-certificate-request-empty-certificate', Flight(leaves, request=True))
        accept('accept-no-alpn-no-sni-ack', Flight(leaves, extensions=ext(23, b'') + ext(0xff01, b'\x00')), alpn='false')
        accept('accept-ems-only', Flight(leaves, extensions=ext(23, b'')), alpn='false')
        accept('accept-explicit-uncompressed-only', Flight(leaves, extensions=ext(23, b'') + ext(11, b'\x01\x00')), alpn='false')

        # ServerHello negotiation.
        sentinel = bytes(range(100, 124))
        hello_rejects = [
            ('tls11-version', dict(version=b'\x03\x02'), 70, 'server-version'),
            ('downgrade-sentinel-tls12', dict(random=sentinel + b'DOWNGRD\x01'), 47, 'downgrade-sentinel'),
            ('downgrade-sentinel-tls11', dict(random=sentinel + b'DOWNGRD\x00'), 47, 'downgrade-sentinel'),
            ('retry-random', dict(random=bytes.fromhex('cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c')), 47, 'server-selection'),
            ('compression', dict(compression=1), 47, 'compression'),
            ('no-extensions', dict(extensions=None), 40, 'extended-master-secret-required'),
            ('empty-extensions', dict(extensions=b''), 40, 'extended-master-secret-required'),
            ('no-ems', dict(extensions=ext(0xff01, b'\x00') + ext(11, b'\x01\x00')), 40, 'extended-master-secret-required'),
            ('ems-body', dict(extensions=ext(23, b'\x00')), 50, 'extended-master-secret'),
            ('session-ticket-unsolicited', dict(extensions=ext(23, b'') + ext(35, b'')), 110, 'unsolicited-extension'),
            ('status-request-unsolicited', dict(extensions=ext(23, b'') + ext(5, b'')), 110, 'unsolicited-extension'),
            ('key-share-in-tls12', dict(extensions=ext(23, b'') + ext(51, b'\x00\x1d\x00\x00')), 110, 'unsolicited-extension'),
            ('renegotiation-info-nonempty', dict(extensions=ext(23, b'') + ext(0xff01, b'\x01\x00')), 40, 'renegotiation-info'),
            ('point-formats-no-uncompressed', dict(extensions=ext(23, b'') + ext(11, b'\x01\x01')), 47, 'ec-point-formats'),
            ('point-formats-malformed', dict(extensions=ext(23, b'') + ext(11, b'\x02\x00')), 50, 'ec-point-formats'),
            ('server-name-nonempty', dict(extensions=ext(23, b'') + ext(0, b'\x00')), 50, 'server-name'),
            ('alpn-h2', dict(extensions=ext(23, b'') + ext(16, b'\x00\x03\x02h2')), 120, 'alpn-selection'),
            ('alpn-malformed', dict(extensions=ext(23, b'') + ext(16, b'\x00\x09\x09http/1.1')), 50, 'alpn'),
        ]
        for name, change, alert, reason in hello_rejects:
            reject('hello-' + name, Flight(leaves, **change), 0, alert, reason)
        for name, suite, alert, reason in (('tls13-suite', 0x1301, 70, 'missing-supported-versions'),
                                           ('rsa-key-exchange', 0x009C, 47, 'server-selection'),
                                           ('cbc', 0xC013, 47, 'server-selection'), ('dhe', 0x009E, 47, 'server-selection'),
                                           ('unoffered-ccm', 0xC0AC, 47, 'server-selection')):
            reject('hello-' + name, Flight(leaves, suite=suite), 0, alert, reason)
        duplicate = Flight(leaves, extensions=ext(23, b'') + ext(23, b''))
        run('hello-duplicate-extension', duplicate, [duplicate.server_hello], ['not-tls12'])
        tls13 = Flight(leaves, extensions=ext(23, b'') + ext(43, b'\x03\x04'))
        run('hello-supported-versions-stays-tls13', tls13, [tls13.server_hello], ['not-tls12'])
        truncated = Flight(leaves)
        run('hello-truncated', truncated, [truncated.server_hello[:-1]], ['not-tls12'])

        # Certificate.
        for name, change, kwargs, alert in (('untrusted', {}, dict(anchor='other.der'), 48),
                                            ('expired', {}, dict(now=civil + 30 * 86400), 45),
                                            ('not-yet-valid', {}, dict(now=civil - 2 * 86400), 45)):
            flight = Flight(leaves, **change)
            lines = flight.expected()[0]
            r = subprocess.run(a.command + ['run', str(ROOT.parent / 'crypto/unicode32_nfkc.bin'), str(ROOT.parent / 'crypto/unicode32_prepare.bin'),
                                            str(directory / kwargs.get('anchor', 'anchor.der')), 'localhost', str(kwargs.get('now', civil)),
                                            put(X25519_SCALAR), put(P256_SCALAR), put(CLIENT_RANDOM), put(flight.client_hello)]
                               + [put(m) for m in flight.server_messages()], capture_output=True, text=True, timeout=120)
            got = r.stdout.splitlines()
            assert got[:1] == lines[:1] and got[1].startswith(f'fail:{alert}:certificate:') and len(got) == 2, (name, got)
            rows.append(dict(name='certificate-' + name, last=got[-1]))
        flight = Flight(leaves)
        r = subprocess.run(a.command + ['run', str(ROOT.parent / 'crypto/unicode32_nfkc.bin'), str(ROOT.parent / 'crypto/unicode32_prepare.bin'),
                                        str(directory / 'anchor.der'), 'example.com', str(civil), put(X25519_SCALAR), put(P256_SCALAR),
                                        put(CLIENT_RANDOM), put(flight.client_hello)] + [put(m) for m in flight.server_messages()],
                           capture_output=True, text=True, timeout=120)
        got = r.stdout.splitlines()
        assert len(got) == 2 and got[1].startswith('fail:42:certificate:'), got
        rows.append(dict(name='certificate-wrong-host', last=got[-1]))
        reject('certificate-ecdsa-suite-rsa-leaf', Flight(leaves, suite=0xC02B, leaf='rsa', scheme=0x0804), 1, 43, 'certificate-key-suite')
        reject('certificate-rsa-suite-ecdsa-leaf', Flight(leaves, suite=0xC02F, leaf='p256', scheme=0x0403), 1, 43, 'certificate-key-suite')
        reject('certificate-empty', Flight(leaves, chain=[]), 1, 50, 'empty-server-certificate')
        flight = Flight(leaves)
        bad = flight.certificate[:7] + b'\x00\x00\x00' + flight.certificate[10:]
        reject('certificate-entry-length', flight, 1, 50, 'certificate-decode', [flight.server_hello, bad])
        reject('certificate-seventeen', Flight(leaves, chain=[leaves['p256'][1]] * 17), 1, 50, 'certificate-decode')

        # ServerKeyExchange: parse, offered parameters and signature input.
        exchange_rejects = [
            ('tampered-signature', dict(tamper=True), 51, 'server-key-exchange-signature'),
            ('swapped-randoms', dict(signed_randoms=bytes(range(100, 132)) + CLIENT_RANDOM), 51, 'server-key-exchange-signature'),
            ('other-key', dict(signer=ec.generate_private_key(ec.SECP256R1())), 51, 'server-key-exchange-signature'),
            ('signed-other-scheme', dict(sign_scheme=0x0503), 51, 'server-key-exchange-signature'),
            ('explicit-curve', dict(curve=1), 47, 'server-key-exchange-curve-type'),
            ('secp384r1', dict(named=24), 47, 'unoffered-group'),
            ('short-point', dict(point=bytes(31)), 47, 'invalid-key-share'),
            ('compressed-p256', dict(named=23, point=b'\x02' + bytes(64)), 47, 'invalid-key-share'),
        ]
        for name, change, alert, reason in exchange_rejects:
            reject('exchange-' + name, Flight(leaves, **change), 2, alert, reason)
        reject('exchange-unoffered-scheme', Flight(leaves, scheme=0x0603), 2, 47, 'unoffered-signature-scheme')
        reject('exchange-rsa-scheme-on-ecdsa-suite', Flight(leaves, suite=0xC02B, leaf='p256', scheme=0x0804, signer=leaves['rsa'][0]), 2, 47, 'signature-scheme-suite')
        reject('exchange-ecdsa-scheme-on-rsa-suite', Flight(leaves, suite=0xC02F, leaf='rsa', scheme=0x0403, signer=leaves['p256'][0]), 2, 47, 'signature-scheme-suite')
        flight = Flight(leaves)
        reject('exchange-truncated', flight, 2, 50, 'server-key-exchange',
               [flight.server_hello, flight.certificate, hs(12, flight.exchange[4:-1])])
        reject('exchange-trailing', flight, 2, 50, 'server-key-exchange',
               [flight.server_hello, flight.certificate, hs(12, flight.exchange[4:] + b'\x00')])
        zero = Flight(leaves, point=bytes(32))
        lines = zero.expected()[0]
        run('exchange-x25519-zero-shared', zero, zero.server_messages(), lines[:3] + ['fail:47:invalid-key-share'])
        off = Flight(leaves, group=23, point=b'\x04' + bytes(31) + b'\x01' + bytes(31) + b'\x01')
        lines = off.expected()[0]
        run('exchange-p256-off-curve', off, off.server_messages(), lines[:4] + ['fail:47:invalid-key-share'])

        # Ordering and the remaining server messages.
        flight = Flight(leaves)
        lines, server_finished, read = flight.expected()
        sh, cert, ske, shd = flight.server_messages()
        cases = [
            ('exchange-before-certificate', [sh, ske], lines[:1] + ['fail:10:handshake-order']),
            ('done-before-exchange', [sh, cert, shd], lines[:2] + ['fail:10:handshake-order']),
            ('ccs-before-exchange', [sh, cert, b''], lines[:2] + ['fail:10:unexpected-change-cipher-spec']),
            ('ccs-before-done', [sh, cert, ske, b''], lines[:3] + ['fail:10:unexpected-change-cipher-spec']),
            ('second-certificate-request', [sh, cert, ske, flight.request_message, flight.request_message], lines[:3] + ['continue', 'fail:10:handshake-order']),
            ('malformed-certificate-request', [sh, cert, ske, hs(13, b'\x00' + u16(b'\x04\x03') + u16(b''))], lines[:3] + ['fail:50:certificate-request']),
            ('nonempty-done', [sh, cert, ske, hs(14, b'\x00')], lines[:3] + ['fail:50:server-hello-done']),
            ('hello-request-in-handshake', [sh, hs(0, b'')], lines[:1] + ['fail:10:handshake-order']),
            ('session-ticket-unsolicited', [sh, cert, ske, shd, hs(4, bytes(6))], lines + ['fail:10:handshake-order']),
            ('finished-before-ccs', [sh, cert, ske, shd, server_finished], lines + ['fail:10:handshake-order']),
            ('second-ccs', [sh, cert, ske, shd, b'', b''], lines + [read, 'fail:10:unexpected-change-cipher-spec']),
            ('altered-finished', [sh, cert, ske, shd, b'', server_finished[:-1] + bytes([server_finished[-1] ^ 1])], lines + [read, 'fail:51:finished']),
            ('client-finished-echoed', [sh, cert, ske, shd, b'', hs(20, bytes.fromhex(lines[-2].split(':')[1])[4:])], lines + [read, 'fail:51:finished']),
            ('short-finished', [sh, cert, ske, shd, b'', hs(20, server_finished[4:-1])], lines + [read, 'fail:50:finished']),
            ('finished-then-more', [sh, cert, ske, shd, b'', hs(14, b'')], lines + [read, 'fail:10:handshake-order']),
        ]
        for name, messages, expected in cases:
            run('order-' + name, flight, messages, expected)
    report = dict(cases=len(rows), rows=rows)
    if a.report:
        a.report.parent.mkdir(parents=True, exist_ok=True)
        a.report.write_text(json.dumps(report, indent=2) + '\n')
    print(f'tls12 client transitions: {len(rows)} cases passed')


if __name__ == '__main__':
    main()
