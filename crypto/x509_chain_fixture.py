"""Regenerate LOCAL SYNTHETIC public chain fixtures (cryptography, oracle only).

Run explicitly with Python cryptography >= 42. Keys exist only in this process;
the checked-in JSON contains public DER and test expectations, never keys.
Normal checks use stdlib Python and the independent OpenSSL CLI, not this file.
"""
from datetime import datetime, timezone
import base64
import ipaddress
import json
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.name import _ASN1Type
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier


def date(text):
    return datetime.fromisoformat(text).replace(tzinfo=timezone.utc)


NOW = date('2026-06-01T00:00:00')
START = date('2026-01-01T00:00:00')
END = date('2027-01-01T00:00:00')


def name(text, printable=False, oid=NameOID.COMMON_NAME):
    return x509.Name([x509.NameAttribute(oid, text, _type=(
        _ASN1Type.PrintableString if printable else _ASN1Type.UTF8String))])


def key(scheme):
    return (ec.generate_private_key(ec.SECP256R1()) if scheme == 'ecdsa' else
            rsa.generate_private_key(public_exponent=65537, key_size=2048))


def issue(subject, issuer, public, signer, scheme='ecdsa', *, ca=False,
          path=None, usage=True, signing=True, certsign=None, eku=None,
          san=None, before=None, after=None, extra=(), basic=True):
    if certsign is None:
        certsign = ca
    b = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
         .public_key(public.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(before or date('2020-01-01T00:00:00'))
         .not_valid_after(after or date('2035-01-01T00:00:00'))
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(public.public_key()), False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()), False))
    if basic:
        b = b.add_extension(x509.BasicConstraints(ca, path), critical=True)
    if usage:
        b = b.add_extension(x509.KeyUsage(signing, False, not signing, False,
            False, certsign, ca, False, False), True)
    if eku is not None:
        b = b.add_extension(x509.ExtendedKeyUsage(eku), True)
    if san is not None:
        b = b.add_extension(x509.SubjectAlternativeName(san), True)
    for extension, critical in extra:
        b = b.add_extension(extension, critical)
    opts = {'rsa_padding': padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)} if scheme == 'pss' else {}
    return b.sign(signer, hashes.SHA256(), **opts).public_bytes(serialization.Encoding.DER)


def tlv(tag, body):
    size = len(body)
    length = bytes([size]) if size < 128 else bytes([0x80 | ((size.bit_length() + 7) // 8)]) + size.to_bytes((size.bit_length() + 7) // 8, 'big')
    return bytes([tag]) + length + body


def fields(data):
    result = []
    while data:
        tag, size, at = data[0], data[1], 2
        if size & 128:
            width = size & 127
            size = int.from_bytes(data[at:at + width], 'big'); at += width
        result.append((tag, data[at:at + size], data[:at + size]))
        data = data[at + size:]
    return result


def legacy_version(cert, signer, scheme, version):
    """Re-sign a real v1/v2 TBS: omit extensions, omit default v1 version."""
    outer = fields(fields(cert)[0][1])
    tbs = fields(outer[0][1])
    assert tbs[0][0] == 160
    body = b''.join(encoded for tag, _, encoded in tbs[1:] if tag != 163)
    if version == 1:
        body = tlv(160, b'\x02\x01\x01') + body
    encoded = tlv(48, body)
    signature = (signer.sign(encoded, ec.ECDSA(hashes.SHA256())) if scheme == 'ecdsa' else
                 signer.sign(encoded, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
                             if scheme == 'pss' else padding.PKCS1v15(), hashes.SHA256()))
    return tlv(48, encoded + outer[1][2] + tlv(3, b'\x00' + signature))


def main():
    certificates, cases = {}, []

    def save(label, der):
        assert label not in certificates
        certificates[label] = base64.b64encode(der).decode()
        return label

    def row(label, presented, anchors, expected='success', *, identity='service.example',
            kind='dns', now=NOW, openssl=None, oracle_path=None):
        # None means the independent verifier should agree on acceptance.
        cases.append(dict(label=label, presented=presented, anchors=anchors,
            identity=identity, kind=kind, now=int(now.timestamp()), expected=expected,
            openssl_accept=(expected == 'success' if openssl is None else openssl)))
        if oracle_path is not None:
            cases[-1]['oracle_path'] = oracle_path

    sans = [x509.DNSName('service.example'), x509.DNSName('*.wild.example'),
            x509.IPAddress(ipaddress.ip_address('192.0.2.4')),
            x509.IPAddress(ipaddress.ip_address('2001:db8::4'))]
    server = [ExtendedKeyUsageOID.SERVER_AUTH]
    for scheme in ('ecdsa', 'v15', 'pss'):
        rootkey, cakey, leafkey = (key(scheme) for _ in range(3))
        rn, cn, ln = (name(f'{scheme} {part}') for part in ('Root', 'CA', 'Leaf'))
        root = save(f'{scheme}-root', issue(rn, rn, rootkey, rootkey, scheme, ca=True, path=6))
        ca = save(f'{scheme}-ca', issue(cn, rn, cakey, rootkey, scheme, ca=True, path=0))

        def leaf(label, **opts):
            kw = dict(eku=server, san=sans, before=START, after=END)
            kw.update(opts)
            return save(f'{scheme}-{label}', issue(ln, cn, leafkey, cakey, scheme, **kw))

        good = leaf('leaf')
        row(f'{scheme}/dns', [good, ca, root], [root])
        row(f'{scheme}/anchor-not-presented', [good, ca], [root])
        row(f'{scheme}/ip4', [good, ca], [root], identity='192.0.2.4', kind='ip')
        row(f'{scheme}/ip6', [good, ca], [root], identity='2001:db8::4', kind='ip')
        row(f'{scheme}/wildcard', [good, ca], [root], identity='one.wild.example')
        row(f'{scheme}/wildcard-multiple-labels', [good, ca], [root], 'identity-mismatch', identity='two.one.wild.example')
        row(f'{scheme}/case-insensitive-dns', [good, ca], [root], identity='SERVICE.EXAMPLE')
        row(f'{scheme}/wrong-issuer', [good], [root], 'wrong-issuer')
        wrongname = save(f'{scheme}-wrong-issuer-name', issue(ln, name('Wrong Issuer'), leafkey, cakey, scheme, eku=server, san=sans))
        row(f'{scheme}/valid-signature-wrong-issuer-name', [wrongname, ca], [root], 'wrong-issuer')
        row(f'{scheme}/no-anchors', [good, ca, root], [], 'untrusted')
        alienkey = key(scheme)
        alienname = name(f'{scheme} Other Root')
        alien = save(f'{scheme}-alien', issue(alienname, alienname, alienkey, alienkey, scheme, ca=True))
        row(f'{scheme}/untrusted-peer-root', [good, ca, root], [alien], 'untrusted')
        bad = bytearray(base64.b64decode(certificates[good])); bad[-1] ^= 1
        bad = save(f'{scheme}-flipped-signature', bytes(bad))
        row(f'{scheme}/signature-bit', [bad, ca], [root], 'bad-signature')
        changed = base64.b64decode(certificates[good]).replace(b'Leaf', b'leaf', 1)
        assert changed != base64.b64decode(certificates[good])
        changed = save(f'{scheme}-changed-tbs', changed)
        row(f'{scheme}/tbs-case-bit', [changed, ca], [root], 'bad-signature')
        row(f'{scheme}/not-before-minus-one', [good, ca], [root], 'not-yet-valid', now=date('2025-12-31T23:59:59'))
        row(f'{scheme}/not-before-exact', [good, ca], [root], now=START)
        row(f'{scheme}/not-before-plus-one', [good, ca], [root], now=date('2026-01-01T00:00:01'))
        row(f'{scheme}/not-after-minus-one', [good, ca], [root], now=date('2026-12-31T23:59:59'))
        row(f'{scheme}/not-after-exact', [good, ca], [root], now=END, openssl=False)
        row(f'{scheme}/not-after-plus-one', [good, ca], [root], 'expired', now=date('2027-01-01T00:00:01'))
        row(f'{scheme}/wrong-dns', [good, ca], [root], 'identity-mismatch', identity='other.example')
        row(f'{scheme}/wrong-ip', [good, ca], [root], 'identity-mismatch', identity='192.0.2.5', kind='ip')
        row(f'{scheme}/wrong-ip6', [good, ca], [root], 'identity-mismatch', identity='2001:db8::5', kind='ip')
        cnonly = save(f'{scheme}-cn-only', issue(name('service.example'), cn, leafkey, cakey, scheme, eku=server))
        row(f'{scheme}/no-cn-fallback', [cnonly, ca], [root], 'identity-mismatch', openssl=True)
        row(f'{scheme}/leaf-ku', [leaf('leaf-ku', signing=False), ca], [root], 'key-usage', openssl=True)
        row(f'{scheme}/leaf-eku', [leaf('leaf-eku', eku=[ExtendedKeyUsageOID.CLIENT_AUTH]), ca], [root], 'eku')
        row(f'{scheme}/any-eku', [leaf('any-eku', eku=[ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE]), ca], [root], 'eku', openssl=False)
        unknown = x509.UnrecognizedExtension(ObjectIdentifier('1.3.6.1.4.1.55555.1'), b'\x05\x00')
        row(f'{scheme}/critical', [leaf('critical', extra=[(unknown, True)]), ca], [root], 'unsupported-critical-extension')
        row(f'{scheme}/noncritical', [leaf('noncritical', extra=[(unknown, False)]), ca], [root])
        row(f'{scheme}/unsupported-critical-san', [leaf('email-san', san=[*sans, x509.RFC822Name('test@example.com')]), ca], [root], 'unsupported-critical-extension', openssl=True)
        unfamiliar = save(f'{scheme}-unknown-name', issue(name('leaf', oid=ObjectIdentifier('1.2.3.4')), cn, leafkey, cakey, scheme, eku=server, san=sans))
        row(f'{scheme}/unsupported-name', [unfamiliar, ca], [root], 'unsupported-name', openssl=True)

        for label, kw, expected, oracle in [
            ('not-ca', dict(ca=False, certsign=False), 'ca-basic-constraints', False),
            ('missing-bc', dict(ca=True, basic=False, certsign=False), 'ca-basic-constraints', False),
            ('missing-ku', dict(ca=True, usage=False), 'key-usage', True),
            ('no-certsign', dict(ca=True, certsign=False), 'key-usage', False),
            ('ca-eku', dict(ca=True, eku=[ExtendedKeyUsageOID.CLIENT_AUTH]), 'eku', False),
            ('ca-expired', dict(ca=True, after=date('2026-05-31T23:59:59')), 'expired', False),
            ('ca-future', dict(ca=True, before=date('2026-06-01T00:00:01')), 'not-yet-valid', False),
            ('ca-critical', dict(ca=True, extra=[(unknown, True)]), 'unsupported-critical-extension', False),
        ]:
            alt = save(f'{scheme}-{label}', issue(cn, rn, cakey, rootkey, scheme, **kw))
            row(f'{scheme}/{label}', [good, alt], [root], expected, openssl=oracle)
        for version in (0, 1):
            old = save(f'{scheme}-v{version+1}', legacy_version(base64.b64decode(certificates[ca]), rootkey, scheme, version))
            row(f'{scheme}/v{version+1}-intermediate', [good, old], [root], 'ca-basic-constraints', openssl=False)

        zero = save(f'{scheme}-root-zero', issue(rn, rn, rootkey, rootkey, scheme, ca=True, path=0))
        row(f'{scheme}/pathlen', [good, ca], [zero], 'path-length')
        direct = save(f'{scheme}-direct', issue(ln, rn, leafkey, rootkey, scheme, eku=server, san=sans))
        row(f'{scheme}/direct-anchor', [direct], [zero])
        expiredroot = save(f'{scheme}-root-expired', issue(rn, rn, rootkey, rootkey, scheme, ca=True, after=date('2026-05-31T23:59:59')))
        row(f'{scheme}/anchor-expired', [good, ca], [expiredroot], 'expired')
        rootcritical = save(f'{scheme}-root-critical', issue(rn, rn, rootkey, rootkey, scheme, ca=True, extra=[(unknown, True)]))
        row(f'{scheme}/anchor-critical', [good, ca], [rootcritical], 'unsupported-critical-extension', openssl=False)

        # Name equality must survive the exact signed cross-encoded issuer DER.
        crosscn = name(f'  {scheme.upper()}   ca  ', printable=True)
        cross = save(f'{scheme}-cross-name', issue(ln, crosscn, leafkey, cakey, scheme, eku=server, san=sans))
        row(f'{scheme}/printable-utf8-case-space', [cross, ca], [root])
        rollover = save(f'{scheme}-rollover', issue(rn, name(f' {scheme.upper()}  ROOT ', True), cakey, rootkey, scheme, ca=True, path=0))
        rolledleaf = save(f'{scheme}-rolled-leaf', issue(ln, rn, leafkey, cakey, scheme, eku=server, san=sans))
        row(f'{scheme}/self-issued-rollover', [rolledleaf, rollover], [zero])
        decoy = save(f'{scheme}-decoy', issue(cn, rn, alienkey, rootkey, scheme, ca=True))
        row(f'{scheme}/backtrack-signature', [good, decoy, ca], [root])
        dead = save(f'{scheme}-dead', issue(cn, alienname, cakey, alienkey, scheme, ca=True))
        row(f'{scheme}/backtrack-path', [good, dead, ca], [root], openssl=False, oracle_path=[good, ca])
        row(f'{scheme}/backtrack-expired', [good, f'{scheme}-ca-expired', ca], [root])
        row(f'{scheme}/unordered-peer-chain', [good, root, ca], [root])
        row(f'{scheme}/duplicate-peer', [good, ca, ca], [root], 'duplicate', openssl=True)
        row(f'{scheme}/duplicate-anchor', [good, ca], [root, root], 'duplicate', openssl=True)
        for critical in (False, True):
            nc = x509.NameConstraints([x509.DNSName('example')], None)
            constrained = save(f'{scheme}-nc-{critical}', issue(cn, rn, cakey, rootkey, scheme, ca=True, extra=[(nc, critical)]))
            row(f'{scheme}/name-constraints-{critical}', [good, constrained], [root], 'unsupported-name-constraints', openssl=True)
        for i in (0, 1, 2, 3, 8, len(base64.b64decode(certificates[good])) // 2, -1):
            data = base64.b64decode(certificates[good])[:i]
            truncated = save(f'{scheme}-truncated-{i}', data)
            row(f'{scheme}/truncated-{i}', [truncated, ca], [root], 'malformed', openssl=False)
        trailing = save(f'{scheme}-trailing', base64.b64decode(certificates[good]) + b'\x00')
        row(f'{scheme}/trailing-der', [trailing, ca], [root], 'malformed', openssl=True)

        if scheme != 'ecdsa':
            continue
        # A real signed two-CA cycle with a separate, explicit unrelated anchor.
        an, bn = name('Cycle A'), name('Cycle B')
        a = save('cycle-a', issue(an, bn, cakey, alienkey, ca=True))
        b = save('cycle-b', issue(bn, an, alienkey, cakey, ca=True))
        cyc = save('cycle-leaf', issue(ln, an, leafkey, cakey, eku=server, san=sans))
        row('ecdsa/cycle', [cyc, a, b], [root], 'cycle')
        # Reuse only public-key identities along differently named synthetic CAs.
        for n in (6, 7):
            chain, issuername, signer = [], rn, rootkey
            for i in range(n):
                nn = name(f'Depth {n} CA {i}')
                item = save(f'depth-{n}-{i}', issue(nn, issuername, cakey, signer, ca=True))
                chain.insert(0, item); issuername, signer = nn, cakey
            item = save(f'depth-{n}-leaf', issue(ln, issuername, leafkey, signer, eku=server, san=sans))
            depthroot = save(f'depth-{n}-root', issue(rn, rn, rootkey, rootkey, ca=True))
            row(f'ecdsa/depth-{n+2}', [item, *chain], [depthroot], 'success' if n == 6 else 'depth-limit', openssl=True)

    # Bounded adversarial ambiguity: many same-Name/same-key but distinct
    # self-issued certificates. The global work limit must survive backtracking.
    sk, lk = key('v15'), key('v15')
    sn = name('Search loop')
    aliases = [save(f'search-{i}', issue(sn, sn, sk, sk, 'v15', ca=True)) for i in range(15)]
    sl = save('search-leaf', issue(name('search leaf'), sn, lk, sk, 'v15', eku=server, san=sans))
    row('search-budget', [sl, *aliases], ['v15-root'], 'search-limit', openssl=False)
    row('peer-input-limit', [sl, *aliases, 'v15-root'], ['v15-root'], 'input-limit', openssl=False)
    row('anchor-input-limit', ['v15-leaf', 'v15-ca'], [*aliases, 'v15-root', 'v15-alien'], 'input-limit', openssl=True)

    row('empty-peer', [], [], 'malformed', openssl=False)
    output = dict(provenance='LOCAL SYNTHETIC; Python cryptography generator; no external credentials',
                  certificates=certificates, cases=cases)
    path = Path(__file__).with_name('x509_chain_vectors.json')
    path.write_text(json.dumps(output, indent=2) + '\n')
    print(f'{len(certificates)} public certificates; {len(cases)} complete-chain cases -> {path}')


if __name__ == '__main__':
    main()
