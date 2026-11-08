"""Opt-in system CA bundle: admission policy and path resolution (native only).

Admission (`system-bytes`, Bundle.decode.system) differs from the explicit
APIs in two ways only: byte-identical duplicates are dropped, and OpenSSL
TRUSTED CERTIFICATE blocks never become anchors, but their trust settings
are honoured: a block that rejects serverAuth or anyExtendedKeyUsage, or
whose trust list has neither, removes every plain copy of its exact
certificate. A TRUSTED block whose certificate or AUX trailer does not
parse, malformed entries, unknown labels and the 2 MiB / 256-block limits
reject the whole load. Path resolution (`system`, `system-env`): a
non-empty SSL_CERT_FILE replaces the candidate list; the first candidate
that opens is the bundle, with no fall-through after it opens.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / 'crypto'))
from pem_bundle_check import BUNDLE, BUNDLE_SHA256, certificates, nested, pem  # noqa: E402
from x509_algorithm_check import tlv  # noqa: E402

DEFAULT_PATHS = ['/etc/ssl/certs/ca-certificates.crt', '/etc/pki/tls/certs/ca-bundle.crt',
                 '/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem', '/etc/ssl/ca-bundle.pem', '/etc/ssl/cert.pem']
SERVER_AUTH = bytes.fromhex('2b06010505070301')
EMAIL = bytes.fromhex('2b06010505070304')
CODE_SIGNING = bytes.fromhex('2b06010505070303')
ANY_EKU = bytes.fromhex('551d2500')


def aux(trust=None, reject=None, alias=None, keyid=None):
    """OpenSSL X509_CERT_AUX: trust SEQUENCE OF OID, reject [0] IMPLICIT
    SEQUENCE OF OID, alias UTF8String, keyid OCTET STRING, all optional."""
    body = b''
    if trust is not None:
        body += tlv(0x30, b''.join(tlv(6, o) for o in trust))
    if reject is not None:
        body += tlv(0xa0, b''.join(tlv(6, o) for o in reject))
    if alias is not None:
        body += tlv(0x0c, alias)
    if keyid is not None:
        body += tlv(0x04, keyid)
    return tlv(0x30, body)


# X509_CERT_AUX { trust: [serverAuth] }, as OpenSSL writes after the DER.
SERVER_AUTH_AUX = aux(trust=[SERVER_AUTH])
assert SERVER_AUTH_AUX == bytes.fromhex('300c300a06082b06010505070301')
REJECT_SERVER_AUTH = aux(trust=[SERVER_AUTH], reject=[SERVER_AUTH])


def trusted(raw, aux=SERVER_AUTH_AUX):
    return (b'-----BEGIN TRUSTED CERTIFICATE-----\n' + base64.encodebytes(raw + aux)
            + b'-----END TRUSTED CERTIFICATE-----\n')


def admission_cases():
    data = BUNDLE.read_bytes()
    roots = certificates(data)
    good, other = pem(roots[0]), pem(roots[1])
    expanded = [pem(roots[0][:-2] + i.to_bytes(2, 'big')) for i in range(257)]
    # NixOS shape: each root followed by its trust-annotated copy, plus
    # email-only TRUSTED blocks (some with rejections, as in NixOS 26.05's
    # bundle) for certificates that are not plain entries.
    nixos = b''.join(b'# root\n' + pem(r) + b'\nTrusted for:\n  - serverAuth\n' + trusted(r) for r in roots)
    nixos += b''.join(trusted(r[:-2] + b'\xee\xee', bytes.fromhex('300c300a06082b06010505070304')) for r in roots[:40])
    nixos += b''.join(trusted(r[:-2] + b'\xef\xef', aux(trust=[EMAIL], reject=[SERVER_AUTH, CODE_SIGNING]))
                      for r in roots[40:44])
    # Rejections are honoured for the exact certificate, in either order,
    # and remove every plain copy; any AUX that does not parse fails the load.
    a, b = roots[0], roots[1]
    reject_a = trusted(a, REJECT_SERVER_AUTH)
    bad_aux = [
        ('aux-not-sequence', bytes.fromhex('0400')),
        ('aux-truncated', REJECT_SERVER_AUTH[:-1]),
        ('aux-trailing', REJECT_SERVER_AUTH + b'\x00'),
        ('aux-second-sequence', SERVER_AUTH_AUX + SERVER_AUTH_AUX),
        ('aux-unknown-field', tlv(0x30, tlv(0x02, b'\x01'))),
        ('aux-out-of-order', tlv(0x30, tlv(0xa0, tlv(6, SERVER_AUTH)) + tlv(0x30, tlv(6, SERVER_AUTH)))),
        ('aux-repeated-trust', tlv(0x30, tlv(0x30, tlv(6, SERVER_AUTH)) * 2)),
        ('aux-reject-noncanonical-oid', aux(reject=[bytes.fromhex('8001')])),
        ('aux-reject-not-oid', tlv(0x30, tlv(0xa0, b'\x05\x00'))),
        ('aux-trust-truncated-oid', tlv(0x30, tlv(0x30, b'\x06\x05\x2b\x06'))),
    ]
    bad = good.replace(b'\n', b'\n!', 1)
    malformed_spki = pem(nested(roots[1], 'spki', bytes.fromhex('3013300c06072a8648ce3d02010601800303000000')))
    return [
        ('snapshot', data, f'ok:{len(roots)}'),
        ('snapshot-twice', data + data, f'ok:{len(roots)}'),
        ('nixos-shape', nixos, f'ok:{len(roots)}'),
        ('duplicate', good + good, 'ok:1'),
        ('duplicate-nonadjacent', good + other + good, 'ok:2'),
        ('duplicate-crlf', good + good.replace(b'\n', b'\r\n'), 'ok:1'),
        ('trusted-skipped', good + trusted(roots[1]), 'ok:1'),
        ('trusted-same-certificate', trusted(roots[0]) + good, 'ok:1'),
        ('trusted-no-aux', trusted(roots[1], b'') + good, 'ok:1'),
        ('trusted-only', trusted(roots[0]) + trusted(roots[1]), 'empty-bundle'),
        ('trusted-unparsed-body', b'-----BEGIN TRUSTED CERTIFICATE-----\nnot base64\n-----END TRUSTED CERTIFICATE-----\n' + good, 'malformed-bundle'),
        ('trusted-not-certificate', b'-----BEGIN TRUSTED CERTIFICATE-----\nAgEA\n-----END TRUSTED CERTIFICATE-----\n' + good, 'malformed-bundle'),
        ('reject-after', pem(a) + pem(b) + reject_a, 'ok:1'),
        ('reject-first', reject_a + pem(a) + pem(b), 'ok:1'),
        ('reject-duplicates-removed', pem(a) + pem(b) + pem(a) + reject_a, 'ok:1'),
        ('reject-only-anchor', pem(a) + reject_a, 'empty-bundle'),
        ('reject-any-eku', pem(a) + pem(b) + trusted(a, aux(reject=[ANY_EKU])), 'ok:1'),
        ('reject-among-others', pem(a) + pem(b) + trusted(a, aux(trust=[EMAIL], reject=[CODE_SIGNING, SERVER_AUTH])), 'ok:1'),
        ('reject-other-purpose', pem(a) + pem(b) + trusted(a, aux(trust=[SERVER_AUTH], reject=[EMAIL])), 'ok:2'),
        ('reject-unrelated-certificate', pem(a) + pem(b) + trusted(a[:-2] + b'\xee\xee', REJECT_SERVER_AUTH), 'ok:2'),
        # A trust list without serverAuth or anyExtendedKeyUsage also
        # withholds TLS server trust (OpenSSL: X509_TRUST_UNTRUSTED).
        ('trust-email-only', pem(a) + pem(b) + trusted(a, aux(trust=[EMAIL])), 'ok:1'),
        ('trust-empty-list', pem(a) + pem(b) + trusted(a, aux(trust=[])), 'ok:1'),
        ('trust-any-eku', pem(a) + pem(b) + trusted(a, aux(trust=[ANY_EKU])), 'ok:2'),
        ('aux-empty', pem(a) + pem(b) + trusted(a, aux()), 'ok:2'),
        ('aux-alias-keyid', pem(a) + pem(b) + trusted(a, aux(trust=[SERVER_AUTH], alias=b'Root', keyid=b'\x01\x02')), 'ok:2'),
        ('aux-alias-reject', pem(a) + pem(b) + trusted(a, aux(reject=[SERVER_AUTH], alias=b'Root')), 'ok:1'),
        *[(name, pem(a) + pem(b) + trusted(a, value), 'malformed-bundle') for name, value in bad_aux],
        *[(name + '-unrelated', pem(a) + pem(b) + trusted(a[:-2] + b'\xee\xee', value), 'malformed-bundle')
          for name, value in bad_aux],
        ('trusted-missing-end', good + trusted(roots[1]).split(b'-----END')[0], 'malformed-bundle'),
        ('trusted-wrong-end', good + trusted(roots[1]).replace(b'END TRUSTED CERTIFICATE', b'END CERTIFICATE'), 'malformed-bundle'),
        ('trusted-nested-begin', trusted(roots[1]).replace(b'-----END TRUSTED', good + b'-----END TRUSTED') + good, 'malformed-bundle'),
        ('trusted-malformed-delimiter', b'-----BEGIN TRUSTED CERTIFICATE----\n' + good, 'malformed-bundle'),
        ('unknown-label', good + pem(roots[1]).replace(b'CERTIFICATE', b'X509 CRL'), 'malformed-bundle'),
        ('bad-base64', good + bad, 'malformed-bundle'),
        ('malformed-after-duplicate', good + good + malformed_spki, 'malformed-bundle'),
        ('malformed-spki', malformed_spki + good, 'malformed-bundle'),
        ('empty', b'', 'empty-bundle'),
        ('scale-256', b''.join(expanded[:256]), 'ok:256'),
        ('scale-257', b''.join(expanded), 'bundle-limit'),
        # The cap counts CERTIFICATE blocks, duplicates included.
        ('scale-256-plus-duplicate', b''.join(expanded[:256]) + expanded[0], 'bundle-limit'),
        ('trusted-not-counted', b''.join(trusted(r) for r in roots) * 3 + good, 'ok:1'),
        ('text-overflow', good + b' ' * (2097153 - len(good)), 'bundle-limit'),
    ]


def run(binary, args, env=None):
    start = time.monotonic()
    r = subprocess.run([str(binary)] + args, capture_output=True, text=True, timeout=25,
                       env=env if env is not None else os.environ)
    return r, time.monotonic() - start


def openssl_verify(bundle, chain, peers, directory):
    """OpenSSL 3's own verdict on the same bundle, chain, time and name."""
    leaf = directory / 'leaf.pem'
    leaf.write_bytes(pem(peers[0]))
    intermediates = directory / 'intermediates.pem'
    intermediates.write_bytes(b''.join(map(pem, peers[1:])))
    r = subprocess.run(['openssl', 'verify', '-no-CApath', '-no-CAstore', '-CAfile', str(bundle),
                        '-purpose', 'sslserver', '-attime', str(chain['now']), '-verify_hostname',
                        chain['hostname'], '-untrusted', str(intermediates), str(leaf)],
                       capture_output=True, text=True, timeout=20)
    return dict(exit=r.returncode, output=(r.stdout + r.stderr).strip())


def chain_main(binary, report):
    """The pinned github.com chain against system bundles whose TRUSTED
    blocks reject serverAuth for the chain's roots (removed_anchor_indices:
    the self-signed root and the root cross-signing it). The rejected roots
    are dropped in either order. OpenSSL keeps the first copy of a
    certificate it reads, so it rejects the chain only when the rejecting
    block comes first; Bend admission is stricter (fail closed)."""
    from public_chain_check import CORPUS, fixture, inputs
    manifest, bundle, roots = inputs()
    chain = next(c for c in manifest['chains'] if c['label'] == 'github.com')
    peers = [certificates((CORPUS / c['file']).read_bytes())[0] for c in chain['certificates']]
    data = bundle.read_bytes()
    removed = chain['removed_anchor_indices']
    rejecting = b''.join(trusted(roots[i], REJECT_SERVER_AUTH) for i in removed)
    email = b''.join(trusted(roots[i], aux(trust=[EMAIL])) for i in removed)
    serving = b''.join(trusted(roots[i]) for i in removed)
    untrusted = chain['untrusted_result']
    version = subprocess.run(['openssl', 'version'], capture_output=True, text=True).stdout.strip()
    assert version.startswith('OpenSSL 3.'), version
    # name, bundle, Bend result, OpenSSL exit (0 verified)
    cases = [
        ('plain', data, 'success', 0),
        ('trusted-serverauth-after', data + serving, 'success', 0),
        ('reject-first', rejecting + data, untrusted, 2),
        ('reject-after', data + rejecting, untrusted, 0),
        ('trust-email-first', email + data, untrusted, 2),
        ('trust-email-after', data + email, untrusted, 0),
    ]
    results = []
    with tempfile.TemporaryDirectory(prefix='grounds-system-chain-') as td:
        d = Path(td)
        case = d / 'github.bin'
        case.write_bytes(fixture(chain['now'], chain['hostname'], peers))
        crypto = Path(__file__).resolve().parents[3] / 'crypto'
        for name, value, expected, openssl_exit in cases:
            path = d / (name + '.pem')
            path.write_bytes(value)
            r, seconds = run(binary, [str(crypto / 'unicode32_nfkc.bin'), str(crypto / 'unicode32_prepare.bin'),
                                      'system', str(path), str(case)])
            answer = r.stdout.strip()
            assert r.returncode == 0 and answer.split(':')[0] == expected, (name, answer, expected, r.stderr[-1000:])
            oracle = openssl_verify(path, chain, peers, d)
            assert oracle['exit'] == openssl_exit, (name, oracle)
            results.append(dict(name=name, result=answer.split(':')[0], expected=expected, seconds=seconds,
                                openssl=oracle))
    out = dict(passed=True, cases=len(results), chain='github.com', removed_anchor_indices=removed,
               openssl_version=version, results=results)
    destination = report or (Path(os.environ['GROUNDS_M5_REPORT_DIR']) / 'system-bundle-chain.json'
                             if os.environ.get('GROUNDS_M5_REPORT_DIR') else None)
    if destination:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(out, indent=2) + '\n')
    print(f'System bundle trust settings on github.com: {len(results)} passed; {version}')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--report', type=Path)
    p.add_argument('--chain', action='store_true', help='binary is tests/public_chain.bend')
    p.add_argument('binary', type=Path)
    a = p.parse_args()
    if a.chain:
        return chain_main(a.binary, a.report)
    results = []

    def record(name, mode, answer, expected, seconds):
        results.append(dict(name=name, mode=mode, result=answer, expected=expected, seconds=seconds))

    with tempfile.TemporaryDirectory(prefix='grounds-system-bundle-') as td:
        d = Path(td)
        for name, data, expected in admission_cases():
            path = d / (name + '.pem')
            path.write_bytes(data)
            for mode in ('system-bytes', 'system'):
                args = [mode, str(path)] if mode == 'system-bytes' else [mode, '', str(path)]
                r, seconds = run(a.binary, args)
                answer = r.stdout.strip()
                actual = ':'.join(answer.split(':')[:2]) if answer.startswith('ok:') else answer
                assert r.returncode == 0 and actual == expected, (name, mode, answer, expected, r.stderr[-1000:])
                if mode == 'system' and answer.startswith('ok:'):
                    assert answer.split(':', 3)[3] == str(path), (name, answer)
                record(name, mode, actual, expected, seconds)
            # The explicit APIs keep rejecting duplicates and TRUSTED blocks.
            if name in ('duplicate', 'trusted-skipped', 'nixos-shape'):
                r, seconds = run(a.binary, ['bytes', str(path)])
                want = 'duplicate-anchor' if name == 'duplicate' else 'malformed-bundle'
                assert r.returncode == 0 and r.stdout.strip() == want, (name, r.stdout, r.stderr[-1000:])
                record(name, 'bytes', r.stdout.strip(), want, seconds)

        snap = d / 'a.pem'
        snap.write_bytes(BUNDLE.read_bytes())
        one = d / 'b.pem'
        one.write_bytes(pem(certificates(BUNDLE.read_bytes())[0]))
        bad = d / 'bad.pem'
        bad.write_bytes(b'-----BEGIN CERTIFICATE-----\n!!\n-----END CERTIFICATE-----\n')
        big = d / 'big.pem'
        big.write_bytes(one.read_bytes() + b' ' * 2097152)
        locked = d / 'locked.pem'
        locked.write_bytes(one.read_bytes())
        locked.chmod(0)
        missing = str(d / 'missing.pem')
        n = len(certificates(BUNDLE.read_bytes()))
        paths = [
            ('first-wins', ['', str(snap), str(one)], f'ok:{n}', snap),
            ('missing-skipped', ['', missing, str(one), str(snap)], 'ok:1', one),
            ('none-exist', ['', missing, missing + '2'], 'no-system-bundle', None),
            ('empty-list', [''], 'no-system-bundle', None),
            ('override-replaces-list', [str(one), str(snap)], 'ok:1', one),
            ('override-missing-no-fallback', [missing, str(snap)], 'no-system-bundle', None),
            ('opened-malformed-no-fallthrough', ['', str(bad), str(snap)], 'malformed-bundle', None),
            ('opened-too-large-no-fallthrough', ['', str(big), str(snap)], 'bundle-limit', None),
        ]
        if os.geteuid() != 0:
            paths.append(('unreadable-skipped', ['', str(locked), str(one)], 'ok:1', one))
        for name, args, expected, chosen in paths:
            r, seconds = run(a.binary, ['system'] + args)
            answer = r.stdout.strip()
            actual = ':'.join(answer.split(':')[:2]) if answer.startswith('ok:') else answer
            assert r.returncode == 0 and actual == expected, (name, answer, expected, r.stderr[-1000:])
            if chosen:
                assert answer.split(':', 3)[3] == str(chosen), (name, answer)
            record(name, 'system', actual, expected, seconds)

        # from_system_bundle reads SSL_CERT_FILE itself.
        base = {k: v for k, v in os.environ.items() if k != 'SSL_CERT_FILE'}
        for name, value, expected, chosen in [
            ('env-override', str(one), 'ok:1', one),
            ('env-override-missing', missing, 'no-system-bundle', None),
            ('env-override-malformed', str(bad), 'malformed-bundle', None),
        ]:
            r, seconds = run(a.binary, ['system-env'], dict(base, SSL_CERT_FILE=value))
            answer = r.stdout.strip()
            actual = ':'.join(answer.split(':')[:2]) if answer.startswith('ok:') else answer
            assert r.returncode == 0 and actual == expected, (name, answer, expected, r.stderr[-1000:])
            if chosen:
                assert answer.split(':', 3)[3] == str(chosen), (name, answer)
            record(name, 'system-env', actual, expected, seconds)

        # Unset or empty SSL_CERT_FILE: the fixed list. The host's own bundle
        # is not a gate; only the chosen path's membership is checked.
        host = []
        for name, env in [('env-unset', base), ('env-empty', dict(base, SSL_CERT_FILE=''))]:
            r, seconds = run(a.binary, ['system-env'], env)
            answer = r.stdout.strip()
            assert r.returncode == 0, (name, answer, r.stderr[-1000:])
            if answer.startswith('ok:'):
                assert answer.split(':', 3)[3] in DEFAULT_PATHS, (name, answer)
            record(name, 'system-env', answer, 'host-dependent', seconds)
            host.append(answer)
        assert host[0] == host[1] or all(h.startswith('ok:') for h in host), host

    report = dict(passed=True, cases=len(results), bundle_sha256=BUNDLE_SHA256, default_paths=DEFAULT_PATHS,
                  host_default=host[0], results=results)
    destination = a.report or (Path(os.environ['GROUNDS_M5_REPORT_DIR']) / 'system-bundle.json'
                               if os.environ.get('GROUNDS_M5_REPORT_DIR') else None)
    if destination:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(report, indent=2) + '\n')
    print(f'Native system bundle policy: {len(results)} passed; host default: {host[0]}')


if __name__ == '__main__':
    main()
