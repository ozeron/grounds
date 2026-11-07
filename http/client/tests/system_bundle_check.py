"""Opt-in system CA bundle: admission policy and path resolution (native only).

Admission (`system-bytes`, Bundle.decode.system) differs from the explicit
APIs in two ways only: byte-identical duplicates are dropped, and exactly
framed OpenSSL TRUSTED CERTIFICATE blocks are skipped (never trusted).
Malformed entries, unknown labels and the 2 MiB / 256-block limits still
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

DEFAULT_PATHS = ['/etc/ssl/certs/ca-certificates.crt', '/etc/pki/tls/certs/ca-bundle.crt',
                 '/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem', '/etc/ssl/ca-bundle.pem', '/etc/ssl/cert.pem']
# X509_CERT_AUX { trust: [serverAuth] }, as OpenSSL writes after the DER.
SERVER_AUTH_AUX = bytes.fromhex('300c300a06082b06010505070301')


def trusted(raw, aux=SERVER_AUTH_AUX):
    return (b'-----BEGIN TRUSTED CERTIFICATE-----\n' + base64.encodebytes(raw + aux)
            + b'-----END TRUSTED CERTIFICATE-----\n')


def admission_cases():
    data = BUNDLE.read_bytes()
    roots = certificates(data)
    good, other = pem(roots[0]), pem(roots[1])
    expanded = [pem(roots[0][:-2] + i.to_bytes(2, 'big')) for i in range(257)]
    # NixOS shape: each root followed by its trust-annotated copy, plus
    # email-only TRUSTED blocks for certificates that are not plain entries.
    nixos = b''.join(b'# root\n' + pem(r) + b'\nTrusted for:\n  - serverAuth\n' + trusted(r) for r in roots)
    nixos += b''.join(trusted(r[:-2] + b'\xee\xee', bytes.fromhex('300c300a06082b06010505070304')) for r in roots[:40])
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
        ('trusted-unparsed-body', b'-----BEGIN TRUSTED CERTIFICATE-----\nnot base64\n-----END TRUSTED CERTIFICATE-----\n' + good, 'ok:1'),
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


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--report', type=Path)
    p.add_argument('binary', type=Path)
    a = p.parse_args()
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
