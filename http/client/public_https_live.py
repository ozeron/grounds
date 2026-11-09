"""Opt-in, non-gating public HTTPS fetches through the native Bend HTTP client."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
HOSTS = ['example.com', 'www.google.com', 'letsencrypt.org', 'github.com', 'www.cloudflare.com']
# M6: EV leaves whose subjects carry jurisdiction/businessCategory/serialNumber
# (and street at GlobalSign); any HTTP status after verification counts.
HOSTS += ['www.digicert.com', 'www.globalsign.com', 'www.bankofamerica.com']
# plain-HTTP origins that redirect to HTTPS: the client follows the redirect
# (http to https is allowed; the reverse never is) and verifies the target
REDIRECTS = ['http://github.com/']
# an IPv6-only origin (AAAA, no A): fetched only when the host has a global
# IPv6 route, else recorded as unavailable (never counted as a failure)
IPV6_ONLY = ['ipv6.google.com']
SUITES = {4865: 'TLS_AES_128_GCM_SHA256', 4866: 'TLS_AES_256_GCM_SHA384', 4867: 'TLS_CHACHA20_POLY1305_SHA256',
          49195: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', 49196: 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
          49199: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 49200: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
          52392: 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256', 52393: 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256'}
# M7 TLS 1.2 targets (refuse TLS 1.3 as of 2026-11-08). `expect` is the
# answer prefix a correct client gives: ok (verified fetch), a certificate
# reason, or a negotiation failure (server alert or refused parameters).
# Observations only: a mismatch is reported, never gating.
TLS12_TARGETS = [
    ('https://registry.npmjs.org/', 'ok:'),
    ('https://badssl.com/', 'ok:'), ('https://sha256.badssl.com/', 'ok:'), ('https://ecc256.badssl.com/', 'ok:'),
    ('https://rsa2048.badssl.com/', 'ok:'), ('https://mozilla-modern.badssl.com/', 'ok:'),
    ('https://tls-v1-2.badssl.com:1012/', 'ok:'),
    ('https://expired.badssl.com/', 'error:tls:certificate:expired'),
    ('https://wrong.host.badssl.com/', 'error:tls:certificate:identity-mismatch'),
    ('https://self-signed.badssl.com/', 'error:tls:certificate:'),
    ('https://untrusted-root.badssl.com/', 'error:tls:certificate:'),
    ('https://incomplete-chain.badssl.com/', 'error:tls:certificate:'),
    ('https://rc4.badssl.com/', 'error:tls:peer-alert'), ('https://dh1024.badssl.com/', 'error:tls:peer-alert'),
    ('https://cbc.badssl.com/', 'error:tls:peer-alert'), ('https://3des.badssl.com/', 'error:tls:peer-alert'),
    ('https://static-rsa.badssl.com/', 'error:tls:peer-alert'), ('https://tls-v1-0.badssl.com:1010/', 'error:tls:peer-alert'),
]
GROUPS = {29: 'x25519', 23: 'secp256r1'}
SIGNATURES = {1027: 'ecdsa_secp256r1_sha256', 1283: 'ecdsa_secp384r1_sha384', 2052: 'rsa_pss_rsae_sha256', 2053: 'rsa_pss_rsae_sha384', 2054: 'rsa_pss_rsae_sha512',
              1025: 'rsa_pkcs1_sha256', 1281: 'rsa_pkcs1_sha384', 1537: 'rsa_pkcs1_sha512'}


def version(suite):
    return None if suite is None else ('TLSv1.3' if 4865 <= suite <= 4867 else 'TLSv1.2')


def global_ipv6():
    """Whether the OS has a route to a global IPv6 address: a UDP connect
    sends nothing, it only selects a route and a source address."""
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
            s.connect(('2001:4860:4860::8888', 53))
            return not s.getsockname()[0].startswith(('fe80', 'fd', 'fc', '::1'))
    except OSError:
        return False


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path)
    p.add_argument('--bundle', type=Path)
    p.add_argument('--system', action='store_true',
                   help='opt into Tr.from_system_bundle (SSL_CERT_FILE, then the fixed path list) instead of --bundle')
    p.add_argument('--report', type=Path, required=True)
    a = p.parse_args()
    report = dict(gating=False, results=[])
    if os.environ.get('GROUNDS_PUBLIC_HTTPS_LIVE') != '1':
        report.update(skipped=True, reason='Set GROUNDS_PUBLIC_HTTPS_LIVE=1 explicitly; public network never gates checks')
        print(report['reason'])
    else:
        assert a.binary and (a.bundle or a.system) and not (a.bundle and a.system), 'explicit binary and one of --bundle/--system required'
        report.update(binary=str(a.binary.resolve()), binary_sha256=hashlib.sha256(a.binary.read_bytes()).hexdigest(),
                      recorded_at=datetime.now(timezone.utc).isoformat(), diagnostic_overlay=True)
        if a.system:
            report.update(bundle='@system', ssl_cert_file=os.environ.get('SSL_CERT_FILE'))
        else:
            report.update(bundle=str(a.bundle.resolve()), bundle_sha256=hashlib.sha256(a.bundle.read_bytes()).hexdigest())
        argument = '@system' if a.system else str(a.bundle.resolve())
        targets = [(host, 'https://' + host + '/', []) for host in HOSTS] + [(url, url, ['follow']) for url in REDIRECTS]
        if os.environ.get('GROUNDS_PUBLIC_TLS12', '1') == '1':
            targets += [(url.split('/')[2], url, [], expect) for url, expect in TLS12_TARGETS]
        report['global_ipv6'] = global_ipv6()
        if report['global_ipv6']:
            targets += [(host, 'https://' + host + '/', ['follow']) for host in IPV6_ONLY]
        else:
            report['ipv6_only'] = [dict(host=host, unavailable='no global IPv6 route on this host') for host in IPV6_ONLY]
        for host, url, extra, *expected in targets:
            civil = int(time.time()) + 62135596800
            cmd = [str(a.binary.resolve()), str(ROOT / 'crypto/unicode32_nfkc.bin'), str(ROOT / 'crypto/unicode32_prepare.bin'), argument, str(civil), url] + extra
            start = time.monotonic()
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=25,
                                   env=dict(os.environ, BEND_LIBSSL='/nonexistent/m5-host-tls', GROUNDS_TLS_CA='/nonexistent/m5-host-ca'))
                lines = r.stdout.splitlines()
                negotiated = [list(map(int, line.split(':')[1:])) for line in lines if line.startswith('m5-negotiated:')]
                signatures = [int(line.split(':')[1]) for line in lines if line.startswith('m5-cv:')]
                answer = next((line for line in lines if line.startswith(('ok:', 'error:'))), '')
                loaded = next((line.split(':', 1)[1] for line in lines if line.startswith('system-bundle:')), None)
                verified = r.returncode == 0 and answer.startswith('ok:') and len(negotiated) == len(signatures) == 1
                pair = negotiated[0] if negotiated else [None, None]
                row = dict(host=host, url=url, followed_redirects=bool(extra), verified=verified, http_status=int(answer.split(':')[1]) if answer.startswith('ok:') else None,
                           version=version(pair[0]), suite=SUITES.get(pair[0], pair[0]), group=GROUPS.get(pair[1], pair[1]),
                           signature=SIGNATURES.get(signatures[0], signatures[0]) if signatures else None,
                           output=r.stdout, stderr=r.stderr, exit=r.returncode)
                if a.system:
                    row['system_bundle'] = loaded
                    if loaded and Path(loaded).is_file():
                        row['system_bundle_sha256'] = hashlib.sha256(Path(loaded).read_bytes()).hexdigest()
                if expected:
                    row.update(expect=expected[0], answer=answer, matched=answer.startswith(expected[0]))
            except (OSError, subprocess.TimeoutExpired) as e:
                row = dict(host=host, verified=False, error=repr(e))
                if expected:
                    row.update(expect=expected[0], matched=False)
            row['elapsed_seconds'] = time.monotonic() - start
            report['results'].append(row)
            a.report.parent.mkdir(parents=True, exist_ok=True)
            a.report.write_text(json.dumps(report, indent=2) + '\n')
            print(json.dumps(row), flush=True)
        report['all_verified'] = all(r['verified'] for r in report['results'] if 'expect' not in r)
        report['tls12_matched'] = [r['host'] for r in report['results'] if r.get('matched')]
        report['tls12_unmatched'] = [r['host'] for r in report['results'] if 'expect' in r and not r.get('matched')]
    a.report.parent.mkdir(parents=True, exist_ok=True)
    a.report.write_text(json.dumps(report, indent=2) + '\n')
    # This diagnostic is deliberately never an internet availability CI gate.


if __name__ == '__main__':
    main()
