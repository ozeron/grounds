"""Opt-in, non-gating public HTTPS fetches through the native Bend HTTP client."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
HOSTS = ['example.com', 'www.google.com', 'letsencrypt.org', 'github.com', 'www.cloudflare.com']
SUITES = {4865: 'TLS_AES_128_GCM_SHA256', 4866: 'TLS_AES_256_GCM_SHA384', 4867: 'TLS_CHACHA20_POLY1305_SHA256'}
GROUPS = {29: 'x25519', 23: 'secp256r1'}
SIGNATURES = {1027: 'ecdsa_secp256r1_sha256', 1283: 'ecdsa_secp384r1_sha384', 2052: 'rsa_pss_rsae_sha256', 2053: 'rsa_pss_rsae_sha384', 2054: 'rsa_pss_rsae_sha512'}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path)
    p.add_argument('--bundle', type=Path)
    p.add_argument('--report', type=Path, required=True)
    a = p.parse_args()
    report = dict(gating=False, results=[])
    if os.environ.get('GROUNDS_PUBLIC_HTTPS_LIVE') != '1':
        report.update(skipped=True, reason='Set GROUNDS_PUBLIC_HTTPS_LIVE=1 explicitly; public network never gates checks')
        print(report['reason'])
    else:
        assert a.binary and a.bundle, 'explicit binary and bundle required'
        report.update(binary=str(a.binary.resolve()), binary_sha256=hashlib.sha256(a.binary.read_bytes()).hexdigest(),
                      bundle=str(a.bundle.resolve()), bundle_sha256=hashlib.sha256(a.bundle.read_bytes()).hexdigest(),
                      recorded_at=datetime.now(timezone.utc).isoformat(), diagnostic_overlay=True)
        for host in HOSTS:
            civil = int(time.time()) + 62135596800
            cmd = [str(a.binary.resolve()), str(ROOT / 'crypto/unicode32_nfkc.bin'), str(ROOT / 'crypto/unicode32_prepare.bin'), str(a.bundle.resolve()), str(civil), 'https://' + host + '/']
            start = time.monotonic()
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=25,
                                   env=dict(os.environ, BEND_LIBSSL='/nonexistent/m5-host-tls', GROUNDS_TLS_CA='/nonexistent/m5-host-ca'))
                lines = r.stdout.splitlines()
                negotiated = [list(map(int, line.split(':')[1:])) for line in lines if line.startswith('m5-negotiated:')]
                signatures = [int(line.split(':')[1]) for line in lines if line.startswith('m5-cv:')]
                answer = next((line for line in lines if line.startswith(('ok:', 'error:'))), '')
                verified = r.returncode == 0 and answer.startswith('ok:') and len(negotiated) == len(signatures) == 1
                pair = negotiated[0] if negotiated else [None, None]
                row = dict(host=host, verified=verified, http_status=int(answer.split(':')[1]) if answer.startswith('ok:') else None,
                           suite=SUITES.get(pair[0], pair[0]), group=GROUPS.get(pair[1], pair[1]),
                           signature=SIGNATURES.get(signatures[0], signatures[0]) if signatures else None,
                           output=r.stdout, stderr=r.stderr, exit=r.returncode)
            except (OSError, subprocess.TimeoutExpired) as e:
                row = dict(host=host, verified=False, error=repr(e))
            row['elapsed_seconds'] = time.monotonic() - start
            report['results'].append(row)
            a.report.parent.mkdir(parents=True, exist_ok=True)
            a.report.write_text(json.dumps(report, indent=2) + '\n')
            print(json.dumps(row), flush=True)
        report['all_verified'] = all(r['verified'] for r in report['results'])
    a.report.parent.mkdir(parents=True, exist_ok=True)
    a.report.write_text(json.dumps(report, indent=2) + '\n')
    # This diagnostic is deliberately never an internet availability CI gate.


if __name__ == '__main__':
    main()
