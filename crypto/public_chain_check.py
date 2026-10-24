"""Pinned public chains, fixed times, explicit Mozilla anchors; entirely offline."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import time

from pem_bundle_check import certificates, pem
import x509_algorithm_check as A
import x509_certificate_check as D

ROOT = Path(__file__).parent
CORPUS = ROOT / 'fixtures/public-chains'


def sequence(values):
    return struct.pack('>I', len(values)) + b''.join(struct.pack('>I', len(v)) + v for v in values)


def fixture(now, hostname, peers):
    stamp = datetime.fromtimestamp(now, timezone.utc).strftime('%Y%m%d%H%M%SZ').encode()
    return sequence([b'\x18\x0f' + stamp, b'\0' + hostname.encode(), sequence(peers)])


def unsupported(raw):
    # A well-framed unknown signature OID on both the TBS and outer signature.
    # No signature is synthesized; the admission decision must precede crypto.
    fields = D.elements(A.complete(raw, 48))
    outer = fields[1][2]
    oid = D.elements(A.complete(outer, 48))[0][2]
    changed = oid[:-1] + b'\x7f'
    assert oid in fields[0][2]
    return A.tlv(48, fields[0][2].replace(oid, changed, 1) + outer.replace(oid, changed, 1) + fields[2][2])


def inputs():
    manifest = json.loads((CORPUS / 'manifest.json').read_text())
    bundle = CORPUS / manifest['bundle_file']
    assert hashlib.sha256(bundle.read_bytes()).hexdigest() == manifest['bundle_sha256']
    roots = certificates(bundle.read_bytes())
    assert len(roots) == manifest['anchor_count']
    for chain in manifest['chains']:
        for c in chain['certificates']:
            raw = (CORPUS / c['file']).read_bytes()
            assert hashlib.sha256(raw).hexdigest() == c['sha256'], c['file']
    return manifest, bundle, roots


def cases(chain, roots):
    peers = [certificates((CORPUS / c['file']).read_bytes())[0] for c in chain['certificates']]
    removed = set(chain['removed_anchor_indices'])
    assert removed, chain['label']
    shortened = b''.join(pem(root) for i, root in enumerate(roots) if i not in removed)
    return [
        ('positive', chain['now'], chain['hostname'], peers, None, 'success'),
        ('wrong-host', chain['now'], 'wrong-host.invalid', peers, None, 'identity-mismatch'),
        ('expired', chain['expired_now'], chain['hostname'], peers, None, 'expired'),
        ('untrusted', chain['now'], chain['hostname'], peers, shortened, chain.get('untrusted_result', 'wrong-issuer')),
        ('unsupported-signature', chain['now'], chain['hostname'], [unsupported(peers[0]), *peers[1:]], None, 'unsupported-algorithm'),
    ]


def oracle(chain, name, now, host, peers, bundle, directory):
    leaf = directory / 'leaf.pem'; leaf.write_bytes(pem(peers[0]))
    intermediate = directory / 'intermediate.pem'; intermediate.write_bytes(b''.join(map(pem, peers[1:])))
    cmd = ['openssl', 'verify', '-no-CApath', '-no-CAstore', '-CAfile', str(bundle),
           '-purpose', 'sslserver', '-attime', str(now), '-verify_hostname', host]
    if len(peers) > 1:
        cmd += ['-untrusted', str(intermediate)]
    r = subprocess.run(cmd + [str(leaf)], capture_output=True, text=True, timeout=10)
    assert (r.returncode == 0) == (name == 'positive'), (chain['label'], name, r.stdout, r.stderr)
    return dict(exit=r.returncode, stdout=r.stdout, stderr=r.stderr)


def check(chain, bundle, roots, binary, directory, enforce=True):
    results = []
    for name, now, host, peers, changed_bundle, expected in cases(chain, roots):
        selected = bundle
        if changed_bundle is not None:
            selected = directory / 'untrusted.pem'; selected.write_bytes(changed_bundle)
        case = directory / 'case.bin'; case.write_bytes(fixture(now, host, peers))
        independent = oracle(chain, name, now, host, peers, selected, directory)
        cmd = [binary, str(ROOT / 'unicode32_nfkc.bin'), str(ROOT / 'unicode32_prepare.bin'), str(selected), str(case)]
        start = time.monotonic()
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        text = r.stdout.strip(); reason = text.split(':')[0]
        if enforce:
            assert r.returncode == 0 and reason == expected, (chain['label'], name, r.returncode, text, expected, r.stderr[-2000:])
        results.append(dict(case=name, result=reason, expected=expected, verify_ms=int(text.split(':')[1]) if ':' in text else None,
                            elapsed_seconds=time.monotonic()-start, oracle=independent))
    return dict(label=chain['label'], results=results)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--batch-index', type=int, required=True)
    p.add_argument('--report', type=Path)
    p.add_argument('binary')
    a = p.parse_args()
    manifest, bundle, roots = inputs()
    chain = manifest['chains'][a.batch_index]
    with tempfile.TemporaryDirectory(prefix='grounds-public-chain-') as td:
        result = check(chain, bundle, roots, a.binary, Path(td))
    report = dict(passed=True, target='native', bundle_sha256=manifest['bundle_sha256'], anchors=len(roots), **result)
    destination = a.report or (Path(os.environ['GROUNDS_M5_REPORT_DIR']) / f'public-chain-{a.batch_index}.json' if os.environ.get('GROUNDS_M5_REPORT_DIR') else None)
    if destination:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(report, indent=2) + '\n')
    print(f'{chain["label"]}: 5 public-chain/negative cases passed with {len(roots)} explicit anchors')


if __name__ == '__main__':
    main()
