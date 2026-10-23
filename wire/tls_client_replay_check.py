"""Pinned RFC 8448 section 3 through the production Bend client transitions.

The exact published ClientHello seeds the public state constructor because the
live client offers the frozen profile, not the RFC's larger offer. The exact
ServerHello must install the published traffic epochs. The exact EE is then
rejected: its record_size_limit extension is outside this client's profile.
A separately labelled profile-compatible EE branch reaches the published
Certificate, which must fail the production RSA-2048 admission floor. Neither
branch claims full authentication or weakens certificate admission.

Reference: RFC 8448 section 3, lines 160-165, 277-315, 360-378, 599-614;
wire/tls_handshake_vectors.json pins the published source identity.
"""

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / 'crypto'))
from x25519_check import BASE, reference
from tls_handshake_vectors import expand, verify

PRIVATE = bytes.fromhex('49af42ba7f7994852d713ef2784bcbcaa7911de26adc5642cb634540e7ea5005')
SERVER_SECRET = 'b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38'
CLIENT_SECRET = 'b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21'
HELLO_HASH = '860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8'
KEYS = [SERVER_SECRET, '3fce516009c21727d0f2e4e86ee403bc', '5d313eb2671276ee13000b30',
        CLIENT_SECRET, 'dbfaa693d1762c5b666af5d950258d01', '5bd3c71b836e0b76bb73265f']


def label(secret, name, size):
    full = b'tls13 ' + name
    return expand(bytes.fromhex(secret), size.to_bytes(2, 'big') + bytes([len(full)]) + full + b'\x00', size)


def fixtures():
    data = json.loads((ROOT / 'tls_handshake_vectors.json').read_text())
    verify(data)
    trace = next(trace for trace in data['traces'] if trace['section'] == 3)
    messages = {}
    for row in trace['operations']:
        if 'construct ' in row['operation']:
            for name, value in row['fields'].items():
                messages.setdefault(name, bytes.fromhex(value))
    ch, sh, ee, cert, finished = (messages[name] for name in (
        'ClientHello', 'ServerHello', 'EncryptedExtensions', 'Certificate', 'Finished'))
    public = reference(PRIVATE, BASE)
    assert public.hex() == '99381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c'
    assert public in ch
    server_public = bytes.fromhex('c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f')
    assert server_public in sh
    assert reference(PRIVATE, server_public).hex() == '8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d'
    assert hashlib.sha256(ch + sh).hexdigest() == HELLO_HASH
    assert [label(SERVER_SECRET, b'key', 16).hex(), label(SERVER_SECRET, b'iv', 12).hex()] == KEYS[1:3]
    assert [label(CLIENT_SECRET, b'key', 16).hex(), label(CLIENT_SECRET, b'iv', 12).hex()] == KEYS[4:6]
    # This is an explicitly modified branch, never called an exact RFC replay.
    # The published EE has supported_groups, record_size_limit, server_name.
    assert ee[30:36] == bytes.fromhex('001c00024001')
    body = ee[6:30] + ee[36:]
    compatible = b'\x08' + (len(body) + 2).to_bytes(3, 'big') + len(body).to_bytes(2, 'big') + body
    assert len(compatible) == len(ee) - 6
    initial = ['install', *KEYS, 'hash:' + HELLO_HASH, 'phase:8']
    advanced = initial + ['continue', 'hash:' + hashlib.sha256(ch + sh + compatible).hexdigest(), 'phase:13']
    cases = [
        ('RFC8448-exact-CH-SH-published-epochs', [sh], initial),
        ('RFC8448-exact-EE-profile-rejection', [sh, ee], initial + ['fail:110:encrypted-extensions']),
        ('modified-EE-profile-transition', [sh, compatible], advanced),
        ('modified-EE-exact-RFC-certificate-RSA-floor', [sh, compatible, cert], advanced + ['fail:42:certificate:malformed']),
        ('certificate-before-server-hello', [cert], ['fail:10:expected-server-hello']),
        ('certificate-before-encrypted-extensions', [sh, cert], initial + ['fail:10:handshake-order']),
        ('finished-before-authentication', [sh, compatible, finished], advanced + ['fail:10:handshake-order']),
        ('duplicate-encrypted-extensions', [sh, compatible, compatible], advanced + ['fail:10:handshake-order']),
    ]
    return [PRIVATE, public, ch[6:38], ch], cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path)
    parser.add_argument('--phase-prefix')
    parser.add_argument('binary', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    binary = args.binary[1:] if args.binary[:1] == ['--'] else args.binary
    if not binary:
        parser.error('compiled replay evaluator required')
    if args.phase_prefix:
        sys.path.insert(0, str(ROOT.parent / 'tools'))
        from check_phase import announce
    started, counts, corpus = time.monotonic(), Counter(), hashlib.sha256()
    seed, cases = fixtures()
    with tempfile.TemporaryDirectory(prefix='grounds-tls-client-replay-') as tmp:
        for index, (name, messages, expected) in enumerate(cases):
            phase = f'{args.phase_prefix}/{index:03d}'
            if args.phase_prefix:
                announce('start', phase)
            command = [*binary, 'run', str(ROOT.parent / 'crypto/unicode32_nfkc.bin'),
                       str(ROOT.parent / 'crypto/unicode32_prepare.bin')]
            for offset, value in enumerate(seed + messages):
                path = Path(tmp) / f'{offset}.bin'
                path.write_bytes(value)
                command.append(str(path))
            result = subprocess.run(command, capture_output=True, text=True, timeout=110)
            assert result.returncode == 0 and result.stdout.splitlines() == expected, (
                name, result.returncode, result.stdout, result.stderr, expected)
            counts[name] += 1
            corpus.update(json.dumps([name, [v.hex() for v in seed + messages], expected], separators=(',', ':')).encode())
            if args.phase_prefix:
                announce('end', phase, 0)
    report = {
        'binary': binary, 'cases': dict(counts), 'total_cases': sum(counts.values()),
        'elapsed_seconds': round(time.monotonic() - started, 3), 'corpus_sha256': corpus.hexdigest(),
        'exact_replay': 'RFC8448 section3 ClientHello seed and ServerHello through production client, published read/write traffic secrets, AES keys/IVs and transcript hash; exact EE rejected110 at record_size_limit',
        'modified_branch': 'remove EE record_size_limit only; production EE transition then exact published RSA1024 Certificate rejected42; no CertificateVerify/Finished authentication claim',
        'certificate_policy_bypass': False, 'live_secret_or_timing_acceptance': False,
        'source_sha256': {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in (
            'tls_client.bend', 'tls_client_replay_cli.bend', 'tls_client_replay_check.py', 'tls_handshake_vectors.json')},
    }
    report_path = args.report
    if report_path is None and os.environ.get('GROUNDS_M3_REPORT_DIR'):
        target = 'bun' if Path(binary[0]).name == 'bun' else 'native'
        report_path = Path(os.environ['GROUNDS_M3_REPORT_DIR']) / f'tls-client-replay-{target}.json'
    if report_path:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
