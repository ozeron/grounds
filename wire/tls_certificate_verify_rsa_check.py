"""Synthetic RSA CertificateVerify signing: RFC 8017/Python and OpenSSL peers.

The fixed public test key was generated with cryptography 50.0.2 on 2026-10-23;
its intentionally published factors are test data, never live credentials.
The ordinary gate needs only stdlib Python and the OpenSSL test oracle.
"""
import argparse
from collections import Counter
import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / 'crypto'))
from rsa_encoding_check import pss_encode, pss_decode

P = 0xf2bb054210a71d92af4c894aa005d6f10263bb058ac0e67e1d9aa9b3d0143e9d932214fd20859e647f7f8dd69e63d1497b912a286a014cbce2a8e676262df498f262f3a05169c739650b40b6a01ab51ece3ed11563359288cb119eed162497ba6145bf007505b2907d970de78bab18b4481862095453871a64639707697913ad
Q = 0xd1ab008989791f328b1cfb91a8df6ba115e5013155ec694ab5267c05fa93e2979e08e269532ebd1779f3bdb027f745f1d26f60c4c4db2664e8016ab634c18ed428efa5ed6ffb00b4a23a6ba301f1541c48bc04d93da2f9c98ae981f469427ffc86227a7aece9f2ae759e52544a69af8641238e2a6c1e3b00e27cd8d503c4ebfd


def be(value):
    return value.to_bytes(max(1, (value.bit_length() + 7) // 8), 'big')


def key():
    n, e = P * Q, 65537
    d = pow(e, -1, math.lcm(P - 1, Q - 1))
    return dict(zip(('n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi'),
                    (be(v) for v in (n, e, d, P, Q, d % (P - 1), d % (Q - 1), pow(Q, -1, P)))))


def digest(role, transcript):
    assert len(transcript) == 32
    context = bytes([32]) * 64 + b'TLS 1.3, ' + (b'server' if role == 's' else b'client') + b' CertificateVerify\x00' + transcript
    return hashlib.sha256(context).digest()


def sign(role, transcript, salt):
    private = key()
    n, d = int.from_bytes(private['n'], 'big'), int.from_bytes(private['d'], 'big')
    message = pss_encode(n.bit_length() - 1, digest(role, transcript), salt)
    signature = pow(int.from_bytes(message, 'big'), d, n).to_bytes(len(private['n']), 'big')
    assert pss_decode(n.bit_length() - 1, digest(role, transcript), pow(int.from_bytes(signature, 'big'), 65537, n).to_bytes(len(private['n']), 'big')) == salt
    return signature


def der(tag, value):
    size = len(value)
    length = bytes([size]) if size < 128 else bytes([128 + len(be(size))]) + be(size)
    return bytes([tag]) + length + value


def integer(value):
    return der(2, (b'\x00' if value[0] & 128 else b'') + value)


def verify_openssl(role, transcript, signature, folder):
    private = key()
    rsa = der(48, integer(private['n']) + integer(private['e']))
    public = der(48, bytes.fromhex('300d06092a864886f70d0101010500') + der(3, b'\x00' + rsa))
    (folder / 'public.der').write_bytes(public)
    (folder / 'digest').write_bytes(digest(role, transcript))
    (folder / 'signature').write_bytes(signature)
    subprocess.run(['openssl', 'pkeyutl', '-verify', '-pubin', '-keyform', 'DER', '-inkey', str(folder / 'public.der'),
                    '-in', str(folder / 'digest'), '-sigfile', str(folder / 'signature'), '-pkeyopt', 'digest:sha256',
                    '-pkeyopt', 'rsa_padding_mode:pss', '-pkeyopt', 'rsa_pss_saltlen:32'], capture_output=True, check=True)


def cases():
    result = []
    for role, salt in (('s', bytes(32)), ('c', bytes(range(32)))):
        transcript = hashlib.sha256(('synthetic CV ' + role).encode()).digest()
        signature = sign(role, transcript, salt)
        result.append(('independent-PSS-sign-' + role, role, transcript, salt, (2).to_bytes(256, 'big'), [signature.hex(), 'true']))
    transcript = bytes(32)
    for name, value, salt, blind in (
            ('invalid-transcript', bytes(31), bytes(32), (2).to_bytes(256, 'big')),
            ('invalid-salt', transcript, bytes(31), (2).to_bytes(256, 'big')),
            ('invalid-blinding-width', transcript, bytes(32), bytes(255)),
            ('invalid-blinding-zero', transcript, bytes(32), bytes(256))):
        result.append((name, 's', value, salt, blind, ['invalid']))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path)
    parser.add_argument('--phase-prefix')
    parser.add_argument('binary', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    binary = args.binary[1:] if args.binary[:1] == ['--'] else args.binary
    if not binary:
        parser.error('compiled evaluator required')
    if args.phase_prefix:
        sys.path.insert(0, str(ROOT.parent / 'tools'))
        from check_phase import announce
    started, counts, corpus = time.monotonic(), Counter(), hashlib.sha256()
    with tempfile.TemporaryDirectory(prefix='grounds-cv-rsa-') as tmp:
        folder = Path(tmp)
        for field, value in key().items():
            (folder / field).write_bytes(value)
        for index, (name, role, transcript, salt, blind, expected) in enumerate(cases()):
            phase = f'{args.phase_prefix}/{index:03d}'
            if args.phase_prefix:
                announce('start', phase)
            for field, value in (('hash', transcript), ('salt', salt), ('blind', blind)):
                (folder / field).write_bytes(value)
            run = subprocess.run([*binary, 'run', 'sign', role, str(folder), str(folder / 'hash'), str(folder / 'salt'), str(folder / 'blind')],
                                 capture_output=True, text=True, timeout=110)
            assert run.returncode == 0 and run.stdout.splitlines() == expected, (name, run.returncode, run.stdout, run.stderr)
            if len(expected) == 2:
                # Every actual Bend signature verifies with independent RSA
                # arithmetic and OpenSSL, in addition to the CLI's Bend verifier.
                signature = bytes.fromhex(run.stdout.splitlines()[0])
                n = P * Q
                recovered = pow(int.from_bytes(signature, 'big'), 65537, n).to_bytes(256, 'big')
                assert pss_decode(n.bit_length() - 1, digest(role, transcript), recovered) == salt
                verify_openssl(role, transcript, signature, folder)
            counts[name] += 1
            corpus.update(json.dumps([name, role, transcript.hex(), salt.hex(), blind.hex(), expected], separators=(',', ':')).encode())
            if args.phase_prefix:
                announce('end', phase, 0)
    report = {'binary': binary, 'cases': dict(counts), 'total_cases': sum(counts.values()),
              'corpus_sha256': corpus.hexdigest(), 'elapsed_seconds': round(time.monotonic() - started, 3),
              'independent_verifiers': ['Python integer exponentiation + RFC8017 encoding', 'OpenSSL PSS/SHA256'],
              'live_secret_or_timing_acceptance': False,
              'source_sha256': {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in (
                  'tls_certificate_verify.bend', 'tls_certificate_verify_rsa_cli.bend', 'tls_certificate_verify_rsa_check.py', '../crypto/rsa_private.bend')}}
    report_path = args.report
    if report_path is None and os.environ.get('GROUNDS_M2_REPORT_DIR'):
        target = 'bun' if Path(binary[0]).name == 'bun' else 'native'
        report_path = Path(os.environ['GROUNDS_M2_REPORT_DIR']) / f'tls-certificate-verify-rsa-{target}.json'
    if report_path:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
