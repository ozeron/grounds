"""Independent TLS 1.3 CertificateVerify contexts, RFC 8448 and signatures.

The RFC traces use 1024-bit RSA and establish exact content construction here;
admitted 2048-bit RSA and P-256 signature checks use separate synthetic keys.
"""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / 'crypto'))
import ecdsa_check as e
import p256_check as p
from tls_handshake_vectors import HRR_RANDOM, verify as verify_vectors


def content(role, transcript):
    assert len(transcript) == 32
    return bytes([32]) * 64 + b'TLS 1.3, ' + (b'server' if role == 's' else b'client') + b' CertificateVerify\x00' + transcript


def published():
    data = json.loads((ROOT / 'tls_handshake_vectors.json').read_text())
    verify_vectors(data)
    result = []
    for trace in data['traces']:
        transcript, certificate = b'', None
        for row in trace['operations']:
            if 'construct ' not in row['operation']:
                continue
            encoded = bytes.fromhex(next(iter(row['fields'].values())))
            if encoded[0] == 15:
                assert row['operation'].startswith('{server}') and encoded[4:6] == b'\x08\x04'
                value = hashlib.sha256(transcript).digest()
                context = content('s', value)
                # Independently bind the reconstructed content to the published
                # signature, while retaining the production RSA size floor.
                assert certificate is not None
                with tempfile.TemporaryDirectory(prefix='grounds-rfc8448-cv-') as tmp:
                    folder = Path(tmp)
                    (folder / 'cert.der').write_bytes(certificate)
                    public = subprocess.run(['openssl', 'x509', '-inform', 'DER', '-in', str(folder / 'cert.der'), '-pubkey', '-noout'], capture_output=True, check=True).stdout
                    (folder / 'public.pem').write_bytes(public)
                    (folder / 'signature').write_bytes(encoded[8:])
                    (folder / 'content').write_bytes(context)
                    subprocess.run(['openssl', 'dgst', '-sha256', '-verify', str(folder / 'public.pem'),
                                    '-signature', str(folder / 'signature'), '-sigopt', 'rsa_padding_mode:pss',
                                    '-sigopt', 'rsa_pss_saltlen:32', str(folder / 'content')], capture_output=True, check=True)
                result += [(f'RFC8448-section-{trace["section"]}', 'content', 's', [value], [context.hex()]),
                           (f'RFC8448-section-{trace["section"]}', 'digest', 's', [value], [hashlib.sha256(context).hexdigest()])]
                break
            if encoded[0] == 11:
                assert encoded[4] == 0
                size = int.from_bytes(encoded[8:11], 'big')
                certificate = encoded[11:11 + size]
            if encoded[0] == 2 and encoded[6:38] == HRR_RANDOM:
                transcript = b'\xfe\x00\x00\x20' + hashlib.sha256(transcript).digest()
            transcript += encoded
    assert len(result) == 4
    return result


def cases():
    result = published()
    rng = random.Random(0x13C3)
    for role in ('s', 'c'):
        for transcript in (bytes(32), bytes([255]) * 32, rng.randbytes(32)):
            result += [('independent-content', 'content', role, [transcript], [content(role, transcript).hex()]),
                       ('independent-digest', 'digest', role, [transcript], [hashlib.sha256(content(role, transcript)).hexdigest()])]
        for width in (0, 1, 31, 33, 64):
            for mode in ('content', 'digest'):
                result.append(('transcript-width', mode, role, [bytes(width)], ['invalid']))
        for scalar in (1, p.N - 1, rng.randrange(1, p.N)):
            private, transcript = scalar.to_bytes(32, 'big'), rng.randbytes(32)
            digest = hashlib.sha256(content(role, transcript)).digest()
            peer, raw = p.sec1(p.mul(scalar, p.G)), e.reference_sign(scalar, digest)
            signature = e.der(raw)
            assert e.reference_verify(peer, digest, raw)
            result += [('ECDSA-independent-sign', 'ecdsa-sign', role, [private, transcript], [signature.hex()]),
                       ('ECDSA-independent-verify', 'ecdsa-verify', role, [peer, transcript, signature], ['true']),
                       ('ECDSA-wrong-role', 'ecdsa-verify', 'c' if role == 's' else 's', [peer, transcript, signature], ['false']),
                       ('ECDSA-wrong-transcript', 'ecdsa-verify', role, [peer, bytes([transcript[0] ^ 1]) + transcript[1:], signature], ['false']),
                       ('ECDSA-invalid-DER', 'ecdsa-verify', role, [peer, transcript, signature + b'\x00'], ['false'])]
        private, peer = (1).to_bytes(32, 'big'), p.sec1(p.G)
        for width in (0, 31, 33):
            result += [('ECDSA-transcript-width', 'ecdsa-sign', role, [private, bytes(width)], ['invalid']),
                       ('ECDSA-transcript-width', 'ecdsa-verify', role, [peer, bytes(width), b''], ['false'])]
    result.append(('non-octet-and-scheme-SPKI-binding', 'guards', '', [], ['invalid'] * 2 + ['false'] * 6))
    from tls_certificate_verify_rsa_check import key, sign
    private = key()
    for role in ('s', 'c'):
        transcript = hashlib.sha256(('synthetic verify ' + role).encode()).digest()
        signature = sign(role, transcript, bytes(range(32)))
        values = [private['n'], private['e'], transcript, signature]
        result += [('RSA-independent-verify', 'rsa-verify', role, values, ['true']),
                   ('RSA-valid-signature-SPKI-restrictions', 'rsa-restricted', role, values, ['false'] * 3),
                   ('RSA-wrong-role', 'rsa-verify', 'c' if role == 's' else 's', values, ['false']),
                   ('RSA-wrong-transcript', 'rsa-verify', role, [private['n'], private['e'], bytes(32), signature], ['false']),
                   ('RSA-modified-signature', 'rsa-verify', role, [private['n'], private['e'], transcript, signature[:-1] + bytes([signature[-1] ^ 1])], ['false']),
                   ('RSA-transcript-width', 'rsa-verify', role, [private['n'], private['e'], bytes(31), signature], ['false'])]
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
    all_cases = cases()
    with tempfile.TemporaryDirectory(prefix='grounds-certificate-verify-') as tmp:
        for index, (name, mode, role, inputs, expected) in enumerate(all_cases):
            phase = f'{args.phase_prefix}/{index:03d}'
            if args.phase_prefix:
                announce('start', phase)
            command = [*binary, 'run', mode] + ([role] if role else [])
            for offset, value in enumerate(inputs):
                path = Path(tmp) / f'{offset}.bin'
                path.write_bytes(value)
                command.append(str(path))
            run = subprocess.run(command, capture_output=True, text=True, timeout=90)
            assert run.returncode == 0 and run.stdout.splitlines() == expected, (index, name, run.returncode, run.stdout, run.stderr)
            counts[name] += 1
            corpus.update(json.dumps([name, mode, role, [v.hex() for v in inputs], expected], separators=(',', ':')).encode())
            if args.phase_prefix:
                announce('end', phase, 0)
    report = {'binary': binary, 'cases': dict(counts), 'total_cases': sum(counts.values()),
              'corpus_sha256': corpus.hexdigest(), 'elapsed_seconds': round(time.monotonic() - started, 3),
              'rfc8448_scope': 'exact pre-CertificateVerify transcript and context/hash; RFC 1024-bit RSA excluded by production profile',
              'live_secret_or_timing_acceptance': False,
              'source_sha256': {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in (
                  'tls_certificate_verify.bend', 'tls_certificate_verify_cli.bend', 'tls_certificate_verify_check.py', 'tls_handshake_vectors.json',
                  '../crypto/ecdsa_scheme256.bend', '../crypto/rsa_signature256.bend')}}
    report_path = args.report
    if report_path is None and os.environ.get('GROUNDS_M2_REPORT_DIR'):
        target = 'bun' if Path(binary[0]).name == 'bun' else 'native'
        report_path = Path(os.environ['GROUNDS_M2_REPORT_DIR']) / f'tls-certificate-verify-{target}.json'
    if report_path:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
