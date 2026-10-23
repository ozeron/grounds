"""TLS ephemeral owners against independent affine and RFC 7748 arithmetic.

Synthetic keys only; successful vectors do not establish runtime timing safety.
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
import p256_check as p
import x25519_check as x


def cases():
    result = []
    rng = random.Random(0x13EC)
    for group in ('x', 'p'):
        for i in range(6):
            private = rng.randbytes(32) if group == 'x' else rng.randrange(1, p.N).to_bytes(32, 'big')
            remote = rng.randbytes(32) if group == 'x' else rng.randrange(1, p.N).to_bytes(32, 'big')
            if group == 'x':
                public, peer = x.reference(private, x.BASE), x.reference(remote, x.BASE)
                secret = x.reference(private, peer)
            else:
                public, peer = p.sec1(p.mul(int.from_bytes(private, 'big'), p.G)), p.sec1(p.mul(int.from_bytes(remote, 'big'), p.G))
                point = p.mul(int.from_bytes(private, 'big'), (int.from_bytes(peer[1:33], 'big'), int.from_bytes(peer[33:], 'big')))
                secret = point[0].to_bytes(32, 'big')
            result.append(('independent-' + group, group, 'shared', [private, peer], [public.hex(), secret.hex()]))
        for width in (0, 1, 31, 33, 64):
            result.append(('private-width-' + group, group, 'pub', [bytes(width)], ['invalid']))
        private = (1).to_bytes(32, 'big')
        public = x.reference(private, x.BASE) if group == 'x' else p.sec1(p.G)
        for peer in ([bytes(32), (1).to_bytes(32, 'little')] if group == 'x' else [b'\x00', b'\x04' + bytes(64), b'\x02' + bytes(32), b'\x04' + p.P.to_bytes(32, 'big') + p.G[1].to_bytes(32, 'big')]):
            result.append(('invalid-peer-' + group, group, 'shared', [private, peer], [public.hex(), 'invalid']))
        for width in (0, 1, 31, 33, 64, 66):
            result.append(('peer-width-' + group, group, 'shared', [private, bytes(width)], [public.hex(), 'invalid']))
    for value in (0, p.N, p.N + 1, 2**256 - 1):
        result.append(('p256-rejection', 'p', 'pub', [value.to_bytes(32, 'big')], ['invalid']))
    for value in (1, p.N - 1):
        result.append(('p256-scalar-boundary', 'p', 'pub', [value.to_bytes(32, 'big')], [p.sec1(p.mul(value, p.G)).hex()]))
    result.append(('non-octets', '', 'guards', [], ['invalid', 'invalid']))
    result.append(('rng-error-and-rejection-bound', '', 'rejection', [], ['invalid'] * 4))
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
    corpus_cases = cases()
    with tempfile.TemporaryDirectory(prefix='grounds-key-share-') as tmp:
        for index, (name, group, mode, inputs, expected) in enumerate(corpus_cases):
            phase = f'{args.phase_prefix}/{index:03d}'
            if args.phase_prefix:
                announce('start', phase)
            command = [*binary, 'run', mode]
            if group:
                command.append(group)
            for offset, value in enumerate(inputs):
                path = Path(tmp) / f'{offset}.bin'
                path.write_bytes(value)
                command.append(str(path))
            run = subprocess.run(command, capture_output=True, text=True, timeout=90)
            assert run.returncode == 0 and run.stdout.splitlines() == expected, (index, name, run.returncode, run.stdout, run.stderr)
            counts[name] += 1
            corpus.update(json.dumps([name, group, mode, [v.hex() for v in inputs], expected], separators=(',', ':')).encode())
            if args.phase_prefix:
                announce('end', phase, 0)
        phase = f'{args.phase_prefix}/rng'
        if args.phase_prefix:
            announce('start', phase)
        # The IO path calls the OS RNG; inspect shape and P-256 curve membership,
        # not exact sampled bytes or entropy quality. Each owner is consumed.
        run = subprocess.run([*binary, 'run', 'random', 'x', 'random', 'p'], capture_output=True, text=True, timeout=90)
        assert run.returncode == 0, run.stderr
        sampled = [bytes.fromhex(row) for row in run.stdout.splitlines()]
        assert len(sampled) == 2 and len(sampled[0]) == 32 and len(sampled[1]) == 65
        px, py = int.from_bytes(sampled[1][1:33], 'big'), int.from_bytes(sampled[1][33:], 'big')
        assert sampled[1][0] == 4 and px < p.P and py < p.P and (py*py-px*px*px+3*px-p.B) % p.P == 0
        counts['host-rng-generation'] += 2
        if args.phase_prefix:
            announce('end', phase, 0)
    report = {'binary': binary, 'cases': dict(counts), 'total_cases': sum(counts.values()),
              'deterministic_cases': len(corpus_cases), 'corpus_sha256': corpus.hexdigest(),
              'elapsed_seconds': round(time.monotonic() - started, 3), 'live_secret_or_timing_acceptance': False,
              'source_sha256': {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in (
                  'tls_key_share.bend', 'tls_key_share_cli.bend', 'tls_key_share_check.py', '../crypto/p256.bend', '../crypto/x25519.bend', 'wire.bend')}}
    report_path = args.report
    if report_path is None and os.environ.get('GROUNDS_M2_REPORT_DIR'):
        target = 'bun' if Path(binary[0]).name == 'bun' else 'native'
        report_path = Path(os.environ['GROUNDS_M2_REPORT_DIR']) / f'tls-keyshare-{target}.json'
    if report_path:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
