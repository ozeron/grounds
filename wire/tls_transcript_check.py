"""Independent exact-byte transcript checks for a compiled Bend evaluator."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import time

from tls_handshake_vectors import HRR_RANDOM, verify

ROOT = Path(__file__).resolve().parent
LIMIT = 1048576


def sha(value):
    return hashlib.sha256(value).hexdigest()


def message(kind, body=b''):
    return bytes([kind]) + len(body).to_bytes(3, 'big') + body


def published_sequences():
    data = json.loads((ROOT / 'tls_handshake_vectors.json').read_text())
    verify(data)
    cases = []
    for trace in data['traces']:
        transcript, messages, expected = b'', [], []
        for row in trace['operations']:
            if 'construct ' not in row['operation']:
                continue
            encoded = bytes.fromhex(next(iter(row['fields'].values())))
            if encoded[0] == 2 and encoded[6:38] == HRR_RANDOM:
                transcript = message(254, hashlib.sha256(transcript).digest())
            transcript += encoded
            messages.append(encoded)
            expected.append(sha(transcript))
        cases.append((f'rfc8448-section-{trace["section"]}', messages, expected))
    return cases


def cases():
    result = published_sequences()
    hello = message(1, b'hello')
    retry = message(2, b'\x03\x03' + HRR_RANDOM)
    # Transcript-only admission: full hello/body validation belongs to TLS.
    first = sha(hello)
    retried = message(254, hashlib.sha256(hello).digest()) + retry
    result.extend([
        ('empty-body-hello', [message(1)], [sha(message(1))]),
        ('empty-input', [b'', hello], ['invalid', 'invalid']),
        ('wrong-first-kind', [message(2), hello], ['invalid', 'invalid']),
        ('retry-first', [retry], ['invalid']),
        ('retry-once', [hello, retry], [first, sha(retried)]),
        ('retry-twice', [hello, retry, retry], [first, sha(retried), 'invalid']),
        ('retry-too-late', [hello, message(2), retry], [first, sha(hello + message(2)), 'invalid']),
        ('wire-synthetic', [hello, message(254, bytes(32))], [first, 'invalid']),
        ('coalesced-requires-splitting', [hello + message(2)], ['invalid']),
        ('record-header-excluded', [b'\x16\x03\x03' + len(hello).to_bytes(2, 'big') + hello], ['invalid']),
    ])
    for length in range(len(hello)):
        result.append(('every-hello-truncation', [hello[:length]], ['invalid']))
    for offset in range(1, 4):
        bad = bytearray(hello)
        bad[offset] ^= 1
        result.append(('length-field-tampering', [bytes(bad)], ['invalid']))
    # Check SHA compression and padding boundaries independently of the RFC.
    for length in (1, 51, 52, 55, 56, 59, 60, 63, 64, 65, 119, 120, 127, 128, 129, 4096, 65535):
        encoded = message(1, bytes((i * 19 + 7) % 256 for i in range(length)))
        result.append(('hash-block-boundaries', [encoded, message(8)], [sha(encoded), sha(encoded + message(8))]))
    return result


def run(binary, batches, folder):
    args, expected, kinds = [*binary, 'run'], [], Counter()
    for number, (kind, messages, results) in enumerate(batches):
        assert len(messages) == len(results)
        if number:
            args.append('reset')
        for index, data in enumerate(messages):
            path = folder / f'msg-{number}-{index}.bin'
            path.write_bytes(data)
            args.append(str(path))
        expected.extend(results)
        kinds[kind] += len(results)
    output = subprocess.run(args, text=True, capture_output=True, timeout=110)
    assert output.returncode == 0, (output.returncode, output.stdout[-1000:], output.stderr[-2000:])
    actual = output.stdout.splitlines()
    assert len(actual) == len(expected), (len(actual), len(expected), output.stderr[-2000:])
    for index, (got, want) in enumerate(zip(actual, expected)):
        assert got == want, (index, got, want)
    return kinds


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path)
    parser.add_argument('--stress', action='store_true', help='Run exact total-byte limits in separate invocation')
    parser.add_argument('binary', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    binary = args.binary[1:] if args.binary[:1] == ['--'] else args.binary
    if not binary:
        parser.error('compiled evaluator required')
    start = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='grounds-transcript-') as tmp:
        if args.stress:
            exact = message(1, b'\x5a' * (LIMIT - 4))
            overflow = message(1, b'\x5a' * (LIMIT - 3))
            almost = message(1, b'\x5a' * (LIMIT - 8))
            batches = [
                ('exact-limit', [exact, message(8)], [sha(exact), 'invalid']),
                ('over-limit', [overflow], ['invalid']),
                ('cumulative-limit', [almost, message(8), message(20)], [sha(almost), sha(almost + message(8)), 'invalid']),
            ]
        else:
            batches = cases()
        counts = run(binary, batches, Path(tmp))
    if not args.stress:
        result = subprocess.run([*binary, 'guards'], text=True, capture_output=True, timeout=20)
        assert result.returncode == 0, result.stderr
        assert result.stdout.splitlines() == [sha(b''), 'invalid', 'invalid'], result.stdout
        counts['direct-nonoctet-and-closed-owner'] += 3
    report = {'binary': binary, 'cases': dict(counts), 'total': sum(counts.values()),
              'elapsed_seconds': round(time.monotonic() - start, 3),
              'stress': args.stress, 'full_tls_handshake': False,
              'sha256': {name: sha((ROOT / name).read_bytes()) for name in (
                  'tls_transcript.bend', 'tls_transcript_cli.bend', 'tls_transcript_check.py',
                  'tls_handshake_vectors.json', '../crypto/sha256_stream.bend',
                  '../crypto/sha256.bend', '../crypto/bytes.bend')}}
    if args.report:
        args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
