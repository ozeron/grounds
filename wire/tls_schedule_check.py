"""Published and independent SHA-256 TLS schedule/Finished checks."""
import argparse
from collections import Counter
import hashlib
import hmac
import json
from pathlib import Path
import random
import subprocess
import tempfile
import time

from tls_handshake_vectors import HRR_RANDOM, verify as verify_vectors

ROOT = Path(__file__).resolve().parent


def digest(value):
    return hashlib.sha256(value).digest()


def mac(key, value):
    return hmac.digest(key, value, 'sha256')


def label(key, name, context):
    name = b'tls13 ' + name
    info = b'\x00\x20' + bytes([len(name)]) + name + bytes([len(context)]) + context
    return mac(key, info + b'\x01')


def next_secret(secret, ikm):
    return mac(label(secret, b'derived', digest(b'')), ikm)


def application(secret, transcript):
    if len(secret) != 32 or len(transcript) != 32:
        return ['invalid']
    main = next_secret(secret, bytes(32))
    return [label(main, name, transcript).hex() for name in (b'c ap traffic', b's ap traffic')]


def flow(shared, hello, server, app):
    if len(shared) != 32 or len(hello) != 32:
        return ['invalid']
    handshake = next_secret(mac(bytes(32), bytes(32)), shared)
    client = label(handshake, b'c hs traffic', hello)
    peer = label(handshake, b's hs traffic', hello)
    ck, sk = label(client, b'finished', b''), label(peer, b'finished', b'')
    outputs = [value.hex() for value in (handshake, client, peer, ck, sk)]
    outputs += [mac(sk, server).hex() if len(server) == 32 else 'invalid',
                mac(ck, app).hex() if len(app) == 32 else 'invalid']
    return outputs + application(handshake, app)


def published():
    data = json.loads((ROOT / 'tls_handshake_vectors.json').read_text())
    verify_vectors(data)
    result = []
    for trace in data['traces']:
        rows = trace['operations']
        def field(description, name):
            matches = [row for row in rows if description in row['operation']]
            assert matches, description
            return bytes.fromhex(matches[0]['fields'][name])
        shared = field('{server}  extract secret "handshake"', 'IKM')
        hello = field('{server}  derive secret "tls13 c hs traffic"', 'hash')
        app = field('{server}  derive secret "tls13 c ap traffic"', 'hash')
        transcript = b''
        for row in rows:
            if 'construct ' not in row['operation']:
                continue
            encoded = bytes.fromhex(next(iter(row['fields'].values())))
            if row['operation'].startswith('{server}') and encoded[0] == 20:
                break
            if encoded[0] == 2 and encoded[6:38] == HRR_RANDOM:
                transcript = b'\xfe\x00\x00\x20' + digest(transcript)
            transcript += encoded
        server = digest(transcript)
        expected = [
            field('{server}  extract secret "handshake"', 'secret'),
            field('{server}  derive secret "tls13 c hs traffic"', 'expanded'),
            field('{server}  derive secret "tls13 s hs traffic"', 'expanded'),
            field('{client}  calculate finished', 'expanded'),
            field('{server}  calculate finished', 'expanded'),
            field('{server}  calculate finished', 'finished'),
            field('{client}  calculate finished', 'finished'),
            field('{server}  derive secret "tls13 c ap traffic"', 'expanded'),
            field('{server}  derive secret "tls13 s ap traffic"', 'expanded'),
        ]
        expected = [value.hex() for value in expected]
        inputs = [shared, hello, server, app]
        assert flow(*inputs) == expected, trace['section']
        result.append((f'rfc8448-section-{trace["section"]}', 'flow', inputs, expected))
    return result


def cases():
    result = published()
    rng = random.Random(9846)
    for _ in range(64):
        inputs = [rng.randbytes(32) for _ in range(4)]
        result.append(('independent-schedule', 'flow', inputs, flow(*inputs)))
    zeros = [bytes(32)] * 4
    result.append(('all-zero-component-inputs', 'flow', zeros, flow(*zeros)))
    for position in range(4):
        for length in (0, 1, 31, 33, 64):
            inputs = [bytes([i + 1]) * 32 for i in range(4)]
            inputs[position] = b'\x07' * length
            result.append(('flow-input-width', 'flow', inputs, flow(*inputs)))
    key, transcript = rng.randbytes(32), rng.randbytes(32)
    tag = mac(key, transcript)
    result += [('finished-positive', 'finished', [key, transcript], [tag.hex()]),
               ('verify-positive', 'verify', [key, transcript, tag], ['true'])]
    for position in range(32):
        altered = bytearray(tag)
        altered[position] ^= 1
        result.append(('every-tag-byte', 'verify', [key, transcript, bytes(altered)], ['false']))
        changed = bytearray(transcript)
        changed[position] ^= 1
        result.append(('every-transcript-byte', 'verify', [key, bytes(changed), tag], ['false']))
    result.append(('wrong-key', 'verify', [bytes(32), transcript, tag], ['false']))
    for index in range(3):
        for length in (0, 1, 31, 33, 64):
            inputs = [key, transcript, tag]
            inputs[index] = b'\x05' * length
            result.append(('verify-input-width', 'verify', inputs, ['false']))
    for index in range(2):
        for length in (0, 31, 33):
            inputs = [key, transcript]
            inputs[index] = b'\x04' * length
            result.append(('finished-input-width', 'finished', inputs, ['invalid']))
            result.append(('application-input-width', 'app', inputs, ['invalid']))
    result.append(('direct-nonoctet', 'guards', [], ['invalid'] * 5 + ['false']))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path)
    parser.add_argument('binary', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    binary = args.binary[1:] if args.binary[:1] == ['--'] else args.binary
    if not binary:
        parser.error('compiled evaluator required')
    started, counts = time.monotonic(), Counter()
    corpus = hashlib.sha256()
    all_cases = cases()
    with tempfile.TemporaryDirectory(prefix='grounds-schedule-') as tmp:
        folder = Path(tmp)
        # Keep command arguments/file ownership bounded, without dropping cases.
        for offset in range(0, len(all_cases), 16):
            command, expected = [*binary, 'run'], []
            for number, (name, mode, inputs, outputs) in enumerate(all_cases[offset:offset + 16]):
                command.append(mode)
                for index, data in enumerate(inputs):
                    path = folder / f'{number}-{index}.bin'
                    path.write_bytes(data)
                    command.append(str(path))
                expected += outputs
                counts[name] += len(outputs)
                corpus.update(json.dumps([name, mode, [value.hex() for value in inputs], outputs], separators=(',', ':')).encode())
            run = subprocess.run(command, text=True, capture_output=True, timeout=90)
            assert run.returncode == 0, (offset, run.returncode, run.stdout[-1000:], run.stderr[-2000:])
            actual = run.stdout.splitlines()
            assert actual == expected, (offset, actual, expected)
    report = {'binary': binary, 'cases': dict(counts), 'total_outputs': sum(counts.values()),
              'commands': len(all_cases), 'corpus_sha256': corpus.hexdigest(),
              'elapsed_seconds': round(time.monotonic() - started, 3), 'live_tls_or_timing_acceptance': False,
              'source_sha256': {name: hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in (
                  'tls_schedule.bend','tls_schedule_cli.bend','tls_schedule_check.py','tls_handshake_vectors.json',
                  '../crypto/hkdf.bend','../crypto/hmac.bend','../crypto/traffic.bend')}}
    if args.report:
        args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
