"""Independent bounded TLV framing oracle; schema/value validation remains separate."""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import random
import subprocess
import tempfile
import time

ROOT = Path(__file__).parent


def tlv(tag, body):
    count = len(body)
    width = (count.bit_length()+7)//8
    size = bytes([count]) if count < 128 else bytes([128+width])+count.to_bytes(width, 'big')
    return bytes([tag])+size+body


def oracle(data):
    if len(data) < 2 or len(data) > 65535 or data[0] & 31 == 31 or data[0] & 223 == 0:
        return 'none'
    width = data[1] & 127 if data[1] & 128 else 0
    if data[1] & 128:
        if width not in (1, 2) or len(data) < width+2 or data[2] == 0:
            return 'none'
        count = int.from_bytes(data[2:2+width], 'big')
        if count < 128 or width == 2 and count < 256:
            return 'none'
    else:
        count = data[1]
    end = 2+width+count
    if end > len(data):
        return 'none'
    return f'{data[0]}:{data[2+width:end].hex()}:{data[end:].hex()}:{data[:end].hex()}'


def cases():
    rows = []

    def add(tag, data, expected=None):
        result = oracle(data)
        if expected is not None:
            assert result == expected, (tag, result[:80])
        rows.append((tag, data, result))

    # X.690 8.1.3/10.1: definite, minimally encoded short and long lengths.
    for count in (0, 1, 2, 126, 127, 128, 129, 254, 255, 256, 257, 511, 512, 1024,
                  65530, 65531, 65532, 65535):
        body = bytes(i % 256 for i in range(count))
        value = tlv(4, body)
        add('length-boundary', value)
        if count <= 1024:
            add('unconsumed-rest', value+b'\x05\x00')
            # A short-form empty value has one missing header byte here.
            add('truncated-length-or-body', value[:-1], 'none')
            for alias in (bytes([4, 129, count]) if count < 128 else b'',
                          bytes([4, 130, 0, count]) if count < 256 else b'',
                          bytes([4, 131, 0])+count.to_bytes(2, 'big')):
                if alias:
                    add('nonminimal-or-unsupported-length', alias+body, 'none')
    for tag in range(256):
        add('single-octet-tag', tlv(tag, b'\xa5'))
    for length in range(256):
        add('length-octet', bytes([4, length])+bytes(512))
    for value in (b'', b'\x04', b'\x04\x80\x00\x00', b'\x04\x81', b'\x04\x82\x01',
                  b'\x04\x81\x00', b'\x04\x82\x00\x80'+bytes(128),
                  b'\x04\x82\x01\x00'+bytes(255)):
        add('malformed-header', value, 'none')
    # Every truncation and bit mutation is checked against the independent
    # byte-slicing oracle; changes in content remain valid framing when appropriate.
    for value in [tlv(48, b'\x02\x01\x01\x05\x00'), tlv(4, bytes(range(128))),
                  tlv(4, bytes(range(256)))]:
        for position in range(len(value)):
            add('every-truncation', value[:position], 'none')
        for position in range(min(len(value), 12)):
            for bit in range(8):
                changed = bytearray(value)
                changed[position] ^= 1 << bit
                add('header-and-content-bit', bytes(changed))
    rng = random.Random(690)
    for _ in range(128):
        length = rng.randrange(600)
        body = rng.randbytes(length)
        value = tlv(rng.choice((2, 3, 4, 6, 48, 49, 160, 163)), body)
        add('seeded-roundtrip', value)
        add('seeded-rest', value+rng.randbytes(rng.randrange(12)))
    fixture = json.loads((ROOT/'der_vectors.json').read_text())
    for peer in fixture['peers']:
        for field in ('certificate_der', 'spki_der'):
            value = bytes.fromhex(peer[field])
            add('OpenSSL-DER-framing', value)
            for position in (0, 1, 2, 3, len(value)//2, len(value)-1):
                add('OpenSSL-truncation', value[:position], 'none')
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--report', type=Path)
    parser.add_argument('binary', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    binary = args.binary[1:] if args.binary[:1] == ['--'] else args.binary
    if not binary:
        parser.error('supply a precompiled evaluator after --')
    rows = cases()
    count = Counter()
    start = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='grounds-der-') as directory:
        first = 0
        while first < len(rows):
            # Large public inputs run alone so one process does not retain
            # several maximum-sized diagnostic strings before its next GC.
            batch = [rows[first]]
            if len(rows[first][1]) <= 4096:
                while len(batch) < 32 and first+len(batch) < len(rows) and len(rows[first+len(batch)][1]) <= 4096:
                    batch.append(rows[first+len(batch)])
            paths = []
            for index, (_, data, _) in enumerate(batch):
                path = Path(directory)/str(index)
                path.write_bytes(data)
                paths.append(path)
            process = subprocess.run(binary+[str(path) for path in paths], capture_output=True,
                                     text=True, timeout=90)
            assert process.returncode == 0, process.stderr[-2000:]
            outputs = process.stdout.splitlines()
            assert len(outputs) == len(batch), (len(outputs), len(batch))
            for (tag, _, expected), output in zip(batch, outputs):
                assert output == expected, (first, tag, output[:100], expected[:100])
                count[tag] += 1
            for path in paths:
                path.unlink()
            first += len(batch)
    result = {'binary': binary, 'total': sum(count.values()), 'cases': dict(count),
              'elapsed_seconds': round(time.monotonic()-start, 3),
              'input_sha256': {name: hashlib.sha256((ROOT/name).read_bytes()).hexdigest()
                               for name in ['der.bend', 'der_cli.bend', 'der_check.py',
                                            'der_vectors.json', 'bytes.bend']},
              'certificate_schema_key_signature_or_trust_accepted': False}
    if args.report:
        args.report.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
