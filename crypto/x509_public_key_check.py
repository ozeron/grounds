"""SPKI admission oracle: independent integer arithmetic and curve equation.

Every implementation result comes from one Bend evaluator. Synthetic modulus
admission cases do not certify RSA factor structure; no certificate trust here.
"""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import random
import re
import subprocess
import tempfile
import time

import x509_algorithm_check as A

ROOT = Path(__file__).parent
P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
RSA = A.algorithm(A.RSA, b'\x05\x00')
EC = A.algorithm(A.EC, A.tlv(6, A.P256))


def integer(number):
    data = number.to_bytes(max(1, (number.bit_length()+7)//8), 'big')
    return A.tlv(2, (b'\x00' if data[0] & 128 else b'') + data)


def spki(algorithm, public, unused=0):
    return A.tlv(48, algorithm+A.tlv(3, bytes([unused])+public))


def rsa_public(n, e):
    return A.tlv(48, integer(n)+integer(e))


def pss_key(salt):
    fields = A.tlv(160, A.algorithm(A.SHA256)) + A.tlv(161, A.algorithm(A.MGF, A.algorithm(A.SHA256)))
    return A.algorithm(A.PSS, A.tlv(48, fields+A.tlv(162, integer(salt))))


def positive(data):
    if not data or data[0] & 128:
        raise ValueError('empty/negative integer')
    if data[0] == 0:
        if len(data) == 1 or data[1] < 128:
            raise ValueError('zero/redundant sign pad')
        data = data[1:]
    return data


def peer_expected(peer):
    # OpenSSL's independently retained public-key display, not the DER oracle.
    text = peer['openssl_public_key_text']
    label = 'pub:' if peer['key_expected'] == 'p256' else 'Modulus:'
    lines = text.split(label, 1)[1].splitlines()
    octets = []
    for line in lines:
        if not line.strip():
            continue
        if not re.fullmatch(r'\s*(?:[0-9a-f]{2}:?)+\s*', line):
            break
        octets.append(line.strip().replace(':', ''))
    public = bytes.fromhex(''.join(octets))
    assert public
    if peer['key_expected'] == 'p256':
        assert 'NIST CURVE: P-256' in text
        return 'p256:'+public.hex()
    modulus = public[1:] if public[0] == 0 else public
    exponent = int(re.search(r'Exponent: (\d+)', text).group(1))
    encoded = exponent.to_bytes((exponent.bit_length()+7)//8, 'big')
    if peer['key_expected'] == 'pss256-16':
        assert 'Minimum Salt Length: 16' in text and 'MGF1 with SHA2-256' in text
    return f'{peer["key_expected"]}:{modulus.hex()}:{encoded.hex()}'


def oracle(data):
    if len(data) > 65535:
        return 'none'
    try:
        remaining = A.complete(data, 48)
        tag, _, remaining, algorithm = A.read(remaining)
        if tag != 48:
            raise ValueError('algorithm tag')
        kind = A.classify(algorithm, True)
        bits = A.complete(remaining, 3)
        if not bits or bits[0] != 0:
            raise ValueError('bit padding')
        public = bits[1:]
        if kind == 'p256':
            if len(public) != 65 or public[0] != 4:
                raise ValueError('point form')
            x, y = int.from_bytes(public[1:33], 'big'), int.from_bytes(public[33:], 'big')
            if x >= P or y >= P or (y*y-x*x*x+3*x-B) % P:
                raise ValueError('coordinate range/curve')
            return 'p256:'+public.hex()
        if kind == 'rsa' or kind == 'pss-any' or kind.startswith('pss256-'):
            remaining = A.complete(public, 48)
            tag, modulus, remaining, _ = A.read(remaining)
            if tag != 2:
                raise ValueError('modulus tag')
            exponent = A.complete(remaining, 2)
            modulus, exponent = positive(modulus), positive(exponent)
            n, e = int.from_bytes(modulus, 'big'), int.from_bytes(exponent, 'big')
            if not (2048 <= n.bit_length() <= 4096 and n & 1 and 1 < e < n and e & 1):
                raise ValueError('RSA public parameter profile')
            return f'{kind}:{modulus.hex()}:{exponent.hex()}'
    except (ValueError, IndexError):
        pass
    return 'none'


def cases():
    rows = []

    def add(tag, data, expected=None):
        result = oracle(data)
        if expected is not None:
            assert result == expected, (tag, result[:100], expected[:100])
        rows.append((tag, data, result))

    n = (1 << 2047)+1
    payload = rsa_public(n, 65537)
    keys = [(RSA, 'rsa'), (A.algorithm(A.PSS), 'pss-any')]
    keys += [(pss_key(salt), f'pss256-{salt}') for salt in (0, 16, 20, 32)]
    for algorithm, kind in keys:
        data = spki(algorithm, payload)
        add('algorithm-restriction-preserved', data, f'{kind}:{n.to_bytes(256,"big").hex()}:010001')
    for width in (0, 1, 8, 127, 1024, 2047, 2048, 2049, 2050, 3072, 4095, 4096, 4097):
        base = (1 << (width-1)) if width else 0
        for modulus in sorted({max(0, base-1), base, base+1, (1 << width)-1}):
            for exponent in (0, 1, 2, 3, 65537, (1 << 64)+1, max(0, modulus-2), max(0, modulus-1), modulus, modulus+2):
                add('RSA-size-parity-exponent-boundaries', spki(RSA, rsa_public(modulus, exponent)))
    for size in (1, 127, 128, 255, 256, 257, 511, 512, 513):
        for first in (0, 1, 127, 128, 255):
            raw = bytes([first])+bytes(max(0, size-2))+(b'\x03' if size > 1 else b'')
            for prefix in (b'', b'\x00', b'\x00\x00'):
                add('RSA-integer-canonicality', spki(RSA, A.tlv(48, A.tlv(2, prefix+raw)+integer(65537))))
                add('RSA-integer-canonicality', spki(RSA, A.tlv(48, integer(n)+A.tlv(2, prefix+raw))))
    for raw in (b'', b'\x00', b'\x01', b'\x02', b'\x03', b'\x7f', b'\x80', b'\xff', b'\x00\x80', b'\x00\x00\x80'):
        for index in (0, 1):
            fields = [integer(n), integer(65537)]
            fields[index] = A.tlv(2, raw)
            add('RSA-small-integers', spki(RSA, A.tlv(48, b''.join(fields))))
    for public in (b'', integer(n), A.tlv(48, b''), A.tlv(48, integer(n)),
                   A.tlv(48, integer(n)+integer(65537)+b'\x05\x00'),
                   A.tlv(48, A.tlv(4, b'\x01')+integer(65537)),
                   A.tlv(48, integer(n)+A.tlv(34, b'\x03')), payload+b'\x05\x00',
                   A.tlv(48, integer(n)+b'\x02\x81\x03\x01\x00\x01'),
                   A.tlv(48, integer(n)+b'\x02\x82\x00\x03\x01\x00\x01')):
        add('RSA-malformed-fields', spki(RSA, public), 'none')
    # Public NIST P-256 ECDH points; no private fixture field is consumed here.
    nist = json.loads((ROOT/'p256_vectors.json').read_text())
    points = []
    for case in nist['cases']:
        for prefix in ('QCAVS', 'QIUT'):
            point = bytes.fromhex('04'+case[prefix+'x']+case[prefix+'y'])
            points.append(point)
            add('NIST-P256-public-point', spki(EC, point), 'p256:'+point.hex())
    for point in points[:5]:
        x, y = int.from_bytes(point[1:33], 'big'), int.from_bytes(point[33:], 'big')
        negative = b'\x04'+x.to_bytes(32, 'big')+((P-y) % P).to_bytes(32, 'big')
        add('P256-negative-valid-point', spki(EC, negative), 'p256:'+negative.hex())
    generator = points[0]
    for x in (0, 1, P-1, P, P+1, (1 << 256)-1):
        for y in (0, 1, P-1, P, P+1, (1 << 256)-1):
            add('P256-coordinate-boundaries', spki(EC, b'\x04'+x.to_bytes(32, 'big')+y.to_bytes(32, 'big')))
    for prefix in range(256):
        add('P256-point-prefix', spki(EC, bytes([prefix])+generator[1:]))
    for public in (b'', b'\x00', b'\x02'+generator[1:33], b'\x03'+generator[1:33], generator[:-1], generator+b'\x00', A.tlv(4, generator)):
        add('P256-point-shape', spki(EC, public), 'none')
    for algorithm in (RSA, A.algorithm(A.PSS), pss_key(16), EC):
        for public in (payload, generator):
            add('algorithm-key-bits-binding', spki(algorithm, public))
        for unused in range(256):
            add('BIT-STRING-unused-bits', spki(algorithm, generator if algorithm == EC else payload, unused))
        for body in (b'', b'\x00', b'\x01'):
            add('BIT-STRING-empty', A.tlv(48, algorithm+A.tlv(3, body)), 'none')
    for algorithm in (A.algorithm(A.RSA), A.algorithm(A.RSA, b'\x05\x01\x00'),
                      pss_key(33), A.algorithm(A.PSS, b'\x05\x00'), A.algorithm(A.EC),
                      A.algorithm(A.EC, A.tlv(6, A.P256[:-1]+b'\x08')), A.algorithm(A.ECDSA)):
        add('unsupported-algorithm', spki(algorithm, payload), 'none')
    peers = json.loads((ROOT/'x509_algorithm_vectors.json').read_text())
    for peer in peers['peers']:
        add('OpenSSL-public-SPKI', bytes.fromhex(peer['spki_der']), peer_expected(peer))
    fixtures = [spki(RSA, payload), spki(A.algorithm(A.PSS), payload), spki(pss_key(16), payload), spki(EC, generator)]
    for data in fixtures:
        for length in range(len(data)):
            add('SPKI-every-truncation', data[:length], 'none')
        for index in range(len(data)):
            for bit in range(8):
                changed = bytearray(data)
                changed[index] ^= 1 << bit
                add('SPKI-every-bit', bytes(changed))
        for suffix in (b'\x00', b'\x05\x00', data):
            add('SPKI-trailing', data+suffix, 'none')
        _, fields, _, _ = A.read(data)
        add('SPKI-indefinite', b'\x30\x80'+fields+b'\x00\x00', 'none')
        length = len(fields).to_bytes(3, 'big')
        add('SPKI-length-alias', b'\x30\x83'+length+fields, 'none')
        _, _, tail, algorithm = A.read(fields)
        add('SPKI-missing-bitstring', A.tlv(48, algorithm), 'none')
        add('SPKI-extra-field', A.tlv(48, fields+b'\x05\x00'), 'none')
        add('SPKI-reordered', A.tlv(48, tail+algorithm), 'none')
        add('SPKI-constructed-bitstring', A.tlv(48, algorithm+bytes([35])+tail[1:]), 'none')
    rng = random.Random(528040555480)
    for _ in range(128):
        data = rng.choice(fixtures)
        changed = bytearray(data)
        for _ in range(rng.randrange(1, 5)):
            changed[rng.randrange(len(changed))] ^= 1 << rng.randrange(8)
        add('seeded-multiple-mutations', bytes(changed))
    for size in (4096, 65500, 65510, 65511, 65512, 65535, 65536):
        add('SPKI-input-bound', spki(RSA, bytes(size)), 'none')
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--report', type=Path)
    parser.add_argument('binary', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    binary = args.binary[1:] if args.binary[:1] == ['--'] else args.binary
    if not binary:
        parser.error('supply an evaluator after --')
    rows = cases()
    counts = Counter()
    start = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='grounds-x509-public-key-') as directory:
        first = 0
        while first < len(rows):
            batch = [rows[first]]
            while len(batch) < 16 and first+len(batch) < len(rows) and len(batch[0][1]) <= 4096 and len(rows[first+len(batch)][1]) <= 4096:
                batch.append(rows[first+len(batch)])
            paths = []
            for index, (_, value, _) in enumerate(batch):
                path = Path(directory)/str(index)
                path.write_bytes(value)
                paths.append(path)
            process = subprocess.run(binary+list(map(str, paths)), capture_output=True, text=True, timeout=90)
            assert process.returncode == 0, process.stderr[-2000:]
            outputs = process.stdout.splitlines()
            assert len(outputs) == len(batch), (len(outputs), len(batch))
            for row, output in zip(batch, outputs):
                tag, _, expected = row
                assert output == expected, (first, tag, output[:100], expected[:100])
                counts[tag] += 1
            for path in paths:
                path.unlink()
            first += len(batch)
    inputs = ['x509_public_key.bend', 'x509_public_key_cli.bend', 'x509_public_key_check.py',
              'x509_algorithm.bend', 'x509_algorithm_check.py', 'x509_algorithm_vectors.json',
              'der.bend', 'bytes.bend', 'rsa_integer.bend', 'p256.bend', 'field256.bend', 'p256_vectors.json']
    result = {'binary': binary, 'total': sum(counts.values()), 'cases': dict(counts),
              'elapsed_seconds': round(time.monotonic()-start, 3),
              'input_sha256': {name: hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in inputs},
              'certificate_trust_or_handshake_accepted': False,
              'RSA_factor_structure_certified': False}
    if args.report:
        args.report.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
