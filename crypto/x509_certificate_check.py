"""Independent certificate field-framing oracle, not path/trust validation."""

import argparse
from collections import Counter
import hashlib
import itertools
import json
from pathlib import Path
import random
import subprocess
import tempfile
import time

import x509_algorithm_check as A

ROOT = Path(__file__).parent


def elements(data):
    result = []
    while data:
        tag, body, data, encoded = A.read(data)
        result.append((tag, body, encoded))
    return result


def integer(data):
    return bool(data) and not (len(data) > 1 and ((data[0] == 0 and data[1] < 128) or (data[0] == 255 and data[1] >= 128)))


def bits(data):
    return bool(data) and data[0] <= 7 and (len(data) > 1 or data[0] == 0) and (len(data) == 1 or data[-1] & ((1 << data[0])-1) == 0)


def parse(data):
    if len(data) > 65535:
        raise ValueError('input bound')
    outer = elements(A.complete(data, 48))
    if len(outer) != 3 or [item[0] for item in outer] != [48, 48, 3]:
        raise ValueError('envelope')
    tbs, algorithm, signature = outer
    profile = A.classify(algorithm[2], False)
    if profile == 'none' or len(signature[1]) < 2 or signature[1][0] != 0:
        raise ValueError('signature profile/bits')
    fields = elements(tbs[1])
    version = 0
    if fields and fields[0][0] == 160:
        encoded_version = fields.pop(0)[1]
        if encoded_version not in (b'\x02\x01\x01', b'\x02\x01\x02'):
            raise ValueError('version/default')
        version = encoded_version[-1]
    if len(fields) < 6 or fields[0][0] != 2 or not integer(fields[0][1]):
        raise ValueError('serial/required fields')
    if fields[1][0] != 48 or A.classify(fields[1][2], False) != profile:
        raise ValueError('inner/outer algorithm mismatch')
    if [item[0] for item in fields[2:6]] != [48]*4:
        raise ValueError('mandatory field tags')
    times = elements(fields[3][1])
    if len(times) != 2 or any(item[0] not in (23, 24) for item in times):
        raise ValueError('validity shape')
    optional = {}
    previous = 128
    for tag, body, _ in fields[6:]:
        if tag not in (129, 130, 163) or tag <= previous:
            raise ValueError('optional field order')
        previous = tag
        if tag in (129, 130):
            if version == 0 or not bits(body):
                raise ValueError('unique ID/version')
            optional[tag] = body
        else:
            if version != 2 or not A.complete(body, 48):
                raise ValueError('extension/version/shape')
            optional[tag] = body
    return {'version': version, 'serial': fields[0][1], 'algorithm': profile,
            'tbs': tbs[2], 'issuer': fields[2][2], 'validity': fields[3][2],
            'subject': fields[4][2], 'spki': fields[5][2],
            'issuer_id': optional.get(129), 'subject_id': optional.get(130),
            'extensions': optional.get(163), 'signature': signature[1][1:]}


def oracle(data):
    try:
        record = parse(data)
    except (ValueError, IndexError):
        return 'none'
    return ':'.join(str(record[key]) if key == 'version' else record[key] if key == 'algorithm'
                    else record[key].hex() if record[key] is not None else 'none'
                    for key in ('version', 'serial', 'algorithm', 'tbs', 'issuer', 'validity', 'subject',
                                'spki', 'issuer_id', 'subject_id', 'extensions', 'signature'))


def assemble(tbs, algorithm, signature=b'\x01'):
    return A.tlv(48, tbs+algorithm+A.tlv(3, b'\x00'+signature))


def cases():
    def add(tag, data, expected=None):
        result = oracle(data)
        if expected is not None:
            assert result == expected, (tag, result[:100], expected[:100])
        return tag, data, result

    peers = json.loads((ROOT/'x509_algorithm_vectors.json').read_text())
    fixtures = []
    for peer in peers['peers']:
        data = bytes.fromhex(peer['certificate_der'])
        record = parse(data)
        assert record['algorithm'] == peer['signature_expected']
        assert record['spki'] == bytes.fromhex(peer['spki_der'])
        assert 'Version: 3' in peer['openssl_certificate_text'] and record['version'] == 2
        yield add('OpenSSL-certificate-exact-fields', data)
        fixtures.append(data)
    baseline = fixtures[0]
    outer = elements(A.complete(baseline, 48))
    source = elements(outer[0][1])
    source.pop(0)
    mandatory = [entry[2] for entry in source[:6]]
    algorithm = outer[1][2]
    # ASN.1 INTEGER framing intentionally retains zero/negative serials. The
    # later conformance/path owner must apply its certificate serial policy.
    for serial in (b'\x00', b'\x01', b'\x7f', b'\x80', b'\xff', b'\x00\x80', b'\xff\x7f', b'', b'\x00\x01', b'\xff\x80'):
        fields = [A.tlv(2, serial)]+mandatory[1:]
        yield add('serial-canonical-signed-framing', assemble(A.tlv(48, b''.join(fields)), algorithm))
    ids = [A.tlv(129, b'\x03\x08'), A.tlv(130, b'\x01\x02')]
    extension = A.tlv(163, A.tlv(48, A.tlv(48, A.tlv(6, b'\x55\x1d\x13')+A.tlv(4, b'\x30\x00'))))
    for version in (None, 0, 1, 2, 3, 255):
        prefix = b'' if version is None else A.tlv(160, A.tlv(2, bytes([version])))
        for count in range(4):
            for selected in itertools.combinations(ids+[extension], count):
                yield add('version-optional-presence', assemble(A.tlv(48, prefix+b''.join(mandatory)+b''.join(selected)), algorithm))
    for permutation in itertools.permutations(ids+[extension]):
        yield add('optional-field-order', assemble(A.tlv(48, b'\xa0\x03\x02\x01\x02'+b''.join(mandatory)+b''.join(permutation)), algorithm))
    for tag in (129, 130):
        for unused in range(256):
            for last in (0, 1, 7, 8, 127, 128, 255):
                value = A.tlv(tag, bytes([unused, last]))
                yield add('unique-id-padding', assemble(A.tlv(48, b'\xa0\x03\x02\x01\x01'+b''.join(mandatory)+value), algorithm))
        for body in (b'', b'\x00', b'\x01', b'\x07'):
            yield add('unique-id-empty', assemble(A.tlv(48, b'\xa0\x03\x02\x01\x01'+b''.join(mandatory)+A.tlv(tag, body)), algorithm))
    for item in ids+[extension]:
        yield add('optional-duplicate', assemble(A.tlv(48, b'\xa0\x03\x02\x01\x02'+b''.join(mandatory)+item+item), algorithm), 'none')
    for wrong in (b'\xa3\x00', A.tlv(163, b'\x30\x00'), A.tlv(163, b'\x04\x01\x00'), A.tlv(163, extension+b'\x00'), A.tlv(164, b'\x30\x01\x00')):
        yield add('extension-wrapper-malformed', assemble(A.tlv(48, b'\xa0\x03\x02\x01\x02'+b''.join(mandatory)+wrong), algorithm), 'none')
    for index in range(6):
        fields = list(mandatory)
        del fields[index]
        yield add('mandatory-field-missing', assemble(A.tlv(48, b''.join(fields)), algorithm), 'none')
        fields = list(mandatory)
        fields[index] = bytes([4])+fields[index][1:]
        yield add('mandatory-field-wrong-tag', assemble(A.tlv(48, b''.join(fields)), algorithm), 'none')
    for times in (b'', A.tlv(23, b''), A.tlv(23, b'')*3, A.tlv(4, b'')+A.tlv(23, b'')):
        fields = list(mandatory); fields[3] = A.tlv(48, times)
        yield add('validity-field-count-tag', assemble(A.tlv(48, b''.join(fields)), algorithm), 'none')
    # Primitive time/Name/extension semantics remain deliberately separate;
    # field extraction must retain their bytes for the pending validators.
    fields = list(mandatory); fields[3] = A.tlv(48, A.tlv(23, b'bad')+A.tlv(24, b'also-bad'))
    yield add('semantic-validation-pending', assemble(A.tlv(48, b''.join(fields)), algorithm))
    algorithms = [A.algorithm(A.V15), A.algorithm(A.V15, b'\x05\x00'), A.algorithm(A.ECDSA)]
    pss_peer = peers['peers'][1]
    algorithms.append(bytes.fromhex(pss_peer['signature_algorithm']))
    for inner, outer_algorithm in itertools.product(algorithms, repeat=2):
        fields = list(mandatory); fields[1] = inner
        yield add('inner-outer-algorithm-binding', assemble(A.tlv(48, b''.join(fields)), outer_algorithm))
    for unused in range(256):
        yield add('signature-bit-alignment', A.tlv(48, outer[0][2]+algorithm+A.tlv(3, bytes([unused, 1]))))
    for body in (b'', b'\x00'):
        yield add('signature-empty', A.tlv(48, outer[0][2]+algorithm+A.tlv(3, body)), 'none')
    for data in fixtures:
        for length in range(len(data)):
            yield add('certificate-every-truncation', data[:length], 'none')
        for index in range(len(data)):
            for bit in range(8):
                changed = bytearray(data); changed[index] ^= 1 << bit
                yield add('certificate-every-bit', bytes(changed))
        for suffix in (b'\x00', b'\x05\x00', data):
            yield add('certificate-trailing', data+suffix, 'none')
    rng = random.Random(52804055)
    for _ in range(128):
        data = rng.choice(fixtures); changed = bytearray(data)
        for _ in range(rng.randrange(1, 5)):
            changed[rng.randrange(len(changed))] ^= 1 << rng.randrange(8)
        yield add('seeded-certificate-mutations', bytes(changed))
    for size in (4096, 64500, 65500, 65535, 65536):
        yield add('certificate-input-bound', assemble(outer[0][2], algorithm, bytes(size)))
    return


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--report', type=Path)
    parser.add_argument('binary', nargs=argparse.REMAINDER)
    options = parser.parse_args()
    binary = options.binary[1:] if options.binary[:1] == ['--'] else options.binary
    if not binary:
        parser.error('supply an evaluator after --')
    rows = iter(cases()); counts = Counter(); start = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='grounds-x509-certificate-') as directory:
        first = 0
        pending = next(rows, None)
        while pending is not None:
            batch = [pending]
            pending = None
            while len(batch) < 32 and len(batch[0][1]) <= 4096:
                row = next(rows, None)
                if row is None:
                    break
                if len(row[1]) > 4096:
                    pending = row
                    break
                batch.append(row)
            paths = []
            for index, (_, data, _) in enumerate(batch):
                path = Path(directory)/str(index); path.write_bytes(data); paths.append(path)
            result = subprocess.run(binary+list(map(str, paths)), capture_output=True, text=True, timeout=90)
            assert result.returncode == 0, result.stderr[-2000:]
            outputs = result.stdout.splitlines(); assert len(outputs) == len(batch)
            for (tag, _, expected), output in zip(batch, outputs):
                assert output == expected, (first, tag, output[:120], expected[:120])
                counts[tag] += 1
            for path in paths:
                path.unlink()
            first += len(batch)
            if pending is None:
                pending = next(rows, None)
    names = ['x509_certificate.bend', 'x509_certificate_cli.bend', 'x509_certificate_check.py',
             'x509_algorithm.bend', 'x509_algorithm_check.py', 'der.bend', 'bytes.bend', 'x509_algorithm_vectors.json']
    report = {'binary': binary, 'total': sum(counts.values()), 'cases': dict(counts),
              'elapsed_seconds': round(time.monotonic()-start, 3),
              'input_sha256': {name: hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in names},
              'certificate_semantic_or_trust_validation': False}
    if options.report:
        options.report.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
