"""RFC-profile AlgorithmIdentifier cases, strict TLV framing and public peers.

Python is an independent oracle and fixture driver. Every evaluator result is
computed in Bend. This does not validate certificates, key bits or trust.
"""

import argparse
from collections import Counter
import hashlib
import itertools
import json
from pathlib import Path
import subprocess
import tempfile
import time

ROOT = Path(__file__).parent
RSA = bytes.fromhex('2a864886f70d010101')
PSS = bytes.fromhex('2a864886f70d01010a')
V15 = bytes.fromhex('2a864886f70d01010b')
MGF = bytes.fromhex('2a864886f70d010108')
SHA256 = bytes.fromhex('608648016503040201')
SHA1 = bytes.fromhex('2b0e03021a')
EC = bytes.fromhex('2a8648ce3d0201')
P256 = bytes.fromhex('2a8648ce3d030107')
ECDSA = bytes.fromhex('2a8648ce3d040302')
ECDSA384 = bytes.fromhex('2a8648ce3d040303')
P384 = bytes.fromhex('2b81040022')
SHA384 = bytes.fromhex('608648016503040202')
SHA512 = bytes.fromhex('608648016503040203')
V15384 = bytes.fromhex('2a864886f70d01010c')
V15512 = bytes.fromhex('2a864886f70d01010d')


def tlv(tag, body):
    n = len(body)
    length = bytes([n]) if n < 128 else bytes([128 + (n.bit_length()+7)//8]) + n.to_bytes((n.bit_length()+7)//8, 'big')
    return bytes([tag]) + length + body


def algorithm(oid, parameters=b''):
    return tlv(48, tlv(6, oid) + parameters)


def read(data):
    if len(data) < 2 or data[0] & 31 == 31 or data[0] & 223 == 0:
        raise ValueError('tag/header')
    width = data[1] & 127 if data[1] & 128 else 0
    if data[1] & 128:
        if width not in (1, 2) or len(data) < 2+width or data[2] == 0:
            raise ValueError('length width')
        size = int.from_bytes(data[2:2+width], 'big')
        if size < 128 or (width == 2 and size < 256):
            raise ValueError('nonminimal length')
    else:
        size = data[1]
    end = 2+width+size
    if end > len(data):
        raise ValueError('truncated')
    return data[0], data[2+width:end], data[end:], data[:end]


def complete(data, tag):
    actual, body, rest, _ = read(data)
    if actual != tag or rest:
        raise ValueError('shape')
    return body


def identifier(data):
    tag, oid, parameters, _ = read(complete(data, 48))
    if tag != 6:
        raise ValueError('OID')
    return oid, parameters


def hash256(data):
    oid, parameters = identifier(data)
    return oid == SHA256 and parameters in (b'', b'\x05\x00')


def pss_params(data):
    fields = {}
    remaining = complete(data, 48)
    previous = 159
    while remaining:
        tag, body, remaining, _ = read(remaining)
        if tag not in range(160, 164) or tag <= previous:
            raise ValueError('field order')
        fields[tag] = body
        previous = tag
    # Absent hash and MGF fields select SHA-1; they never mean SHA-256.
    h_oid,h_params = identifier(fields.get(160,algorithm(SHA1)))
    if h_oid not in (SHA256,SHA384,SHA512) or h_params not in (b'',b'\x05\x00'):
        raise ValueError('hash')
    bits={SHA256:256,SHA384:384,SHA512:512}[h_oid]
    mgf_oid, mgf_hash = identifier(fields.get(161, algorithm(MGF, algorithm(SHA1))))
    if mgf_oid != MGF or identifier(mgf_hash)[0] != h_oid or identifier(mgf_hash)[1] not in (b'', b'\x05\x00'):
        raise ValueError('MGF')
    salt_bytes = complete(fields.get(162, b'\x02\x01\x14'), 2)
    if not salt_bytes or len(salt_bytes)>2 or salt_bytes[0]&128 or len(salt_bytes)>1 and salt_bytes[0]==0 and salt_bytes[1]<128:
        raise ValueError('salt encoding')
    salt=int.from_bytes(salt_bytes,'big')
    if salt>(32 if bits==256 else 512):raise ValueError('salt bound')
    if complete(fields.get(163, b'\x02\x01\x01'), 2) != b'\x01':
        raise ValueError('trailer')
    return bits,salt


def classify(data, key):
    if len(data) > 65535:
        return 'none'
    try:
        oid, params = identifier(data)
        if key:
            if oid == RSA and params == b'\x05\x00':
                return 'rsa'
            if oid == PSS:
                return 'pss-any' if not params else 'pss%d-%d'%pss_params(params)
            if oid == EC:
                curve=complete(params,6)
                return {P256:'p256',P384:'p384'}.get(curve,'none')
        else:
            if oid == V15 and params in (b'', b'\x05\x00'):
                return 'v15256'
            if oid == PSS:
                bits,salt=pss_params(params)
                return ('pss256' if salt==32 else 'none') if bits==256 else f'pss{bits}-{salt}'
            if oid in (V15384,V15512) and params in (b'',b'\x05\x00'):
                return 'v15384' if oid==V15384 else 'v15512'
            if oid==ECDSA384 and not params:return 'ecdsa384'
            if oid == ECDSA and not params:
                return 'ecdsa256'
    except (ValueError, IndexError):
        pass
    return 'none'


def oracle(op, values):
    if op in ('0', '1'):
        return classify(values[0], op == '0')
    if op == '2':
        key, signature = classify(values[0], True), classify(values[1], False)
        accepted = (key == 'rsa' and signature.startswith(('v15','pss')) or
                    key == 'pss-any' and signature.startswith('pss') or
                    key.startswith('pss') and '-' in key and signature.startswith(key.split('-')[0]) and int(key.split('-')[1]) <= (32 if signature=='pss256' else int(signature.split('-')[1])) or
                    key == 'p256' and signature in ('ecdsa256','ecdsa384') or key=='p384' and signature=='ecdsa384')
        return str(accepted).lower()
    try:
        if len(values[0]) > 65535:
            return 'none'
        tag, body, rest, encoded = read(values[0])
        return f'{tag}:{body.hex()}:{rest.hex()}:{encoded.hex()}'
    except ValueError:
        return 'none'


def cases():
    rows = []

    def add(tag, op, values, expected=None):
        result = oracle(op, values)
        if expected is not None:
            assert result == expected, (tag, op, result, expected)
        rows.append((tag, op, values, result))

    positives = [
        (algorithm(RSA, b'\x05\x00'), 'rsa', 'none'),
        (algorithm(PSS), 'pss-any', 'none'),
        (algorithm(V15), 'none', 'v15256'),
        (algorithm(V15, b'\x05\x00'), 'none', 'v15256'),
        (algorithm(EC, tlv(6, P256)), 'p256', 'none'),
        (algorithm(ECDSA), 'none', 'ecdsa256'),
    ]
    for oid,label in [(V15384,'v15384'),(V15512,'v15512'),(ECDSA384,'ecdsa384')]:
        positives.append((algorithm(oid),'none',label))
    positives.append((algorithm(EC,tlv(6,P384)),'p384','none'))
    for bits,hash_oid in [(384,SHA384),(512,SHA512)]:
        for salt in (0,1,20,31,32,47,48,49,63,64,65,127,128,207,255,256,511,512,513):
            value=salt.to_bytes((salt.bit_length()+7)//8 or 1,'big')
            value=(b'\0' if value[0]&128 else b'')+value
            for null_hash,null_mgf,trailer in itertools.product((b'',b'\x05\x00'),(b'',b'\x05\x00'),(b'',tlv(163,tlv(2,b'\x01')))):
                h=tlv(160,algorithm(hash_oid,null_hash))
                m=tlv(161,algorithm(MGF,algorithm(hash_oid,null_mgf)))
                aid=algorithm(PSS,tlv(48,h+m+tlv(162,tlv(2,value))+trailer))
                add('SHA2-PSS-salt-params','0',[aid],f'pss{bits}-{salt}' if salt<=512 else 'none')
                add('SHA2-PSS-salt-params','1',[aid],f'pss{bits}-{salt}' if salt<=512 else 'none')
        h=tlv(160,algorithm(hash_oid));m=tlv(161,algorithm(MGF,algorithm(hash_oid)))
        aid=algorithm(PSS,tlv(48,h+m))
        add('SHA2-PSS-default-salt','1',[aid],f'pss{bits}-20')
        for wrong in [tlv(161,algorithm(MGF,algorithm(SHA256))),tlv(161,algorithm(SHA1)),b'']:
            add('SHA2-PSS-wrong-MGF','1',[algorithm(PSS,tlv(48,h+wrong+tlv(162,tlv(2,b'\x30'))))],'none')
        for bad in [b'',b'\x00\x30',b'\xff',b'\x00\x00\x80',b'\x80']:
            add('SHA2-PSS-malformed-salt','1',[algorithm(PSS,tlv(48,h+m+tlv(162,tlv(2,bad))))],'none')
    for null_hash, null_mgf, salt, explicit_trailer in itertools.product((False, True), (False, True), range(34), (False, True)):
        h = algorithm(SHA256, b'\x05\x00' if null_hash else b'')
        m = algorithm(MGF, algorithm(SHA256, b'\x05\x00' if null_mgf else b''))
        fields = tlv(160, h)+tlv(161, m)+tlv(162, tlv(2, bytes([salt])))
        if explicit_trailer:
            fields += tlv(163, tlv(2, b'\x01'))
        encoded = algorithm(PSS, tlv(48, fields))
        add('PSS-parameter-matrix', '0', [encoded], f'pss256-{salt}' if salt <= 32 else 'none')
        add('PSS-parameter-matrix', '1', [encoded], 'pss256' if salt == 32 else 'none')
    h, m = tlv(160, algorithm(SHA256)), tlv(161, algorithm(MGF, algorithm(SHA256)))
    for trailer in (b'', tlv(163, tlv(2, b'\x01'))):
        encoded = algorithm(PSS, tlv(48, h+m+trailer))
        add('PSS-default-salt', '0', [encoded], 'pss256-20')
        add('PSS-default-salt', '1', [encoded], 'none')
    positives.append((algorithm(PSS, tlv(48, h+m+tlv(162, tlv(2, b'\x20')))), 'pss256-32', 'pss256'))
    for encoded, key, signature in positives:
        add('RFC-identifier', '0', [encoded], key)
        add('RFC-identifier', '1', [encoded], signature)
        for size in range(len(encoded)):
            for op in ('0', '1'):
                add('identifier-every-truncation', op, [encoded[:size]], 'none')
        for index in range(len(encoded)):
            for bit in range(8):
                changed = bytearray(encoded)
                changed[index] ^= 1 << bit
                for op in ('0', '1'):
                    add('identifier-every-bit', op, [bytes(changed)])
        for suffix in (b'\x00', b'\x05\x00', encoded):
            for op in ('0', '1'):
                add('identifier-trailing', op, [encoded+suffix], 'none')
    fields = [h, m, tlv(162, tlv(2, b'\x20')), tlv(163, tlv(2, b'\x01'))]
    for order in itertools.permutations(fields):
        for op in ('0', '1'):
            add('PSS-field-order', op, [algorithm(PSS, tlv(48, b''.join(order)))])
    malformed = [algorithm(RSA), algorithm(RSA, b'\x05\x01\x00'),
                 algorithm(ECDSA, b'\x05\x00'), algorithm(EC),
                 algorithm(EC, b'\x05\x00'), algorithm(EC, tlv(48, b'')),
                 algorithm(PSS, b'\x05\x00'), algorithm(PSS, tlv(48, b''))]
    for omission in (h, m, b''):
        malformed.append(algorithm(PSS, tlv(48, omission+fields[2])))
    for field in fields:
        malformed.append(algorithm(PSS, tlv(48, b''.join(fields)+field)))
    for wrong in [tlv(162, tlv(2, b'')), tlv(162, tlv(2, b'\x00\x20')),
                  tlv(162, tlv(2, b'\xff')), tlv(162, tlv(2, b'\x00\x80')),
                  tlv(162, tlv(4, b'\x20')), tlv(163, tlv(2, b'\x02')),
                  tlv(164, tlv(2, b'\x01')), tlv(2, b'\x20')]:
        malformed.append(algorithm(PSS, tlv(48, h+m+wrong)))
    for value in malformed:
        for op in ('0', '1'):
            add('algorithm-malformed', op, [value], 'none')
    for suffix in range(256):
        for parameters in (b'', b'\x05\x00'):
            encoded = algorithm(RSA[:-1]+bytes([suffix]), parameters)
            for op in ('0', '1'):
                add('PKCS1-OID-suffix-admission', op, [encoded])
    for key, _, _ in positives:
        for sig, _, _ in positives:
            add('key-signature-binding', '2', [key, sig])
    for size in (0, 1, 127, 128, 129, 255, 256, 257, 512, 1024, 65530, 65531, 65532, 65535):
        value = tlv(4, bytes((i % 256 for i in range(size))))
        add('DER-length-boundary', '3', [value])
        if size < 1025:
            add('DER-rest-preserved', '3', [value+b'\x05\x00'])
            add('DER-truncated', '3', [value[:-1]])
    for value in [b'', b'\x04', b'\x04\x80\x00\x00', b'\x04\xff',
                  b'\x04\x81\x01\x00', b'\x04\x82\x00\x80'+bytes(128),
                  b'\x04\x83\x00\x01\x00'+bytes(256), b'\x1f\x01\x00',
                  b'\x00\x00', b'\x20\x00']:
        add('DER-malformed', '3', [value], 'none')
    fixture = json.loads((ROOT/'x509_algorithm_vectors.json').read_text())
    for peer in fixture['peers']:
        key, signature = bytes.fromhex(peer['key_algorithm']), bytes.fromhex(peer['signature_algorithm'])
        add('OpenSSL-key-algorithm', '0', [key], peer['key_expected'])
        add('OpenSSL-signature-algorithm', '1', [signature], peer['signature_expected'])
        add('OpenSSL-key-signature-binding', '2', [key, signature], 'true')
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
    with tempfile.TemporaryDirectory(prefix='grounds-x509-algorithm-') as directory:
        first = 0
        while first < len(rows):
            batch = [rows[first]]
            if max(map(len, rows[first][2])) <= 4096:
                while len(batch) < 32 and first+len(batch) < len(rows) and max(map(len, rows[first+len(batch)][2])) <= 4096:
                    batch.append(rows[first+len(batch)])
            command = list(binary)
            paths = []
            for index, (_, op, values, _) in enumerate(batch):
                command.append(op)
                for part, value in enumerate(values):
                    path = Path(directory)/f'{index}-{part}'
                    path.write_bytes(value)
                    paths.append(path)
                    command.append(str(path))
            process = subprocess.run(command, capture_output=True, text=True, timeout=90)
            assert process.returncode == 0, process.stderr[-2000:]
            outputs = process.stdout.splitlines()
            assert len(outputs) == len(batch), (len(outputs), len(batch))
            for row, output in zip(batch, outputs):
                tag, op, _, expected = row
                assert output == expected, (first, tag, op, output[:100], expected[:100])
                counts[tag] += 1
            for path in paths:
                path.unlink()
            first += len(batch)
    result = {'binary': binary, 'total': sum(counts.values()), 'cases': dict(counts),
              'elapsed_seconds': round(time.monotonic()-start, 3),
              'input_sha256': {name: hashlib.sha256((ROOT/name).read_bytes()).hexdigest()
                               for name in ['der.bend', 'x509_algorithm.bend', 'x509_key_cli.bend', 'x509_signature_cli.bend', 'x509_binding_cli.bend', 'der_cli.bend', 'x509_algorithm_fixture.py',
                                            'x509_algorithm_check.py', 'x509_algorithm_vectors.json', 'bytes.bend']},
              'certificate_key_bits_trust_or_handshake_accepted': False}
    if args.report:
        args.report.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
