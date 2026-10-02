"""Independent numeric OID/re-encoding and exact extension-envelope oracle."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import random
import subprocess
import tempfile
import time

import x509_algorithm_check as A
import x509_certificate_check as C

ROOT = Path(__file__).parent


def base128(number):
    parts = [number & 127]
    while number >> 7:
        number >>= 7
        parts.append((number & 127) | 128)
    return bytes(reversed(parts))


def oid_contents(body):
    numbers, number = [], 0
    for byte in body:
        number = number*128+(byte & 127)
        if byte < 128:
            numbers.append(number); number = 0
    if not numbers or body[-1] >= 128:
        raise ValueError('empty/unterminated OID')
    if b''.join(base128(value) for value in numbers) != body:
        raise ValueError('nonminimal OID')
    return body


def oid(data):
    if len(data) > 65535:
        raise ValueError('input limit')
    return oid_contents(A.complete(data, 6))


def extension(identifier=b'\x55\x1d\x13', value=b'\x30\x00', critical=None):
    return A.tlv(48, A.tlv(6, identifier)+(b'' if critical is None else A.tlv(1, critical))+A.tlv(4, value))


def extensions(data):
    if len(data) > 65535:
        raise ValueError('input limit')
    fields = C.elements(A.complete(data, 48))
    if not fields:
        raise ValueError('empty sequence')
    seen, result = set(), []
    for tag, body, _ in fields:
        if tag != 48:
            raise ValueError('extension tag')
        entries = C.elements(body)
        if len(entries) not in (2, 3):
            raise ValueError('field count')
        identifier = oid(entries[0][2])
        if identifier in seen:
            raise ValueError('duplicate')
        seen.add(identifier)
        critical = len(entries) == 3
        if critical and entries[1][2] != b'\x01\x01\xff':
            raise ValueError('Boolean/default')
        if entries[-1][0] != 4:
            raise ValueError('payload tag')
        result.append(f'{identifier.hex()}:{str(critical).lower()}:{entries[-1][1].hex()}')
    return ','.join(result)


def oracle(operation, data):
    try:
        if operation == '0':
            return oid(data).hex()
        if operation == '2':
            field = C.parse(data)['extensions']
            if field is None:
                return ''
            data = field
        return extensions(data)
    except (ValueError, IndexError):
        return 'none'


def cases():
    def add(tag, operation, data, expected=None):
        result = oracle(operation, data)
        if expected is not None: assert result == expected, tag
        return tag, operation, data, result

    yield add('ITU-X690-2-999-3', '0', b'\x06\x03\x88\x37\x03', '883703')
    for first in range(256):
        yield add('every-one-octet-OID', '0', A.tlv(6, bytes([first])))
        for second in range(256):
            yield add('every-two-octet-OID', '0', A.tlv(6, bytes([first, second])))
    rng = random.Random(690)
    for _ in range(256):
        numbers = [rng.getrandbits(rng.randrange(1, 1025)) for _ in range(rng.randrange(1, 9))]
        body = b''.join(base128(value) for value in numbers)
        yield add('large-and-random-subidentifiers', '0', A.tlv(6, body), body.hex())
        yield add('large-nonminimal-first', '0', A.tlv(6, b'\x80'+body), 'none')
        yield add('large-unterminated-last', '0', A.tlv(6, body+b'\x81'), 'none')
    for body in (b'', b'\x80\x00', b'\x81', b'\x2a\x80\x00', b'\x2a\x81'):
        yield add('OID-boundary-malformed', '0', A.tlv(6, body), 'none')
    good = extension()
    for critical in range(256):
        yield add('every-critical-Boolean-value', '1', A.tlv(48, extension(critical=bytes([critical]))))
    for value in (b'', b'\x00', bytes(range(256)), b'not DER', A.tlv(159,b'\x80')):
        yield add('opaque-payload-preserved', '1', A.tlv(48, extension(value=value)))
    for critical in (None,b'\xff'):
        data = A.tlv(48, extension(critical=critical))
        for size in range(len(data)):
            yield add('every-extension-truncation', '1', data[:size], 'none')
        for index in range(len(data)):
            for bit in range(8):
                changed = bytearray(data);changed[index] ^= 1 << bit
                yield add('every-extension-bit', '1', bytes(changed))
        fields = C.elements(A.complete(C.elements(A.complete(data,48))[0][2],48))
        for index in range(len(fields)):
            rows = [r[2] for r in fields]
            yield add('missing-extension-field','1', A.tlv(48,A.tlv(48,b''.join(rows[:index]+rows[index+1:]))))
            yield add('duplicate-extension-field','1', A.tlv(48,A.tlv(48,b''.join(rows+[rows[index]]))))
    for bad in (A.tlv(48,b''), good, A.tlv(49,good), A.tlv(48,good+b'\x00'),
                A.tlv(48,good)+b'\x00', A.tlv(48,A.tlv(48,A.tlv(6,b'\x80\x00')+A.tlv(4,b''))),
                A.tlv(48,extension(critical=b'')), A.tlv(48,extension(critical=b'\xff\xff')),
                A.tlv(48,A.tlv(48,A.tlv(6,b'\x55\x1d\x13')+A.tlv(36,b'\x04\x00')))):
        yield add('extension-shape-default-and-canonicality', '1', bad, 'none')
    identifiers = [base128(80)+base128(i) for i in range(32)]
    for count in range(1,33):
        entries = [extension(oid, bytes([i]), b'\xff' if i%2 else None) for i,oid in enumerate(identifiers[:count])]
        yield add('unique-identity-map-order', '1', A.tlv(48,b''.join(entries)))
        for position in range(count):
            duplicate = extension(identifiers[position], b'different', b'\xff')
            yield add('every-duplicate-position', '1', A.tlv(48,b''.join(entries+[duplicate])), 'none')
    collision = (b'costarring', b'liquid')
    def fnv(value):
        result = 2166136261
        for byte in value: result = ((result ^ byte)*16777619) & 0xffffffff
        return result
    assert fnv(collision[0]) == fnv(collision[1]) == 0x5e4daa9d
    for order in (collision, collision[::-1]):
        entries = [extension(identifier, bytes([i])) for i,identifier in enumerate(order)]
        yield add('hash-collision-distinct-OIDs', '1', A.tlv(48,b''.join(entries)))
        for identifier in order:
            yield add('hash-collision-exact-duplicate', '1', A.tlv(48,b''.join(entries+[extension(identifier,b'different',b'\xff')])), 'none')
    for count in (128,256,1024,4096,8000):
        entries = [extension(base128(i), b'') for i in range(count)]
        data = A.tlv(48,b''.join(entries))
        assert len(data) <= 65535
        yield add('many-unique-extensions', '1', data)
        yield add('late-duplicate-after-many', '1', A.tlv(48,b''.join(entries+[entries[0]])), 'none')
    for prefix_length in (16,128,1024,8192):
        prefix = b'\x81'*prefix_length+b'\x01'
        entries = [extension(prefix+base128(i), bytes([i])) for i in range(4)]
        yield add('long-shared-OID-prefix-map', '1', A.tlv(48,b''.join(entries)))
        yield add('long-prefix-duplicate', '1', A.tlv(48,b''.join(entries+[entries[-1]])), 'none')
    for total in (4096,65534,65535,65536):
        for size in range(total-32,total):
            data = A.tlv(48,extension(value=bytes(size)))
            if len(data) == total:
                yield add('exact-extension-input-bound','1',data)
                break
        else: raise AssertionError(total)
        for size in range(total-8,total):
            data = A.tlv(6,bytes(size))
            if len(data) == total:
                yield add('exact-OID-input-bound','0',data)
                break
        else: raise AssertionError(total)
    peers = json.loads((ROOT/'x509_algorithm_vectors.json').read_text())['peers']
    peers += json.loads((ROOT/'x509_signature_vectors.json').read_text())['records']
    for peer in peers:
        certificate = bytes.fromhex(peer['certificate_der'])
        fields = C.parse(certificate)
        yield add('frozen-OpenSSL-certificate-extensions', '2', certificate)
        yield add('extracted-OpenSSL-extensions', '1', fields['extensions'])
        yield add('certificate-trailing', '2', certificate+b'\x00','none')
        outer = C.elements(A.complete(certificate,48))
        tbs_fields = C.elements(outer[0][1])
        without = A.tlv(48,b''.join(row[2] for row in tbs_fields if row[0]!=163))
        yield add('certificate-no-extensions', '2', C.assemble(without,outer[1][2],fields['signature']), '')


def main():
    parser = argparse.ArgumentParser();parser.add_argument('--report',type=Path)
    parser.add_argument('binary',nargs=argparse.REMAINDER);options = parser.parse_args()
    binary = options.binary[1:] if options.binary[:1] == ['--'] else options.binary
    if not binary:parser.error('supply evaluator after --')
    rows = iter(cases());pending = next(rows,None);counts = Counter();start = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='grounds-extensions-') as folder:
        first = 0
        while pending is not None:
            batch = [pending];pending = None
            while len(batch)<64 and len(batch[0][2])<=4096:
                row = next(rows,None)
                if row is None:break
                if len(row[2])>4096:pending=row;break
                batch.append(row)
            args = []
            for index,(_,operation,value,_) in enumerate(batch):
                path = Path(folder)/f'{index}.der';path.write_bytes(value);args.extend((operation,str(path)))
            result = subprocess.run(binary+['check']+args,capture_output=True,text=True,timeout=60)
            expected = [r[3] for r in batch]
            assert result.returncode==0 and result.stdout.splitlines()==expected,(first,[r[0] for r in batch],result.returncode,result.stdout[-1000:],expected[-2:],result.stderr[-1000:])
            counts.update(r[0] for r in batch);first += len(batch)
            if pending is None:pending=next(rows,None)
        for args in ([],['check','0'],['check','unknown','one-path'],['unknown']):
            result = subprocess.run(binary+args,capture_output=True,text=True,timeout=10)
            assert result.returncode==2 and not result.stdout,args
    names = ('oid.bend','x509_extensions.bend','x509_extensions_cli.bend','x509_extensions_check.py',
             'der.bend','bytes.bend','x509_certificate.bend','x509_algorithm.bend',
             'x509_algorithm_check.py','x509_certificate_check.py','x509_algorithm_vectors.json','x509_signature_vectors.json')
    report = {'binary':binary,'total':sum(counts.values()),'cases':dict(counts),'CLI_failures':4,
              'elapsed_seconds':round(time.monotonic()-start,3),'payload_semantics_or_trust_checked':False,
              'input_sha256':{n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in names}}
    if options.report:options.report.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report))


if __name__=='__main__':main()
