"""Independent numeric-OID, DER ordering and typed Name string checks."""
import argparse
from collections import Counter
import hashlib
import itertools
import json
from pathlib import Path
import subprocess
import tempfile

import x509_algorithm_check as A
import x509_certificate_check as C
import x509_extensions_check as E

ROOT = Path(__file__).parent
PRINTABLE = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 '()+,-./:=?")
DIRECTORY = {3: 64, 4: 32768, 7: 128, 8: 128, 10: 64, 11: 64, 12: 64,
             41: 32768, 42: 32768, 43: 32768, 44: 32768, 65: 128}
DC = bytes.fromhex('0992268993f22c640119')
EMAIL = bytes.fromhex('2a864886f70d010901')


def string(tag, body):
    if tag == 12:
        return len(body.decode('utf-8', errors='strict'))
    if tag == 19:
        if any(byte not in PRINTABLE for byte in body):
            raise ValueError('PrintableString alphabet')
        return len(body)
    if tag == 22:
        return len(body.decode('ascii', errors='strict'))
    if tag in (28, 30):
        return len(body.decode('utf-32-be' if tag == 28 else 'utf-16-be', errors='strict')) if tag == 28 else bmp(body)
    raise ValueError('unsupported string tag')


def bmp(body):
    # BMPString is UCS-2: paired UTF-16 surrogates are also forbidden.
    if len(body) % 2:
        raise ValueError('BMP width')
    values = [int.from_bytes(body[i:i+2], 'big') for i in range(0, len(body), 2)]
    if any(0xd800 <= value <= 0xdfff for value in values):
        raise ValueError('BMP surrogate')
    return len(values)


def value(oid, tag, body):
    directory = oid[:2] == b'\x55\x04' and len(oid) == 3 and oid[2] in DIRECTORY
    if directory:
        if tag == 20:
            if not body: raise ValueError('empty Teletex DirectoryString')
            return False
        if tag not in (12, 19, 28, 30): raise ValueError('DirectoryString tag')
        minimum, maximum = 1, DIRECTORY[oid[2]]
    elif oid == b'\x55\x04\x06':
        if tag != 19: raise ValueError('country tag')
        minimum = maximum = 2
    elif oid == b'\x55\x04\x05':
        if tag != 19: raise ValueError('serial tag')
        minimum, maximum = 1, 64
    elif oid == b'\x55\x04\x2e':
        if tag != 19: raise ValueError('qualifier tag')
        minimum, maximum = 0, 65535
    elif oid in (DC, EMAIL):
        if tag != 22: raise ValueError('IA5 attribute tag')
        minimum, maximum = (0, 65535) if oid == DC else (1, 255)
    else:
        return False
    count = string(tag, body)
    if not minimum <= count <= maximum: raise ValueError('attribute SIZE')
    return True


def parse(data):
    if len(data) > 65535: raise ValueError('input limit')
    rdns, supported = [], True
    for tag, body, _ in C.elements(A.complete(data, 48)):
        members = C.elements(body)
        if tag != 49 or not members: raise ValueError('RDN shape')
        if [row[2] for row in members] != sorted(row[2] for row in members):
            raise ValueError('SET OF order')
        attrs = []
        for tag, body, encoded in members:
            fields = C.elements(body)
            if tag != 48 or len(fields) != 2 or fields[0][0] != 6: raise ValueError('attribute shape')
            oid = E.oid_contents(fields[0][1])
            value_tag, value_body, _ = fields[1]
            processed = value(oid, value_tag, value_body)
            supported = supported and processed
            attrs.append((oid, value_tag, value_body, encoded))
        rdns.append(attrs)
    return rdns, supported


def inspect(data, allow_empty=True):
    rdns, supported = parse(data)
    if not rdns and not allow_empty: raise ValueError('empty issuer')
    return 'supported' if supported else 'deferred'


def oracle(mode, data):
    try:
        if mode == '2':
            cert = C.parse(data)
            names = [inspect(cert['issuer'], False), inspect(cert['subject'])]
            return 'deferred' if 'deferred' in names else 'supported'
        if mode == '1': return inspect(data, False)
        rdns, supported = parse(data)
        return ('supported' if supported else 'deferred')+'|'+''.join(
            ''.join(f'{oid.hex()}:{tag}:{body.hex()}:{encoded.hex()};' for oid, tag, body, encoded in attrs)+'/'
            for attrs in rdns)
    except (ValueError, UnicodeError, IndexError):
        return 'none'


def attribute(oid=b'\x55\x04\x03', tag=12, body=b'a'):
    return A.tlv(48, A.tlv(6, oid)+A.tlv(tag, body))


def name(*rdns):
    return A.tlv(48, b''.join(A.tlv(49, members) for members in rdns))


def cases():
    def add(group, data, mode='0', expected=None):
        actual = oracle(mode, data)
        if expected is not None: assert actual == expected, (group, actual, expected)
        return group, mode, data, actual
    yield add('empty-subject', b'\x30\x00', expected='supported|')
    yield add('empty-issuer', b'\x30\x00', mode='1', expected='none')
    yield add('empty-RDN', b'\x30\x02\x31\x00', expected='none')
    for tag in (12, 19, 20, 22, 28, 30):
        for byte in range(256):
            yield add('all-octets-typed-string', name(attribute(tag=tag, body=bytes([byte]))))
    for oid in [bytes([85,4,x]) for x in (*DIRECTORY, 5, 6, 46)]+[DC, EMAIL]:
        for tag in (12, 19, 20, 22, 28, 30, 4, 44, 51):
            for size in (0, 1, 2, 63, 64, 65, 127, 128, 129, 254, 255, 256):
                unit = {28: b'\x00\x00\x00a', 30: b'\x00a'}.get(tag, b'a')
                yield add('attribute-types-and-size-endpoints', name(attribute(oid, tag, unit*size)))
    for byte in range(256):
        for prefix in (b'\xc2', b'\xe0', b'\xed', b'\xf0', b'\xf4', b'\xc0'):
            yield add('UTF8-lead-continuation-boundaries', name(attribute(body=prefix+bytes([byte])+b'\x80\x80')))
        for high in (0, 0xd7, 0xd8, 0xdf, 0xe0, 0xff):
            yield add('BMP-scalar-boundaries', name(attribute(tag=30, body=bytes([high, byte]))))
        for offset in range(4):
            data = bytearray(4); data[offset] = byte
            yield add('Universal-scalar-boundaries', name(attribute(tag=28, body=bytes(data))))
        yield add('canonical-arbitrary-OID', name(attribute(oid=bytes([byte]), tag=4, body=b'x')))
    for text in ('a', '\u00e9', '\u20ac', '\U0001f600'):
        for size in (1, 63, 64, 65):
            yield add('UTF8-counts-characters-not-octets', name(attribute(body=(text*size).encode())))
    for data in (b'\xc0\xaf', b'\xc1\xbf', b'\xed\xa0\x80', b'\xf4\x90\x80\x80',
                 b'\xf0\x80\x80\x80', b'\xe0\x80\x80', b'\xe2\x82', b'\x80'):
        yield add('literal-invalid-UTF8', name(attribute(body=data)), expected='none')
    yield add('BMP-surrogate-pair-forbidden', name(attribute(tag=30, body=b'\xd8\x3d\xde\x00')), expected='none')
    attrs = [attribute(body=b'aa'), attribute(body=b'b'), attribute(b'\x55\x04\x0a', 19, b'a'), attribute(body=b'a')]
    for members in itertools.permutations(attrs):
        yield add('SET-orders-entire-encoding', name(b''.join(members)))
        yield add('RDN-sequence-order-preserved', name(*members))
    yield add('equal-SET-encodings-allowed', name(attrs[0]*2))
    for good_bad in ((attribute(), attribute(body=b'\xff')), (attribute(body=b'\xff'), attribute())):
        yield add('later-invalid-attribute-cannot-hide', name(*good_bad), expected='none')
    sample = name(*attrs)
    for cut in range(len(sample)):
        yield add('every-Name-truncation', sample[:cut], expected='none')
    for index in range(len(sample)):
        for bit in range(8):
            data = bytearray(sample); data[index] ^= 1 << bit
            yield add('every-Name-bit-mutation', bytes(data))
    for oid in (b'', b'\x80', b'\x80\x01', b'\x2a\x80\x01', b'\x2a\x81'):
        yield add('malformed-OID', name(attribute(oid=oid)), expected='none')
    for fields in (A.tlv(6, b'\x55\x04\x03'), A.tlv(12,b'a'), A.tlv(6,b'\x55\x04\x03')+A.tlv(12,b'a')*2,
                   A.tlv(12,b'a')+A.tlv(6,b'\x55\x04\x03')):
        yield add('attribute-field-count-and-order', name(A.tlv(48,fields)), expected='none')
    for data in (b'', b'\x31\x00', b'\x30\x80\x00\x00', sample+b'\x00', A.tlv(48,attribute())):
        yield add('malformed-Name-envelope', data, expected='none')
    for count in (128, 1024, 4096):
        yield add('many-RDN-tail-walk', name(*([attribute()]*count)), mode='1', expected='supported')
        yield add('many-SET-members-tail-walk', name(attribute()*count), mode='1', expected='supported')
    for size in (32767, 32768, 32769):
        yield add('large-DirectoryString-character-bound', name(attribute(b'\x55\x04\x04', 12, b'a'*size)), mode='1',
                  expected='supported' if size<=32768 else 'none')
    # A complete unknown-attribute Name of exactly the DER owner's size bound.
    for size in (65514, 65515, 65516):
        data = name(attribute(b'\x2a\x03', 4, bytes(size)))
        assert len(data) == size+20
        yield add('exact-Name-input-bound', data, mode='1', expected='deferred' if len(data)<=65535 else 'none')
    for filename in ('x509_hostname_vectors.json','x509_san_vectors.json','x509_eku_vectors.json'):
        for peer in json.loads((ROOT/filename).read_text())['records']:
            data = bytes.fromhex(peer['certificate_der']); parsed = C.parse(data)
            yield add('signed-certificate-Name-fields', data, mode='2')
            for field in ('issuer', 'subject'):
                yield add('signed-certificate-exact-attribute-fields', parsed[field])
            outer = C.elements(A.complete(data,48)); fields = C.elements(outer[0][1]); shift = int(fields[0][0]==160)
            for index, bad in ((2+shift,b'\x30\x00'), (2+shift,b'\x30\x02\x31\x00'), (4+shift,b'\x30\x02\x31\x00')):
                replacements = [item[2] for item in fields]; replacements[index]=bad
                yield add('certificate-actual-issuer-subject-schema', C.assemble(A.tlv(48,b''.join(replacements)),outer[1][2]), mode='2', expected='none')
    for peer in json.loads((ROOT/'x509_name_vectors.json').read_text())['records']:
        data = bytes.fromhex(peer['certificate_der']); parsed = C.parse(data)
        yield add('signed-Name-schema-controls', data, mode='2', expected=peer['Name_status'])
        for field in ('issuer', 'subject'):
            yield add('signed-Name-exact-attribute-controls', parsed[field])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report',type=Path); parser.add_argument('binary',nargs=argparse.REMAINDER)
    args=parser.parse_args(); binary=args.binary[1:] if args.binary[:1]==['--'] else args.binary
    if not binary: parser.error('supply evaluator')
    counts, identity=Counter(),hashlib.sha256()
    with tempfile.TemporaryDirectory(prefix='grounds-name-') as directory:
        root=Path(directory)
        def evaluate(rows):
            command=binary+['check']
            for index,(group,mode,data,expected) in enumerate(rows):
                path=root/f'{index}.der'; path.write_bytes(data); command += [mode,str(path)]
                identity.update(json.dumps([group,mode,data.hex(),expected]).encode())
            result=subprocess.run(command,capture_output=True,text=True,timeout=25)
            assert result.returncode==0,(result.returncode,result.stderr)
            assert result.stdout.splitlines()==[r[3] for r in rows],(sum(counts.values()),result.stdout,[r[3] for r in rows])
            counts.update(row[0] for row in rows)
        batch=[]
        for row in cases():
            large=len(row[2])>4096
            if len(batch)==32 or large:
                if batch: evaluate(batch); batch=[]
            if large: evaluate([row])
            else: batch.append(row)
        if batch: evaluate(batch)
    report={'total':sum(counts.values()),'groups':dict(counts),'corpus_sha256':identity.hexdigest(),'binary':binary,
            'unknown_attributes_and_Teletex_deferred':True,'normalized_Name_comparison_constraints_or_authorization':False}
    if args.report: args.report.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,sort_keys=True))


if __name__=='__main__': main()
