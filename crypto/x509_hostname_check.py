"""Independent typed DNS/IP matching and actual SAN/certificate field oracle."""
import argparse
from collections import Counter
import hashlib
import itertools
import json
from pathlib import Path
import random
import re
import subprocess
import tempfile

import x509_algorithm_check as A
import x509_certificate_check as C
import x509_extensions_check as E

ROOT=Path(__file__).parent
SAN=bytes.fromhex('551d11')
LABEL=re.compile(rb'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?')


def domain(name):
    return len(name)<=253 and all(LABEL.fullmatch(label) for label in name.split(b'.'))


def dns(pattern, reference):
    if not domain(reference) or len(pattern)>253:
        return False
    if pattern.startswith(b'*.'):
        suffix=pattern[2:]
        return domain(suffix) and reference.partition(b'.')[2].lower()==suffix.lower()
    return domain(pattern) and pattern.lower()==reference.lower()


def ip(presented, reference):
    return len(presented) in (4,16) and len(reference) in (4,16) and presented==reference


def frame(data):
    if len(data)>65535:
        raise ValueError('input bound')
    names=C.elements(A.complete(data,48))
    if not names:
        raise ValueError('empty SAN')
    for tag,body,_ in names:
        if tag in (129,130,134):
            if not body or any(byte>=128 for byte in body):
                raise ValueError('nonempty IA5')
        elif tag==135:
            if len(body) not in (4,16):
                raise ValueError('IP length')
        elif tag==136:
            E.oid_contents(body)
        elif tag in (160,163,164,165):
            if not body:
                raise ValueError('empty constructed GeneralName framing')
        else:
            raise ValueError('GeneralName choice/tag')
    return names


def payload(data, certificate=False):
    if certificate:
        data=C.parse(data)['extensions']
        if data is None:
            return None
    E.extensions(data)
    for _,body,_ in C.elements(A.complete(data,48)):
        fields=C.elements(body)
        if fields[0][1]==SAN:
            return fields[-1][1]
    return None


def oracle(mode,data,reference,kind):
    try:
        if mode=='0': return str(dns(data,reference)).lower()
        if mode=='1': return str(ip(data,reference)).lower()
        if mode in ('3','4'):
            data=payload(data,mode=='4')
            if data is None: return 'false'
        names=frame(data)
        if mode=='5': return ''.join(f'{tag}:{body.hex()};' for tag,body,_ in names)
        return str(any(dns(body,reference) if tag==130 and kind=='0' else ip(body,reference) if tag==135 and kind=='1' else False for tag,body,_ in names)).lower()
    except (ValueError,IndexError):
        return 'none' if mode=='5' else 'false'


def identity_cases():
    def add(group,mode,data,reference,expected=None):
        value=oracle(mode,data,reference,'0')
        if expected is not None: assert value==expected,(group,value,expected)
        return group,mode,data,reference,'0',value
    for pattern,ref,expected in [
        (b'API.Example.Test',b'api.example.test',True),(b'*.example.test',b'api.example.test',True),
        (b'*.example.test',b'a.b.example.test',False),(b'*.example.test',b'example.test',False),
        (b'api*.example.test',b'api1.example.test',False),(b'*.*.example.test',b'a.b.example.test',False),
        (b'api.example.test',b'api.example.test.evil',False),(b'api.example.test\x00.evil',b'api.example.test',False),
        (b'api.example.test',b'api.example.test\x00',False),(b'*.example.test',b'.example.test',False),
        (b'*.example.test',b'-x.example.test',False),(b'*.example.test',b'xn--bcher-kva.example.test',True),
        (b'xn--bcher-kva.example.test',b'XN--BCHER-KVA.example.test',True),
        (b'xn--bcher-kva.example.test','bücher.example.test'.encode(),False),
        (b'api.example.test.',b'api.example.test',False),(b'api.example.test',b'api.example.test.',False),
        (b'localhost',b'LOCALHOST',True),(b'*',b'localhost',False)]:
        yield add('literal-DNS-rules','0',pattern,ref,str(expected).lower())
    for byte in range(256):
        for candidate in (bytes([byte])+b'.example.test',b'a'+bytes([byte])+b'.example.test',b'a'+bytes([byte])+b'b.example.test'):
            yield add('every-DNS-octet-and-position','0',candidate,candidate)
            yield add('wildcard-reference-validation','0',b'*.example.test',candidate)
    for size in (0,1,2,62,63,64,65,127,128,253,254,255,4096,65535,65536):
        name=b'a'*size+b'.test'
        yield add('label-size-bound','0',name,name)
        yield add('wildcard-label-size-bound','0',b'*.test',name)
    for total in (252,253,254,255):
        name=b'.'.join([b'a'*63]*3+[b'b'*(total-192)])
        assert len(name)==total
        yield add('total-domain-size-bound','0',name,name,str(total<=253).lower())
    rng=random.Random(9525)
    for _ in range(256):
        labels=[bytes(rng.choice(b'abcXYZ012345') for _ in range(rng.randrange(1,64))) for _ in range(rng.randrange(1,5))]
        name=b'.'.join(labels)
        yield add('random-exact-case','0',name,name.swapcase())
        yield add('random-nonmatching-suffix','0',name,name+b'.evil')
        if len(labels)>1:
            yield add('random-one-label-wildcard','0',b'*.'+b'.'.join(labels[1:]),name)
    for size,positions in ((4,range(4)),(16,(0,7,15))):
        for position in positions:
            for byte in range(256):
                address=bytearray(size);address[position]=byte
                other=bytearray(address);other[position]^=1
                yield add('every-IP-octet-selected-positions','1',bytes(address),bytes(address),'true')
                yield add('every-IP-octet-mismatch','1',bytes(address),bytes(other),'false')
    for size in (*range(0,19),4096,65535,65536):
        yield add('IP-length-bound','1',bytes(size),bytes(size),str(size in (4,16)).lower())
    yield add('IPv4-mapped-IPv6-not-alias','1',bytes.fromhex('c0000201'),bytes.fromhex('00000000000000000000ffffc0000201'),'false')


def hostname_cases():
    def add(group,mode,data,reference=b'api.example.test',kind='0',expected=None):
        value=oracle(mode,data,reference,kind)
        if expected is not None: assert value==expected,(group,value,expected)
        return group,mode,data,reference,kind,value
    def san(*entries): return A.tlv(48,b''.join(A.tlv(tag,body) for tag,body in entries))
    good=(130,b'api.example.test')
    for tag in range(256):
        yield add('every-GeneralName-tag','5',san((tag,b'x')))
    for tag in (129,130,134):
        for byte in range(256):
            data=san(good,(tag,bytes([byte])))
            yield add('IA5-complete-framing-before-match','2',data)
            yield add('IA5-exact-framing-retention','5',data)
    for size in range(0,33):
        yield add('SAN-IP-exact-length','5',san((135,bytes(size))))
    for oid in (b'',b'\x2a',b'\x80\x00',b'\x81',b'\x88\x37\x03',b'\x81'*1024+b'\x01'):
        yield add('registeredID-canonical-arcs','5',san((136,oid)))
    # Constructed contents survive untouched and remain semantically pending.
    for tag in (160,163,164,165):
        yield add('constructed-form-retained-not-schema-admitted','5',san(good,(tag,b'\x00')))
    data=san(good,(135,bytes.fromhex('c0000201')),(135,bytes.fromhex('20010db8000000000000000000000001')))
    for kind,reference,expected in (('0',b'API.example.test','true'),('0',b'192.0.2.1','false'),('1',bytes.fromhex('c0000201'),'true'),('1',bytes.fromhex('c0000202'),'false'),('1',bytes.fromhex('20010db8000000000000000000000001'),'true'),('2',b'api.example.test','false')):
        yield add('literal-SAN-typed-identity','2',data,reference,kind,expected)
    for bad in (b'',b'\x30\x00',b'\x30\x80\x00\x00',data+b'\x00',A.tlv(49,A.tlv(*good)),A.tlv(48,A.tlv(*good)+b'\x82'),san(good,(135,b'x'))):
        yield add('malformed-later-frame-cannot-hide','2',bad,expected='false')
    for cut in range(len(data)):
        yield add('every-SAN-truncation','5',data[:cut],expected='none')
    for index in range(len(data)):
        for bit in range(8):
            mutated=bytearray(data);mutated[index]^=1<<bit
            yield add('every-SAN-bit-mutation','2',bytes(mutated))
    for pattern in (b'api*.example.test',b'*.*.example.test',b'bad_name.example.test'):
        yield add('invalid-pattern-ignored-other-DNS-can-match','2',san((130,pattern),good),expected='true')
    for permutation in itertools.permutations([good,(129,b'a@example.test'),(134,b'https://wrong.example.test')]):
        yield add('SAN-order-other-form-no-type-confusion','2',san(*permutation),expected='true')
        yield add('SAN-order-exact-retention','5',san(*permutation))
    for count in (128,1024,8192):
        yield add('many-SAN-entries','2',san(*([(130,b'x')]*count+[good])),expected='true')
    for total in (4096,65535,65536):
        for size in range(total-12,total):
            data=san((134,b'x'*size))
            if len(data)==total:
                yield add('exact-SAN-input-bound','5',data)
                break
        else: raise AssertionError(total)
    data=san(good)
    valid=E.extension(SAN,data)
    critical=E.extension(SAN,data,b'\xff')
    for entries,expected in ((valid,'true'),(critical,'true'),(valid+valid,'false'),(E.extension(SAN+b'\x00',data),'false'),(E.extension(b'\x2a\x03',data),'false')):
        yield add('actual-extension-OID-criticality-duplicates','3',A.tlv(48,entries),expected=expected)
    for peer in json.loads((ROOT/'x509_hostname_vectors.json').read_text())['records']:
        data=bytes.fromhex(peer['certificate_der'])
        for row in peer['references']:
            yield add('signed-OpenSSL-no-CN-no-partial-wildcard-reference','4',data,bytes.fromhex(row['reference']),'0' if row['kind']=='DNS' else '1',str(row['accepted']).lower())
        yield add('signed-certificate-every-last-octet-truncation','4',data[:-1],expected='false')
    peers=json.loads((ROOT/'x509_algorithm_vectors.json').read_text())['peers']
    source=bytes.fromhex(peers[0]['certificate_der'])
    outer=C.elements(A.complete(source,48));fields=C.elements(outer[0][1]);fields=fields[1:] if fields[0][0]==160 else fields
    mandatory=[item[2] for item in fields[:6]]
    for version in (0,1,2):
        prefix=b'' if version==0 else A.tlv(160,A.tlv(2,bytes([version])))
        for extension in (None,valid,critical,valid+valid):
            tbs=A.tlv(48,prefix+b''.join(mandatory)+(A.tlv(163,A.tlv(48,extension)) if extension else b''))
            yield add('certificate-version-actual-SAN-field','4',C.assemble(tbs,outer[1][2]))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scope',choices=('identity','all'),default='all')
    parser.add_argument('--report',type=Path)
    parser.add_argument('binary',nargs=argparse.REMAINDER)
    args=parser.parse_args();binary=args.binary[1:] if args.binary[:1]==['--'] else args.binary
    if not binary: parser.error('supply evaluator')
    counts,identity=Counter(),hashlib.sha256()
    with tempfile.TemporaryDirectory(prefix='grounds-hostname-') as directory:
        root=Path(directory)
        def evaluate(rows):
            command=binary+['check']
            for index,(group,mode,data,reference,kind,expected) in enumerate(rows):
                path=root/f'{index}-data.der';path.write_bytes(data);command.extend([mode,str(path)])
                if mode!='5':
                    path=root/f'{index}-reference.bin';path.write_bytes(reference);command.append(str(path))
                    if args.scope=='all': command.append(kind)
                identity.update(json.dumps([group,mode,data.hex(),reference.hex(),kind,expected]).encode())
            result=subprocess.run(command,capture_output=True,text=True,timeout=25)
            assert result.returncode==0,(sum(counts.values()),result.returncode,result.stderr)
            assert result.stdout.splitlines()==[row[5] for row in rows],(sum(counts.values()),[r[:2] for r in rows],result.stdout,[r[5] for r in rows])
            counts.update(row[0] for row in rows)
        batch=[]
        rows=itertools.chain(identity_cases(),hostname_cases()) if args.scope=='all' else identity_cases()
        for row in rows:
            large=max(len(row[2]),len(row[3]))>4096
            if len(batch)==32 or large:
                if batch: evaluate(batch);batch=[]
            if large: evaluate([row])
            else: batch.append(row)
        if batch: evaluate(batch)
    report={'binary':binary,'scope':args.scope,'total':sum(counts.values()),'groups':dict(counts),'corpus_sha256':identity.hexdigest(),'GeneralName_schema_or_profile_admission':False,'chain_trust_time_or_peer_authorization':False,'Unicode_IDNA_reference_construction':False}
    if args.report: args.report.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,sort_keys=True))


if __name__=='__main__': main()
