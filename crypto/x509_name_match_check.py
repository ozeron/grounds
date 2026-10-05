"""DER Name equality against independent Unicode 3.2 RDN multiset models."""
import argparse
from collections import Counter
import hashlib
import itertools
import json
from pathlib import Path
import random
import struct
import subprocess
import sys
import tempfile

import x509_name_check as N
from x509_name_prepare_check import expected as attribute_oracle

ROOT = Path(__file__).resolve().parent
CN, ORG, NAME = (bytes.fromhex(s) for s in ['550403', '55040a', '550429'])


def prepared(data):
    rdns, _ = N.parse(data)
    result = []
    for attrs in rdns:
        keys = []
        for oid, tag, body, _ in attrs:
            if oid == N.DC:
                # Name parsing has already applied the independent IA5 schema.
                # No Unicode preparation, space compression or DNS fallback.
                value = list(body.lower())
            else:
                value = attribute_oracle(oid, tag, body)
            if value is None:
                raise ValueError('unsupported/failed attribute preparation')
            keys.append((oid, tuple(value)))
        result.append(Counter(keys))
    return result


def expected(a, b):
    try:
        return 'same' if prepared(a) == prepared(b) else 'different'
    except (ValueError, UnicodeError):
        return 'none'


def attribute(oid=CN, tag=12, text='a'):
    codec = {12:'utf-8', 19:'ascii', 28:'utf-32-be', 30:'utf-16-be'}[tag]
    return oid, tag, text.encode(codec)


def name(rdns):
    # DER sorts the original complete encodings only inside each SET OF.
    return N.A.tlv(48, b''.join(N.A.tlv(49, b''.join(sorted(
        N.attribute(oid, tag, body) for oid, tag, body in attrs))) for attrs in rdns))


def cases():
    def row(kind, a, b, wanted=None):
        result = expected(a, b)
        if wanted is not None:
            assert result == wanted, ('literal oracle', kind, result, wanted)
        return kind, a, b, result
    empty = name([])
    a = attribute(text='a'); b = attribute(text='b'); upper = attribute(tag=19, text='A')
    literals = [
        ('empty-Name', empty, empty, 'same'),
        ('RDN-count', empty, name([[a]]), 'different'),
        ('attribute-OID-binding', name([[a]]), name([[attribute(ORG)]]), 'different'),
        ('cross-encoding-case', name([[a]]), name([[upper]]), 'same'),
        ('BMP-case', name([[attribute(tag=30, text='A')]]), name([[a]]), 'same'),
        ('Universal-case', name([[attribute(tag=28, text='A')]]), name([[a]]), 'same'),
        ('canonical-compose', name([[attribute(text='A\u030a')]]), name([[attribute(text='\u00c5')]]), 'same'),
        ('fold-expansion', name([[attribute(text='Stra\u00dfe')]]), name([[attribute(tag=19,text='STRASSE')]]), 'same'),
        ('stored-space', name([[attribute(text='  FOO   BAR ')]]), name([[attribute(tag=19,text='foo bar')]]), 'same'),
        ('RDN-order', name([[a],[b]]), name([[b],[a]]), 'different'),
        ('RDN-partition', name([[a,b]]), name([[a],[b]]), 'different'),
        ('multiplicity-not-membership', name([[a,a,b]]), name([[a,b,b]]), 'different'),
        ('normalized-multiplicity', name([[a,upper,b]]), name([[upper,a,b]]), 'same'),
        ('attribute-count', name([[a]]), name([[a,upper]]), 'different'),
        ('DER-order-changes-after-preparation',
         name([[attribute(CN,12,'FoO'), attribute(ORG,19,'ACME')]]),
         name([[attribute(ORG,12,'acme'), attribute(CN,19,'foo')]]), 'same'),
        ('prohibited-is-not-equal-to-itself', name([[attribute(text='\u0221')]]), name([[attribute(text='\u0221')]]), 'none'),
        ('mapped-empty-is-supported', name([[attribute(text='\u00ad')]]), name([[attribute(text=' ')]]) , 'same'),
        ('domainComponent-ASCII-case', name([[(N.DC,22,b'EXAMPLE')]]), name([[(N.DC,22,b'example')]]), 'same'),
        ('domainComponent-A-label', name([[(N.DC,22,b'XN--BCHER-KVA')]]), name([[(N.DC,22,b'xn--bcher-kva')]]), 'same'),
        ('domainComponent-no-space-removal', name([[(N.DC,22,b' example ')]]), name([[(N.DC,22,b'example')]]), 'different'),
        ('domainComponent-no-space-compression', name([[(N.DC,22,b'a  b')]]), name([[(N.DC,22,b'a b')]]), 'different'),
        ('domainComponent-no-control-deletion', name([[(N.DC,22,b'A\0')]]), name([[(N.DC,22,b'a')]]), 'different'),
        ('domainComponent-no-DirectoryString-coercion', name([[(N.DC,12,b'EXAMPLE')]]), name([[(N.DC,22,b'example')]]), 'none'),
        ('domainComponent-no-nonASCII-coercion', name([[(N.DC,22,b'\xc5')]]), name([[(N.DC,22,b'a')]]), 'none'),
        ('domainComponent-RDN-order', name([[(N.DC,22,b'example')],[(N.DC,22,b'com')]]), name([[(N.DC,22,b'com')],[(N.DC,22,b'example')]]), 'different'),
        ('domainComponent-OID-binding', name([[(N.DC,22,b'example')]]), name([[attribute(text='example')]]), 'different'),
        ('legacy-email-profile-deferred', name([[(N.EMAIL,22,b'A@example.test')]]), name([[(N.EMAIL,22,b'A@example.test')]]), 'none'),
        ('Teletex-profile-deferred', name([[(CN,20,b'A')]]), name([[(CN,20,b'A')]]), 'none'),
        ('unknown-rule-deferred', name([[(bytes.fromhex('2a0304'),4,b'x')]]), name([[(bytes.fromhex('2a0304'),4,b'x')]]), 'none'),
        ('malformed-later-attribute', name([[a],[(CN,12,b'\xff')]]), name([[a]]), 'none'),
    ]
    for args in literals:
        yield row(*args)
        yield row(args[0]+'/reverse',args[2],args[1],args[3])
    for byte in range(256):
        a = name([[(N.DC,22,bytes([byte]))]])
        b = name([[(N.DC,22,bytes([byte]).lower())]])
        yield row('domainComponent-all-octets',a,b,'same' if byte<128 else 'none')
    for x in range(128):
        for y in range(128):
            yield row('domainComponent-all-ASCII-pairs',
                      name([[(N.DC,22,bytes([x]))]]), name([[(N.DC,22,bytes([y]))]]),
                      'same' if bytes([x]).lower()==bytes([y]).lower() else 'different')
    for count in [0,1,63,64,65522,65523,65524,65535,65536]:
        a = name([[(N.DC,22,b'A'*count)]])
        b = name([[(N.DC,22,b'a'*count)]])
        yield row('domainComponent-complete-Name-bound',a,b)
    for kind, mode, data, _ in N.cases():
        if mode == '2':
            cert = N.C.parse(data)
            yield row('actual-certificate-issuer-subject',cert['issuer'],cert['subject'])
        else:
            yield row('schema/self/'+kind,data,data)
    randomizer = random.Random(5280714518)
    words = ['a','A','foo bar','  FOO   BAR ','Stra\u00dfe','STRASSE','A\u030a',
             '\u00c5','\u00ad',' ','\u05d0A','\u13a0','\u1c90','\ufdfa','x\u0315\u0323\u0300']
    for i in range(1024):
        rdns = []
        for _ in range(randomizer.randrange(1,6)):
            attrs = []
            for _ in range(randomizer.randrange(1,7)):
                oid = randomizer.choice([CN, ORG, NAME])
                text = randomizer.choice(words)
                tag = randomizer.choice([12,28,30])
                attrs.append(attribute(oid,tag,text))
            rdns.append(attrs)
        other = [list(attrs) for attrs in rdns]
        for attrs in other: randomizer.shuffle(attrs)
        choice = i % 4
        if choice == 1: other.reverse()
        if choice == 2: other[0].append(other[0][0])
        if choice == 3: other[0][0] = attribute(CN,19,'different')
        yield row('seeded-multiset-sequence-profile',name(rdns),name(other))
    # Exhaustive small duplicate distributions defeat set-membership matching.
    # Earlier schema/boundary loops rebind a/b to complete DER Names. Build
    # these attribute triples explicitly so the exhaustive corpus remains valid.
    pool = [attribute(text='a'), upper, attribute(text='b'), attribute(ORG,19,'a')]
    for left in itertools.product(pool,repeat=3):
        for right in itertools.product(pool,repeat=3):
            yield row('exhaustive-duplicate-multisets',name([left]),name([right]))
    # Large RDNs exercise the affine mergesort, not quadratic candidate scans.
    for count in [128,1024,4096]:
        values = [attribute(NAME,12,f'{i:04d}') for i in range(count)]
        a = name([values]); b = name([[attribute(NAME,19,f'{i:04d}') for i in reversed(range(count))]])
        yield row('large-RDN-cross-encoding-sort',a,b)
        altered = list(values); altered[-1] = values[0]
        yield row('large-RDN-multiplicity-change',a,name([altered]))
    for count in [32767,32768,32769]:
        a = name([[attribute(NAME,12,'A'*count)]])
        b = name([[attribute(NAME,19,'a'*count)]])
        yield row('large-prepared-key',a,b)
    # Exactly 65,535 Name octets; 2-byte scalars expand to two folded scalars.
    for count in [32756,32757,32758]:
        a = name([[attribute(NAME,12,'\u00df'*count)]])
        yield row('complete-Name-octet-bound',a,a)
    a = name([[attribute(NAME,12,'\ufdfa'*21838)]])
    yield row('packed-normalization-expansion-key',a,a)


def batch_bytes(rows):
    data = bytearray(struct.pack('>I',len(rows)))
    for _, a, b, _ in rows:
        data.extend(struct.pack('>I',len(a)));data.extend(a)
        data.extend(struct.pack('>I',len(b)));data.extend(b)
    return data


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report',type=Path)
    parser.add_argument('--mode',choices=['all','regular','stress'],default='all')
    parser.add_argument('--limit',type=int,help='diagnostic prefix, not full acceptance')
    parser.add_argument('--phase-prefix',help='Declare each unchanged evaluator batch as a guarded resource phase')
    parser.add_argument('binary',nargs=argparse.REMAINDER)
    args=parser.parse_args();binary=args.binary[1:] if args.binary[:1]==['--'] else args.binary
    if not binary: parser.error('supply evaluator')
    if args.limit is not None and args.limit<0: parser.error('limit must be nonnegative')
    if args.phase_prefix:
        sys.path.insert(0,str(ROOT.parent/'tools'))
        from check_phase import announce
    counts,identity=Counter(),hashlib.sha256()
    batch_index=0
    with tempfile.TemporaryDirectory(prefix='grounds-name-match-') as directory:
        paths=[Path(directory)/f'batch-{i}.bin' for i in range(2)]
        def evaluate(rows):
            nonlocal batch_index
            phase=f'{args.phase_prefix}/{args.mode}/batch-{batch_index:03d}'
            if args.phase_prefix:announce(['start',phase])
            selected=[]
            for i,start in enumerate(range(0,len(rows),64)):
                data=batch_bytes(rows[start:start+64]);paths[i].write_bytes(data)
                selected.append(str(paths[i]));identity.update(data)
            result=subprocess.run([*binary,'check',str(ROOT/'unicode32_nfkc.bin'),str(ROOT/'unicode32_prepare.bin'),*selected],capture_output=True,text=True,timeout=100)
            assert result.returncode==0,(result.returncode,result.stderr[-1200:])
            actual=result.stdout.splitlines()
            assert len(actual)==len(rows),(len(actual),len(rows))
            for answer,(kind,a,b,wanted) in zip(actual,rows):
                assert answer==wanted,(sum(counts.values()),kind,len(a),len(b),answer,wanted)
                identity.update(json.dumps([kind,wanted]).encode());counts[kind]+=1
            if args.phase_prefix:announce(['end',phase,'0'])
            batch_index+=1
        pending=[]
        def selected():
            for row in cases():
                large=max(len(row[1]),len(row[2]))>4096
                if args.mode=='all' or large==(args.mode=='stress'):
                    yield row
        source=selected() if args.limit is None else itertools.islice(selected(),args.limit)
        for row in source:
            if len(pending)==128 or max(len(row[1]),len(row[2]))>4096:
                if pending:evaluate(pending);pending=[]
            if max(len(row[1]),len(row[2]))>4096:evaluate([row])
            else:pending.append(row)
        if pending:evaluate(pending)
    report={'binary':binary,'mode':args.mode,'total':sum(counts.values()),'groups':dict(counts),
            'evaluator_batches':batch_index,
            'complete_selected_mode':args.limit is None,'complete_corpus':args.limit is None and args.mode=='all',
            'corpus_sha256':identity.hexdigest(),'RDN_multisets_preserve_multiplicity_and_sequence':True,
            'domainComponent':'ASCII case insensitive exact IA5; DNS/IDNA label validity separate',
            'unknown_Teletex_legacy_email_profiles':'unsupported','chain_constraints_trust_or_issuer_authorization':False}
    if args.report:args.report.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,sort_keys=True))


if __name__=='__main__':main()
