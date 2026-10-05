"""Independent TLS extension-vector oracle; body semantics remain caller-owned."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import random
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parent


def entry(kind, body=b''):
    return kind.to_bytes(2, 'big') + len(body).to_bytes(2, 'big') + body


def vector(payload):
    return len(payload).to_bytes(2, 'big') + payload


def expected(data):
    if data == 'nonbyte' or len(data) < 2 or len(data) > 65537:
        return 'invalid'
    if int.from_bytes(data[:2], 'big') != len(data)-2:
        return 'invalid'
    cursor, seen, parsed = 2, set(), []
    while cursor < len(data):
        if len(data)-cursor < 4:
            return 'invalid'
        kind = int.from_bytes(data[cursor:cursor+2], 'big')
        size = int.from_bytes(data[cursor+2:cursor+4], 'big')
        cursor += 4
        if kind in seen or size > len(data)-cursor:
            return 'invalid'
        seen.add(kind)
        parsed.append((kind, data[cursor:cursor+size]))
        cursor += size
    normalized = b''.join(entry(kind, body) for kind, body in parsed)
    return f'ok:{len(parsed)}:{normalized.hex()}'


def cases(stress):
    if stress:
        result = []
        # Cover every uint16 bitset position, in legal-sized distinct vectors.
        for start in range(0,65536,16383):
            result.append(('all-types',vector(b''.join(entry(k) for k in range(start,min(start+16383,65536))))))
        full = b''.join(entry(k, b'abc' if k == 0 else b'') for k in range(16383))
        result += [('maximum-body',vector(entry(65535,b'\x5a'*65531))),
                   ('maximum-vector',vector(full)),
                   ('maximum-duplicate',vector(full[:-4]+entry(0))),
                   ('oversized-vector',b'\xff\xff'+bytes(65536))]
        # A duplicate at opposite ends with all intervening types distinct.
        result.append(('distant-duplicate',vector(b''.join(entry(k) for k in range(16382))+entry(0))))
        return result
    result = [('empty',b'\x00\x00'),('missing-length',b''),('short-length',b'\x00'),('nonoctet','nonbyte')]
    for kind in (0,1,30,31,32,33,255,256,32767,32768,65534,65535):
        result += [('bitset-boundary',vector(entry(kind,b'\x00\xff'))),
                   ('duplicate',vector(entry(kind)+entry(kind,b'a')))]
    for kind in range(0,65536,257):
        result.append(('unknown-type',vector(entry(kind))))
    data=json.loads((ROOT/'tls_handshake_vectors.json').read_text())
    for trace in data['traces']:
        for row in trace['operations']:
            if 'construct ' not in row['operation']:continue
            name,encoded=next(iter(row['fields'].items()))
            if name not in ('ClientHello','ServerHello','HelloRetryRequest','EncryptedExtensions'):continue
            raw=bytes.fromhex(encoded);body=raw[4:]
            assert len(body)==int.from_bytes(raw[1:4],'big')
            if raw[0] in (1,2):
                pos=35+body[34]
                if raw[0]==1:
                    size=int.from_bytes(body[pos:pos+2],'big');pos+=2+size
                    size=body[pos];pos+=1+size
                else:pos+=3
                raw=body[pos:]
            else:raw=body
            assert expected(raw).startswith('ok:')
            result.append(('rfc8448',raw))
            for stop in range(len(raw)):
                result.append(('published-truncation',raw[:stop]))
            result.append(('published-trailing-byte',raw+b'\x00'))
    rng=random.Random(984643)
    for _ in range(128):
        kinds=rng.sample(range(65536),rng.randrange(1,17))
        encoded=b''.join(entry(k,rng.randbytes(rng.randrange(65))) for k in kinds)
        result.append(('random-valid',vector(encoded)))
        result.append(('random-duplicate',vector(encoded+entry(kinds[0]))))
        result.append(('random-declared-short', (len(encoded)-1).to_bytes(2,'big')+encoded))
    for size in range(1,4):result.append(('partial-header',vector(bytes(size))))
    result += [('short-body',vector(b'\x00\x01\x00\x02\x00')),
               ('oversized-body-declaration',vector(b'\x00\x01\xff\xff')),
               ('zero-length-body',vector(entry(51))),
               ('psk-order-is-caller-owned',vector(entry(41)+entry(43))),
               ('unknown-body-is-opaque',vector(entry(0xaaaa,b'\xff\xff\x00')))]
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stress',action='store_true')
    parser.add_argument('--report',type=Path)
    parser.add_argument('binary',nargs=argparse.REMAINDER)
    args=parser.parse_args();binary=args.binary[1:] if args.binary[:1]==['--'] else args.binary
    if not binary:parser.error('compiled evaluator required')
    start=time.monotonic();counts=Counter();corpus=hashlib.sha256();rows=cases(args.stress)
    with tempfile.TemporaryDirectory(prefix='grounds-tls-extensions-') as folder:
        for offset in range(0,len(rows),32):
            command=[*binary,'run'];wanted=[]
            for index,(name,data) in enumerate(rows[offset:offset+32]):
                value=expected(data);wanted.append(value);counts[name]+=1
                corpus.update(json.dumps([name,data if isinstance(data,str) else data.hex(),value],separators=(',',':')).encode()+b'\n')
                if isinstance(data,str):command.append(data)
                else:
                    path=Path(folder)/f'{index}.bin';path.write_bytes(data);command.append(str(path))
            run=subprocess.run(command,text=True,capture_output=True,timeout=110)
            assert run.returncode==0,(offset,run.returncode,run.stderr[-2000:])
            actual=run.stdout.splitlines();assert len(actual)==len(wanted),(offset,len(actual),len(wanted))
            for index,(got,want) in enumerate(zip(actual,wanted)):
                assert got==want,(offset+index,got[:100],want[:100])
    report={'cases':len(rows),'groups':dict(counts),'stress':args.stress,'corpus_sha256':corpus.hexdigest(),
            'elapsed_seconds':round(time.monotonic()-start,3),'binary':binary,'full_tls_or_extension_semantics':False,
            'source_sha256':{name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in ('tls_extensions.bend','tls_extensions_cli.bend','tls_extensions_check.py','tls_handshake_vectors.json')}}
    if args.report:args.report.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,sort_keys=True))


if __name__=='__main__':main()
