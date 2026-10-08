"""Independent TLS 1.3 Hello field/framing oracle; no negotiation acceptance."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import random
import subprocess
import tempfile
import time

from tls_extensions_check import entry, vector

ROOT=Path(__file__).resolve().parent
RETRY=hashlib.sha256(b'HelloRetryRequest').digest()


def frame(kind,body):return bytes([kind])+len(body).to_bytes(3,'big')+body


def client(random_bytes=bytes(32),session=b'',suites=b'\x13\x01',extensions=None,compression=b'\x00'):
    if extensions is None:extensions=entry(43,b'\x02\x03\x04')
    return frame(1,b'\x03\x03'+random_bytes+bytes([len(session)])+session+len(suites).to_bytes(2,'big')+suites+bytes([len(compression)])+compression+vector(extensions))


def server(random_bytes=bytes(32),session=b'',suite=b'\x13\x01',extensions=None,compression=0):
    if extensions is None:extensions=entry(43,b'\x03\x04')
    return frame(2,b'\x03\x03'+random_bytes+bytes([len(session)])+session+suite+bytes([compression])+vector(extensions))


class Invalid(Exception):pass


def expected(raw):
    if raw=='nonbyte':return 'error:decode'
    if len(raw)>131146:return 'error:overflow'
    if len(raw)<4 or raw[0] not in (1,2):return 'error:decode'
    kind,size=raw[0],int.from_bytes(raw[1:4],'big')
    if size!=len(raw)-4:return 'error:decode'
    if size>(131142 if kind==1 else 65607):return 'error:overflow'
    cursor=4
    def take(n):
        nonlocal cursor
        if len(raw)-cursor<n:raise Invalid('decode')
        value=raw[cursor:cursor+n];cursor+=n;return value
    def integer(n):return int.from_bytes(take(n),'big')
    try:
        if integer(2)!=0x0303:raise Invalid('version')
        random_bytes=take(32)
        session_size=integer(1)
        if session_size>32:raise Invalid('decode')
        session=take(session_size)
        if kind==1:
            size=integer(2)
            if not 2<=size<=65534 or size%2:raise Invalid('decode')
            selected=take(size)
            count=integer(1)
            if count!=1:raise Invalid('compression')
            if integer(1)!=0:raise Invalid('compression')
        else:
            selected=take(2)
            if integer(1)!=0:raise Invalid('compression')
        size=integer(2)
        if size<(7 if kind==1 else 6):raise Invalid('decode')
        if size!=len(raw)-cursor:raise Invalid('decode')
        start=cursor;seen=set()
        while cursor<len(raw):
            extension=integer(2);length=integer(2)
            if extension in seen:raise Invalid('decode')
            seen.add(extension);take(length)
        role='client' if kind==1 else 'retry' if random_bytes==RETRY else 'server'
        return f'{role}:{random_bytes.hex()}:{session.hex()}:{selected.hex()}:ok:{len(seen)}:{raw[start:].hex()}'
    except Invalid as error:return 'error:'+str(error)


def cases(stress):
    if stress:
        extensions=entry(65535,b'\x5a'*65531)
        largest=client(session=bytes(32),suites=b'\x13\x01'*32767,extensions=extensions)
        large_server=server(session=bytes(32),extensions=extensions)
        assert len(largest)==131146 and len(large_server)==65611
        return [('maximum-client',largest),('maximum-server',large_server),
                ('client-limit-plus-one',frame(1,largest[4:]+b'\x00')),
                ('server-limit-plus-one',frame(2,large_server[4:]+b'\x00')),
                ('all-offered-suite-values-low',client(suites=b''.join(v.to_bytes(2,'big') for v in range(32767)))),
                ('all-offered-suite-values-high',client(suites=b''.join(v.to_bytes(2,'big') for v in range(32767,65534)))),
                ('last-offered-suite-values',client(suites=b'\xff\xfe\xff\xff'))]
    rows=[('minimal-client',client()),('minimal-server',server()),('retry',server(random_bytes=RETRY)),('nonoctet','nonbyte')]
    traces=json.loads((ROOT/'tls_handshake_vectors.json').read_text())['traces']
    published=[]
    for trace in traces:
        for operation in trace['operations']:
            if 'construct ' not in operation['operation']:continue
            raw=bytes.fromhex(next(iter(operation['fields'].values())))
            if raw[0] in (1,2):
                assert not expected(raw).startswith('error:')
                published.append(raw);rows.append(('rfc8448',raw))
    for raw in published+[client(),server()]:
        for stop in range(len(raw)):
            rows.append(('truncated-frame',raw[:stop]))
            if stop>=4:rows.append(('truncated-body-reframed',frame(raw[0],raw[4:stop])))
        rows.append(('trailing-byte',raw+b'\x00'))
        rows.append(('trailing-byte-reframed',frame(raw[0],raw[4:]+b'\x00')))
        for version in (b'\x00\x00',b'\x03\x01',b'\x03\x02',b'\x03\x04'):
            rows.append(('legacy-version',raw[:4]+version+raw[6:]))
    for size in (0,1,31,32,33,255):
        rows.append(('session-size-client',client(session=bytes(size))))
        rows.append(('session-size-server',server(session=bytes(size))))
    for offered in (b'',b'\x13',b'\x13\x01\x13',b'\xff\xff',b'\x13\x01\x13\x01'):
        rows.append(('suite-shape-or-unknown',client(suites=offered)))
    for methods in (b'',b'\x01',b'\x00\x00',b'\x01\x00'):
        rows.append(('client-compression',client(compression=methods)))
    for method in (1,255):rows.append(('server-compression',server(compression=method)))
    for extensions in (b'',entry(0),entry(43,b'\x03\x04'),entry(43,b'\x02\x03\x04')+entry(43)):
        rows.append(('extension-framing-client',client(extensions=extensions)))
        rows.append(('extension-framing-server',server(extensions=extensions)))
    for i in range(32):
        damaged=bytearray(RETRY);damaged[i]^=1
        rows.append(('retry-marker-byte-mutation',server(random_bytes=bytes(damaged))))
    rows.append(('client-random-is-not-retry',client(random_bytes=RETRY)))
    rows.append(('context-validation-is-caller-owned',server(extensions=entry(0xaaaa,b'\x01\x02'))))
    for kind in (0,3,11,20,255):rows.append(('wrong-message-kind',frame(kind,b'')))
    rng=random.Random(984642)
    for _ in range(64):
        session=rng.randbytes(rng.randrange(33));random_bytes=rng.randbytes(32)
        extensions=entry(43,b'\x02\x03\x04')+entry(0xaaaa,rng.randbytes(rng.randrange(33)))
        suites=b''.join(rng.randrange(65536).to_bytes(2,'big') for _ in range(rng.randrange(1,17)))
        rows.append(('random-client',client(random_bytes,session,suites,extensions)))
        rows.append(('random-server',server(random_bytes,session,suites[:2],entry(43,b'\x03\x04'))))
    return rows


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stress',action='store_true');parser.add_argument('--report',type=Path)
    parser.add_argument('binary',nargs=argparse.REMAINDER);args=parser.parse_args()
    binary=args.binary[1:] if args.binary[:1]==['--'] else args.binary
    if not binary:parser.error('compiled evaluator required')
    start=time.monotonic();counts=Counter();corpus=hashlib.sha256();rows=cases(args.stress)
    with tempfile.TemporaryDirectory(prefix='grounds-tls-hello-') as folder:
        for offset in range(0,len(rows),32):
            command=[*binary,'run'];wanted=[]
            for index,(name,raw) in enumerate(rows[offset:offset+32]):
                want=expected(raw);wanted.append(want);counts[name]+=1
                corpus.update(json.dumps([name,raw if isinstance(raw,str) else raw.hex(),want],separators=(',',':')).encode()+b'\n')
                if isinstance(raw,str):command.append(raw)
                else:
                    path=Path(folder)/f'{index}.bin';path.write_bytes(raw);command.append(str(path))
            run=subprocess.run(command,text=True,capture_output=True,timeout=110)
            assert run.returncode==0,(offset,run.returncode,run.stderr[-1500:])
            actual=run.stdout.splitlines();assert len(actual)==len(wanted),(offset,len(actual),len(wanted))
            for index,(got,want) in enumerate(zip(actual,wanted)):
                assert got==want,(offset+index,rows[offset+index][0],got[:150],want[:150])
    result={'cases':len(rows),'groups':dict(counts),'stress':args.stress,'corpus_sha256':corpus.hexdigest(),'elapsed_seconds':round(time.monotonic()-start,3),'binary':binary,'negotiation_or_live_tls':False,
            'source_sha256':{name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in ('tls_hello.bend','tls_hello_cli.bend','tls_hello_check.py','tls_extensions.bend','tls_extensions_cli.bend','tls_extensions_check.py','tls_handshake_vectors.json')}}
    if args.report:args.report.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,sort_keys=True))


if __name__=='__main__':main()
