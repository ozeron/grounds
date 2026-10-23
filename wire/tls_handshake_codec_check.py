"""Independent bounded TLS 1.3 handshake codec/context oracle (no sockets/keys)."""
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
RETRY = bytes.fromhex('cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c')


def u16(n): return n.to_bytes(2, 'big')
def u24(n): return n.to_bytes(3, 'big')
def vec(b): return u16(len(b)) + b
def ext(k, b=b''): return u16(k) + vec(b)
def frame(k, b): return bytes([k]) + u24(len(b)) + b


class Rejected(Exception):
    def __init__(self, alert=50): self.alert = alert


class Reader:
    def __init__(self, data): self.data, self.pos = data, 0
    def take(self, n):
        if n > len(self.data) - self.pos: raise Rejected()
        result = self.data[self.pos:self.pos+n]; self.pos += n
        return result
    def integer(self, n): return int.from_bytes(self.take(n), 'big')
    def vector(self, n): return self.take(self.integer(n))
    def finish(self):
        if self.pos != len(self.data): raise Rejected()


ALLOWED = {0:{1,8,13}, 1:{1,8}, 5:{1,13,11}, 10:{1,8}, 13:{1,13},
           14:{1,8}, 15:{1,8}, 16:{1,8}, 18:{1,13,11}, 19:{1,8},20:{1,8},
           21:{1}, 27:{1,13},28:{1,8},41:{1,2},42:{1,8,4},43:{1,2,6},
           44:{1,6},45:{1},47:{1,13},48:{13},49:{1},50:{1,13},51:{1,2,6}}
OFFERED = {0,5,10,13,16,18,43,50,51,65000}


def extensions(data):
    r = Reader(data); body = Reader(r.vector(2)); r.finish(); values=[]; seen=set()
    while body.pos < len(body.data):
        kind=body.integer(2); data=body.vector(2)
        if kind in seen: raise Rejected()
        seen.add(kind); values.append((kind,data))
    return values


def validate(context, values, offered=OFFERED):
    seen=set()
    for kind,_ in values:
        independent = context in {1,13,4} or (context,kind) in {(6,44),(8,10)}
        allowed = context in ALLOWED.get(kind,{1,8,13,4})
        if kind in ALLOWED and not allowed: raise Rejected(47)
        if not allowed or not (independent or kind in offered): raise Rejected(110)
        if kind in seen: raise Rejected()
        seen.add(kind)


def flattened(values):
    return f'ok:{len(values)}:' + b''.join(ext(k,b) for k,b in values).hex()


def hello(k, data):
    r=Reader(data)
    if r.integer(2)!=771: raise Rejected(70)
    random=r.take(32); session=r.vector(1)
    if len(session)>32: raise Rejected()
    if k==1:
        suites=r.vector(2)
        if not suites or len(suites)%2: raise Rejected()
        compression=r.vector(1)
        if compression!=b'\0': raise Rejected(47)
        e=r.take(len(data)-r.pos)
        if len(e)<9: raise Rejected()
        values=extensions(e)
        return f'client:{random.hex()}:{session.hex()}:{suites.hex()}:{flattened(values)}'
    suite=r.take(2)
    if r.integer(1)!=0: raise Rejected(47)
    e=r.take(len(data)-r.pos)
    if len(e)<8: raise Rejected()
    values=extensions(e); kind='retry' if random==RETRY else 'server'
    for typ,body in values:
        if typ==43 and len(body)!=2: raise Rejected()
        if typ==51:
            if kind=='retry':
                if len(body)!=2: raise Rejected()
            elif len(body)<4 or int.from_bytes(body[2:4],'big')!=len(body)-4: raise Rejected()
        if typ==44:
            v=Reader(body)
            if not v.vector(2): raise Rejected()
            v.finish()
    return f'{kind}:{random.hex()}:{session.hex()}:{suite.hex()}:{flattened(values)}'


def expected(mode, data):
    try:
        if data=='nonbyte': raise Rejected()
        if mode=='alerts':
            if len(data)!=2 or data[0] not in {1,2}: raise Rejected()
            return f'alert:{data[1]}'
        if mode=='contexts':
            if not data: raise Rejected()
            validate(data[0],extensions(data[1:])); return 'valid'
        if len(data)>1048576: raise Rejected()
        r=Reader(data); kind=r.integer(1); body=r.vector(3); r.finish(); b=Reader(body)
        if kind in {1,2}: result=hello(kind,body)
        elif kind==8:
            values=extensions(body)
            for typ,value in values:
                if typ==16:
                    names=Reader(value); protocol=Reader(names.vector(2)); names.finish()
                    if not protocol.vector(1): raise Rejected()
                    protocol.finish()
            result='ee:'+flattened(values)
        elif kind==13:
            context=b.vector(1); values=extensions(b.take(len(body)-b.pos))
            result='cr:'+context.hex()+':'+flattened(values)
        elif kind==11:
            context=b.vector(1); encoded=b.vector(3); b.finish()
            if len(encoded)>524288: raise Rejected()
            entries=Reader(encoded); chain=[]
            while entries.pos<len(encoded):
                size=entries.integer(3)
                if not 0<size<=65535 or len(chain)>=16: raise Rejected()
                cert=entries.take(size); values=extensions(vec(entries.vector(2)))
                validate(11,values,set()); chain.append(cert)
            result='cert:'+context.hex()+''.join(':'+x.hex() for x in chain)
        elif kind==15:
            scheme=b.integer(2); signature=b.vector(2); b.finish()
            if not signature: raise Rejected()
            result=f'cv:{scheme}:{signature.hex()}'
        elif kind==20:
            if len(body)!=32: raise Rejected()
            result='finished:'+body.hex()
        elif kind==24:
            if len(body)!=1: raise Rejected()
            if body[0]>1: raise Rejected(47)
            result=f'update:{body[0]}'
        elif kind==4:
            b.take(8); b.vector(1); ticket=b.vector(2)
            if not ticket: raise Rejected()
            validate(4,extensions(b.take(len(body)-b.pos))); result='ticket'
        else: raise Rejected(10)
        if mode=='serialize': return data.hex() if kind in {1,2,8,13,11,15,20,24} else 'unsupported'
        return result
    except Rejected as error: return f'error:{error.alert}'


def cases(stress):
    result=[]
    def add(name,mode,data): result.append((name,mode,data))
    def cert(chain): return frame(11,b'\0'+u24(len(chain))+chain)
    if stress:
        for size in (65535,65536,65537):
            add('certificate-size-bound','run',cert(u24(size)+bytes(size)+b'\0\0'))
        for count in (16,17): add('chain-count-bound','run',cert((u24(1)+b'x\0\0')*count))
        for size in (524288,524289): add('chain-byte-bound','run',cert(bytes(size)))
        for size in (1048572,1048573): add('handshake-size-bound','run',frame(9,bytes(size)))
        return result
    helloext=ext(43,b'\x02\x03\x04')+ext(51,b'\0\x1d\0\x20'+bytes(32))
    randombytes=bytes(range(32)); session=bytes(range(16))
    seeds=[frame(1,b'\3\3'+randombytes+bytes([len(session)])+session+vec(b'\x13\x01\x13\x03')+b'\1\0'+vec(helloext)),
           frame(2,b'\3\3'+randombytes+bytes([len(session)])+session+b'\x13\x01\0'+vec(ext(43,b'\3\4')+ext(51,b'\0\x1d\0\x20'+bytes(32)))),
           frame(2,b'\3\3'+RETRY+b'\0\x13\x01\0'+vec(ext(43,b'\3\4')+ext(51,b'\0\x17'))),
           frame(8,vec(ext(16,vec(b'\x08http/1.1')))),frame(8,b'\0\0'),
           frame(13,b'\0'+vec(ext(13,vec(b'\4\3\x08\4')))),
           frame(13,b'\x03abc'+vec(ext(65000,b'opaque'))),
           cert(u24(3)+b'der\0\0'+u24(1)+b'x\0\0'),cert(b''),
           frame(15,b'\4\3'+vec(b'fake-signature')),frame(15,b'\x08\4'+vec(bytes(256))),
           frame(20,bytes(range(32))),frame(24,b'\0'),frame(24,b'\1'),
           frame(4,bytes(8)+b'\0'+vec(b'ticket')+vec(ext(42,bytes(4))))]
    for index,data in enumerate(seeds):
        add('valid-message','run',data)
        add('serialize-roundtrip','serialize',data)
        for stop in range(len(data)): add('every-byte-truncation','run',data[:stop])
        add('trailing-byte','run',data+b'\0')
        add('short-declaration','run',data[:1]+u24(len(data)-5)+data[4:])
    for trace in json.loads((ROOT/'tls_handshake_vectors.json').read_text())['traces']:
        for row in trace['operations']:
            if 'construct ' not in row['operation']: continue
            name,encoded=next(iter(row['fields'].items()))
            if name in {'ClientHello','ServerHello','HelloRetryRequest','EncryptedExtensions','Certificate','CertificateVerify','Finished','NewSessionTicket'}:
                add('rfc8448-message','run',bytes.fromhex(encoded))
    for name,extra in [('bad-version-width',ext(43,b'\3')),('bad-share-vector',ext(43,b'\3\4')+ext(51,b'\0\x1d\0\x20'+bytes(31)))]:
        add(name,'run',frame(2,b'\3\3'+bytes(32)+b'\0\x13\1\0'+vec(extra)))
    add('bad-retry-cookie','run',frame(2,b'\3\3'+RETRY+b'\0\x13\1\0'+vec(ext(43,b'\3\4')+ext(44,b'\0'))))
    add('bad-alpn-vector','run',frame(8,vec(ext(16,b'\0\3\2h'))))
    add('framed-other-alpn-state-owned','run',frame(8,vec(ext(16,b'\0\3\2h2'))))
    add('nonoctet','run','nonbyte')
    for kind in (0,3,5,12,16,254,255): add('unexpected-type','run',frame(kind,b''))
    for body in (b'',b'\2',b'\xff',b'\0\0'): add('bad-key-update','run',frame(24,body))
    for size in (0,1,31,33,64): add('finished-width','run',frame(20,bytes(size)))
    for body in (b'',bytes(8),bytes(8)+b'\0\0\0\0\0'):
        add('malformed-ticket','run',frame(4,body))
    for k in (5,18,65000): add('unsolicited-cert-extension','run',cert(u24(1)+b'x'+vec(ext(k))))
    add('duplicate-ee','run',frame(8,vec(ext(16)+ext(16))))
    for context in (1,2,6,8,13,11,4):
        for kind in (*ALLOWED,65000,65001):
            add('extension-context','contexts',bytes([context])+vec(ext(kind)))
            add('duplicate-context','contexts',bytes([context])+vec(ext(kind)+ext(kind)))
    for level in (0,1,2,3,255):
        for description in (0,10,20,40,47,50,70,80,109,110,120,255):
            add('alert-codec','alerts',bytes([level,description]))
    for data in (b'',b'\1',b'\1\0\0'): add('alert-length','alerts',data)
    rng=random.Random(984613)
    for _ in range(128):
        n=rng.randrange(1,20); data=bytes([n])+rng.randbytes(rng.randrange(80))
        add('random-malformed','run',data)
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--stress',action='store_true');p.add_argument('--report',type=Path)
    p.add_argument('binary',nargs=argparse.REMAINDER);a=p.parse_args();binary=a.binary[1:] if a.binary[:1]==['--'] else a.binary
    if not binary:p.error('compiled evaluator required')
    start=time.monotonic();rows=cases(a.stress);counts=Counter();corpus=hashlib.sha256()
    with tempfile.TemporaryDirectory(prefix='grounds-tls-codec-') as folder:
        for mode in ('run','alerts','contexts','serialize'):
            selected=[row for row in rows if row[1]==mode]
            for offset in range(0,len(selected),24 if not a.stress else 1):
                batch=selected[offset:offset+(24 if not a.stress else 1)];command=[*binary,mode];wanted=[]
                for index,(name,_,data) in enumerate(batch):
                    want=expected(mode,data);wanted.append(want);counts[name]+=1
                    corpus.update(json.dumps([name,mode,data if isinstance(data,str) else data.hex(),want],separators=(',',':')).encode()+b'\n')
                    if isinstance(data,str):command.append(data)
                    else:
                        path=Path(folder)/f'{index}.bin';path.write_bytes(data);command.append(str(path))
                run=subprocess.run(command,text=True,capture_output=True,timeout=110)
                assert run.returncode==0,(mode,offset,run.returncode,run.stderr[-2000:])
                actual=run.stdout.splitlines();assert len(actual)==len(wanted),(mode,offset,len(actual),len(wanted),run.stderr[-1000:])
                for index,(got,want) in enumerate(zip(actual,wanted)):
                    assert got==want,(mode,offset+index,batch[index][0],got[:300],want[:300])
    report={'cases':len(rows),'groups':dict(counts),'stress':a.stress,'corpus_sha256':corpus.hexdigest(),
            'elapsed_seconds':round(time.monotonic()-start,3),'binary':binary,'live_tls':False,
            'source_sha256':{name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in ('tls_handshake_codec.bend','tls_handshake_codec_cli.bend','tls_handshake_codec_check.py','tls_handshake_vectors.json')}}
    if a.report:a.report.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,sort_keys=True))


if __name__=='__main__':main()
