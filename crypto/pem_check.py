"""Independent strict PEM/Base64 corpus; no private material in diagnostics."""
import argparse
import base64
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import random
import subprocess
import tempfile
import time

ROOT = Path(__file__).parent
LABELS = {'PRIVATE KEY':'pkcs8','EC PRIVATE KEY':'sec1','RSA PRIVATE KEY':'pkcs1','CERTIFICATE':'certificate'}


def encode(label, data, newline=b'\n'):
    return b'-----BEGIN '+label.encode()+b'-----'+newline+base64.b64encode(data)+newline+b'-----END '+label.encode()+b'-----'+newline


def cases():
    rows = []
    def add(tag, data, expected):
        rows.append((tag,data,expected))
    rng = random.Random(7468)
    for label,kind in LABELS.items():
        for size in (0,1,2,3,31,32,33,127,128,256,1024):
            data = rng.randbytes(size)
            for newline in (b'\n',b'\r\n'):
                text = encode(label,data,newline)
                assert base64.b64decode(base64.b64encode(data),validate=True) == data
                add('canonical-PEM',text,kind+':'+data.hex())
            add('whitespace-outside',b'\n'+text+b' \t\r\n',kind+':'+data.hex())
        good = encode(label,b'a')
        add('footer-without-final-newline',good[:-1],kind+':61')
        for bad in (good.replace(b'YQ==',b'YR=='),good.replace(b'YQ==',b'YQ='),good.replace(b'YQ==',b'YQ==='),good.replace(b'YQ==',b'YQ==AAAA'),good.replace(b'YQ==',b'Y Q=='),good.replace(b'YQ==',b'YQ_='),good.replace(b'YQ==',b'\xffQ=='),good+good,good+b'x',good.replace(b'END ',b'END X'),good.replace(b'BEGIN ',b'BEGIN X')):
            add('malformed-PEM',bad,'none')
        for pos in range(len(good)-1):
            add('PEM-every-truncation',good[:pos],'none')
    add('encrypted-label',b'-----BEGIN ENCRYPTED PRIVATE KEY-----\nAA==\n-----END ENCRYPTED PRIVATE KEY-----\n','encrypted')
    add('encrypted-legacy',b'-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,00\n\nAA==\n-----END RSA PRIVATE KEY-----\n','encrypted')
    add('unknown-header',b'-----BEGIN RSA PRIVATE KEY-----\nComment: no\nAA==\n-----END RSA PRIVATE KEY-----\n','none')
    valid=encode('PRIVATE KEY',b'\x00')
    for size in (99999,100000):
        add('text-bound-valid-whitespace',valid+b' '*(size-len(valid)),'pkcs8:00')
    add('text-bound-valid-leading-lines',b'\n'*(100000-len(valid))+valid,'pkcs8:00')
    add('text-bound-malformed-line',b'A'*100000,'none')
    add('input-bound',b'x'*100001,'large')
    # Bounded decode reaches DER's full maximum without aliasing a shorter key.
    data = bytes(65535)
    add('DER-bound-accepted',encode('PRIVATE KEY',data),'pkcs8:'+data.hex())
    add('DER-bound-rejected',encode('PRIVATE KEY',data+b'\x00'),'large')
    return rows


def run(rows,binary,report,inputs):
    counts = Counter()
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='grounds-m2-keys-') as directory:
        for first in range(0,len(rows),8):
            batch = rows[first:first+8]
            paths=[]
            for index,(_,value,_) in enumerate(batch):
                path=Path(directory)/str(index); path.write_bytes(value); paths.append(str(path))
            p=subprocess.run(binary+paths,capture_output=True,text=True,timeout=90)
            assert p.returncode == 0,p.stderr[-2000:]
            outputs=p.stdout.splitlines()
            assert len(outputs)==len(batch),(len(outputs),len(batch))
            for (tag,_,expected),output in zip(batch,outputs):
                assert output==expected,(first,tag,output[:80],expected[:80])
                counts[tag]+=1
    result={'binary':binary,'total':sum(counts.values()),'cases':dict(counts),'elapsed_seconds':round(time.monotonic()-started,3),'synthetic_keys_only':True,'input_sha256':{name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in inputs}}
    if report:
        report.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result))


def main():
    parser=argparse.ArgumentParser(); parser.add_argument('--report',type=Path); parser.add_argument('binary',nargs=argparse.REMAINDER); args=parser.parse_args()
    binary=args.binary[1:] if args.binary[:1]==['--'] else args.binary
    if not binary: parser.error('supply evaluator after --')
    if not args.report and os.environ.get('GROUNDS_M2_REPORT_DIR'):
        directory=Path(os.environ['GROUNDS_M2_REPORT_DIR']); directory.mkdir(parents=True,exist_ok=True)
        target='bun' if any(Path(word).name=='bun' for word in binary[:1]) else 'native'
        args.report=directory/('pem-'+target+'.json')

    run(cases(),binary,args.report,['pem.bend','pem_cli.bend','pem_check.py'])

if __name__=='__main__': main()
