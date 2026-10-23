"""Frozen cryptography differential cases for all admitted private-key formats."""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
ROOT=Path(__file__).parent


def main():
    parser=argparse.ArgumentParser(); parser.add_argument('--report',type=Path); parser.add_argument('--part',choices=['all','ec','rsa'],default='all'); parser.add_argument('binary',nargs=argparse.REMAINDER); args=parser.parse_args()
    binary=args.binary[1:] if args.binary[:1]==['--'] else args.binary
    if not binary: parser.error('supply evaluator after --')
    if not args.report and os.environ.get('GROUNDS_M2_REPORT_DIR'):
        directory=Path(os.environ['GROUNDS_M2_REPORT_DIR']); directory.mkdir(parents=True,exist_ok=True)
        target='bun' if any(Path(word).name=='bun' for word in binary[:1]) else 'native'
        args.report=directory/('private-key-'+args.part+'-'+target+'.json')

    fixture=json.loads((ROOT/'private_key_vectors.json').read_text()); rows=fixture['private']
    assert {row['family'] for row in rows}=={'ec','rsa'},'unpartitioned private-key corpus row'
    # Every row is retained; halves bound per-phase CRT/curve work.
    if args.part!='all': rows=[row for row in rows if row['family']==args.part]
    counts=Counter(); started=time.monotonic()
    with tempfile.TemporaryDirectory(prefix='grounds-private-key-') as directory:
        for first in range(0,len(rows),4):
            batch=rows[first:first+4]; command=list(binary)
            for index,row in enumerate(batch):
                path=Path(directory)/str(index); path.write_bytes(bytes.fromhex(row['data'])); command += [row['mode'],str(path)]
            p=subprocess.run(command,capture_output=True,text=True,timeout=90)
            assert p.returncode==0,p.stderr[-2000:]
            outputs=p.stdout.splitlines(); assert len(outputs)==len(batch),(len(outputs),len(batch))
            for row,output in zip(batch,outputs):
                assert output==row['expected'],(first,row['tag'],output[:80],row['expected'][:80])
                counts[row['tag']]+=1
    names=['private_key.bend','private_key_cli.bend','private_key_check.py','private_key_vectors.json','private_key_fixture.py','pem.bend','rsa_private.bend','p256.bend','der.bend']
    result={'binary':binary,'part':args.part,'total':sum(counts.values()),'cases':dict(counts),'elapsed_seconds':round(time.monotonic()-started,3),'synthetic_keys_only':True,'independent_oracle':fixture['oracle'],'input_sha256':{name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in names}}
    if args.report: args.report.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result))

if __name__=='__main__': main()
