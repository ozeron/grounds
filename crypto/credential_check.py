"""Leaf-SPKI binding: independent synthetic certificates and private keys."""
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
    parser=argparse.ArgumentParser(); parser.add_argument('--report',type=Path); parser.add_argument('binary',nargs=argparse.REMAINDER); args=parser.parse_args()
    binary=args.binary[1:] if args.binary[:1]==['--'] else args.binary
    if not binary: parser.error('supply evaluator after --')
    if not args.report and os.environ.get('GROUNDS_M2_REPORT_DIR'):
        directory=Path(os.environ['GROUNDS_M2_REPORT_DIR']); directory.mkdir(parents=True,exist_ok=True)
        target='bun' if any(Path(word).name=='bun' for word in binary[:1]) else 'native'
        args.report=directory/('credential-'+target+'.json')

    fixture=json.loads((ROOT/'private_key_vectors.json').read_text()); rows=fixture['credentials']; counts=Counter(); started=time.monotonic()
    with tempfile.TemporaryDirectory(prefix='grounds-credential-') as directory:
        for index,row in enumerate(rows):
            leaf=Path(directory)/'leaf'; key=Path(directory)/'key'; leaf.write_bytes(bytes.fromhex(row['leaf'])); key.write_bytes(bytes.fromhex(row['pem']))
            p=subprocess.run(binary+[str(leaf),str(key)],capture_output=True,text=True,timeout=90)
            assert p.returncode==0,p.stderr[-2000:]
            assert p.stdout.strip()==row['expected'],(index,row['tag'],p.stdout[:80],row['expected'])
            counts[row['tag']]+=1
    names=['credential.bend','credential_cli.bend','credential_check.py','private_key.bend','private_key_vectors.json','pem.bend','rsa_private.bend','x509_certificate.bend','x509_public_key.bend']
    result={'binary':binary,'total':sum(counts.values()),'cases':dict(counts),'elapsed_seconds':round(time.monotonic()-started,3),'synthetic_keys_only':True,'certificate_trust_accepted':False,'input_sha256':{name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in names}}
    if args.report: args.report.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result))

if __name__=='__main__': main()
