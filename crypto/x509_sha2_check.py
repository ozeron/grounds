"""Offline new SHA-2 signature/chain cases; cryptography is not a gate dependency."""
import argparse,base64,json,subprocess,tempfile
from pathlib import Path
import x509_chain_check as C
p=argparse.ArgumentParser();p.add_argument('--mode',choices=['signature','chain'],required=True);p.add_argument('binary');a=p.parse_args()
x=json.loads(Path(__file__).with_name('x509_sha2_vectors.json').read_text())
with tempfile.TemporaryDirectory() as d:
 d=Path(d)
 if a.mode=='signature':
  rows=x['signatures'];count=0
  for start in range(0,len(rows),8):
   cmd=[a.binary,'verify'];want=[]
   for i,r in enumerate(rows[start:start+8]):
    for key in ['issuer','certificate']:
     f=d/f'{i}-{key}';f.write_bytes(bytes.fromhex(r[key]));cmd.append(str(f))
    want.append(str(r['expected']).lower())
   run=subprocess.run(cmd,capture_output=True,text=True,timeout=110)
   assert run.returncode==0,(run.returncode,run.stderr)
   assert run.stdout.splitlines()==want,(start,run.stdout,want)
   count+=len(want)
  print('SHA2 certificate signatures:',count,'passed')
 else:
  certs={k:base64.b64decode(v) for k,v in x['certificates'].items()}
  # OpenSSL 3 fixed-time whole-chain verification uses explicit anchors only.
  C.oracle(x['cases'],certs,d)
  for i,r in enumerate(x['cases']):
   f=d/'chain';f.write_bytes(C.sequence([C.encoded(r,certs)]))
   run=subprocess.run([a.binary,'check',str(Path(__file__).parent/'unicode32_nfkc.bin'),str(Path(__file__).parent/'unicode32_prepare.bin'),str(f)],capture_output=True,text=True,timeout=110)
   assert run.returncode==0,(r['label'],run.returncode,run.stderr)
   assert run.stdout.strip()==r['expected'],(r['label'],run.stdout,r['expected'])
  print('SHA2 fixed-time chains:',len(x['cases']),'passed')
