"""Native forced-0x1302 OpenSSL, Go and Bend loopback interoperability."""
import argparse,hashlib,json,shutil,subprocess,tempfile
from pathlib import Path
import bend_tls_client_check as C
import bend_tls_server_check as S
import bend_tls_peer_check as P
p=argparse.ArgumentParser();p.add_argument('--client',required=True);p.add_argument('--server',required=True);p.add_argument('--go-peer',required=True);p.add_argument('--peer',choices=['openssl-server','openssl-client','go-server','go-client','bend','updates'],required=True);p.add_argument('--report',type=Path,required=True);a=p.parse_args()
# Only this native driver opts into the new matrix; existing Bun batches retain
# their case counts and two-suite scope.
C.SUITES['aes256']=(4866,'TLS_AES_256_GCM_SHA384')
results=[]
with tempfile.TemporaryDirectory(prefix='aes256-interop-',dir=a.report.resolve().parent) as d:
 d=Path(d);fixtures=C.fixture(d,shutil.which('openssl'))
 cases=[dict(name=f'{a.peer}-aes256-{g}-{s}',suite='aes256',group=g,signature=s,peer=a.peer) for g in C.GROUPS for s in ('ecdsa','rsa')]
 if a.peer=='updates':cases=[dict(name=n,suite='aes256',group='x25519',signature='ecdsa') for n in ['keyupdate-client','keyupdate-server']]
 if a.peer in ('openssl-server','go-server'):
  commands=[['req','-new','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-384','-noenc','-keyout',str(d/'p384.key'),'-out',str(d/'p384.csr'),'-subj','/CN=synthetic P384 leaf','-sha384'],
    ['x509','-req','-in',str(d/'p384.csr'),'-CA',str(d/'ca.pem'),'-CAkey',str(d/'ca.key'),'-CAcreateserial','-days','2','-sha384','-extfile',str(d/'leaf.cnf'),'-out',str(d/'p384.pem')]]
  for command in commands:
   run=subprocess.run([shutil.which('openssl')]+command,capture_output=True,text=True);assert run.returncode==0,run.stderr
  fixtures['p384.pem']=hashlib.sha256((d/'p384.pem').read_bytes()).hexdigest()
  cases += [dict(name=f'{a.peer}-aes256-{g}-p384',suite='aes256',group=g,signature='p384',peer=a.peer) for g in C.GROUPS]
 if a.peer=='openssl-server':
  cases += [dict(name=f'openssl-rsa-pss-{bits}-{g}',suite='aes256',group=g,signature='rsa',sigalg='rsa_pss_rsae_sha'+str(bits),peer=a.peer) for bits in (384,512) for g in C.GROUPS]
 for case in cases:
  if a.peer in ('openssl-server','updates'):r=C.test_case([a.client],d,shutil.which('openssl'),case,25)
  elif a.peer=='openssl-client':r=S.openssl_case([a.server],d,shutil.which('openssl'),case)
  else:r=P.test([a.server],[a.client],a.go_peer,d,case)
  results.append({**r,'case':case});print(case['name'],r['passed'],flush=True)
 a.report.write_text(json.dumps(dict(results=results,fixtures=fixtures,native_only=True,go_cipher_preference='test-only standard-library overlay; see Go build receipt',passed=sum(r['passed'] for r in results)),indent=2)+'\n')
 assert all(r['passed'] for r in results),results
