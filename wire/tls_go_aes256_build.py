"""Build a test-only Go peer pinned to TLS_AES_256_GCM_SHA384.

Go Config.CipherSuites excludes TLS 1.3. An overlay changes only its two
TLS1.3 default offer/preference lists, leaving all cryptographic code intact.
Never installed as a GOROOT change or used by the Grounds Bend execution path.
"""
import argparse,hashlib,json,os,re,subprocess,tempfile
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--report',type=Path,required=True);a=p.parse_args()
go=os.environ.get('GROUNDS_GO') or str(Path(subprocess.check_output(['mise','where','go@1.26.9'],text=True).strip())/'bin/go')
goro=Path(subprocess.check_output([go,'env','GOROOT'],text=True).strip());source=goro/'src/crypto/tls/defaults.go';before=source.read_text();after=before
for name in ['defaultCipherSuitesTLS13','defaultCipherSuitesTLS13NoAES']:
 pattern=r'var '+name+r' = \[\]uint16\{[^}]*\}'
 match=re.search(pattern,after);assert match and set(re.findall(r'TLS_[A-Z0-9_]+',match[0]))=={'TLS_AES_128_GCM_SHA256','TLS_AES_256_GCM_SHA384','TLS_CHACHA20_POLY1305_SHA256'},name
 after,n=re.subn(pattern,'var '+name+' = []uint16{TLS_AES_256_GCM_SHA384}',after);assert n==1
with tempfile.TemporaryDirectory(prefix='go-aes256-',dir=a.output.resolve().parent) as d:
 d=Path(d);patched=d/'defaults.go';patched.write_text(after);overlay=d/'overlay.json';overlay.write_text(json.dumps({'Replace':{str(source):str(patched)}}))
 peer=Path(__file__).with_name('tls_go_peer.go').resolve()
 command=[go,'build','-overlay',str(overlay),'-o',str(a.output.resolve()),str(peer)]
 run=subprocess.run(command,capture_output=True,text=True)
 a.report.write_text(json.dumps(dict(command=command,exit=run.returncode,stderr=run.stderr,go_version=subprocess.check_output([go,'version'],text=True).strip(),original_defaults_sha256=hashlib.sha256(before.encode()).hexdigest(),overlaid_defaults_sha256=hashlib.sha256(after.encode()).hexdigest(),peer_source_sha256=hashlib.sha256(peer.read_bytes()).hexdigest(),scope='test-only cipher offers and preferences; Go crypto unchanged; actual negotiation asserted by peer'),indent=2)+'\n')
 if run.returncode:print(run.stderr);raise SystemExit(run.returncode)
