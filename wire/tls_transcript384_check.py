"""SHA-384 transcript selection, snapshots and HRR message_hash rewrite."""
import hashlib,random,subprocess,sys,tempfile
from pathlib import Path
HRR=bytes.fromhex('cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c')
def frame(kind,body):return bytes([kind])+len(body).to_bytes(3,'big')+body
def main():
 binary=sys.argv[1:];rng=random.Random(0x384);count=0
 with tempfile.TemporaryDirectory() as d:
  d=Path(d)
  for width in (0,1,107,108,111,112,124,128,129,1024,4097,1048000):
   ch=frame(1,rng.randbytes(width));sh=frame(2,b'\x03\x03'+rng.randbytes(32));retry=frame(2,b'\x03\x03'+HRR);ch2=frame(1,rng.randbytes(111))
   messages=[ch,sh,retry,ch2]
   paths=[]
   for i,msg in enumerate(messages):p=d/str(i);p.write_bytes(msg);paths.append(str(p))
   c,s,r,c2=paths
   for args,want in [([c,'sha384',s],[hashlib.sha256(ch).hexdigest(),hashlib.sha384(ch+sh).hexdigest()]),
      ([c,'sha384',r,c2,s],[hashlib.sha256(ch).hexdigest()]+[hashlib.sha384(b'\xfe\0\0\x30'+hashlib.sha384(ch).digest()+retry+tail).hexdigest() for tail in (b'',ch2,ch2+sh)]),
      (['sha384',c,s],[hashlib.sha384(ch).hexdigest(),hashlib.sha384(ch+sh).hexdigest()]),
      (['sha384',c,'sha256',s],[hashlib.sha384(ch).hexdigest(),'invalid'])]:
    run=subprocess.run(binary+['run']+args,capture_output=True,text=True,timeout=110)
    assert run.returncode==0,(width,run.stderr)
    assert run.stdout.splitlines()==want,(width,args,run.stdout,want);count+=1
 print('SHA384 transcripts:',count,'independent selection/snapshot/HRR/hash-switch cases passed')
if __name__=='__main__':main()
