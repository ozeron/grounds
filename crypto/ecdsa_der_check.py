"""Strict P-256 ECDSA DER encoder/decoder canonical and malformed boundaries."""
from pathlib import Path
import random, subprocess, sys, tempfile, time
N=int('ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551',16)
def integer(v):
 b=v.to_bytes(max(1,(v.bit_length()+7)//8),'big')
 if b[0]>=128:b=b'\x00'+b
 return b'\x02'+bytes([len(b)])+b
def seq(body):return b'\x30'+bytes([len(body)])+body
def der(r,s):return seq(integer(r)+integer(s))
def raw(r,s):return r.to_bytes(32,'big')+s.to_bytes(32,'big')
def main():
 start=time.monotonic();cases=[];rng=random.Random(0xDE256)
 values=[1,2,127,128,255,256,N-1]+[1<<i for i in range(256)]+[rng.randrange(1,N) for _ in range(32)]
 for i,r in enumerate(values):
  s=values[-i-1]
  cases.extend([('encode',raw(r,s),der(r,s).hex()),('decode',der(r,s),raw(r,s).hex())])
 good=der(N-1,1)
 invalid=[b'',b'\x30',good[:-1],good+b'\x00',b'\x31'+good[1:],b'\x30\x81'+good[1:],b'\x30\x80'+good[2:]+b'\x00\x00']
 invalid += [der(0,1),der(1,0),der(N,1),der(1,N),der(N+1,1),der(1,2**256-1)]
 invalid += [seq(a+integer(1)) for a in [b'\x02\x00',b'\x02\x01\x80',b'\x02\x01\xff',b'\x02\x02\x00\x01',b'\x02\x03\x00\x00\x80',b'\x02\x81\x01\x01',b'\x03\x01\x01',b'\x02\x22'+b'\x01'*34]]
 invalid += [seq(integer(1)+a) for a in [b'\x02\x00',b'\x02\x01\x80',b'\x02\x02\x00\x01',b'\x02\x81\x01\x01',b'\x03\x01\x01']]
 invalid += [bytes([48,l])+good[2:] for l in range(256) if l != good[1]]
 invalid += [good[:3]+bytes([l])+good[4:] for l in range(256) if l != good[3]]
 second_length=5+good[3]
 invalid += [good[:second_length]+bytes([l])+good[second_length+1:] for l in range(256) if l != good[second_length]]
 for data in invalid:cases.append(('decode',data,'invalid'))
 for data in [b'',bytes(63),bytes(65),raw(0,1),raw(1,0),raw(N,1),raw(1,N)]:cases.append(('encode',data,'invalid'))
 with tempfile.TemporaryDirectory() as folder:
  p=Path(folder)
  for offset in range(0,len(cases),64):
   batch=cases[offset:offset+64];args=[]
   for i,(op,data,_) in enumerate(batch):
    f=p/f'{i}.bin';f.write_bytes(data);args.extend([op,str(f)])
   r=subprocess.run(sys.argv[1:]+args,capture_output=True,text=True,timeout=60)
   assert r.returncode==0,(offset,r.returncode,r.stderr)
   assert r.stdout.splitlines()==[c[2] for c in batch],(offset,r.stdout,[c[2] for c in batch])
 print(f'ECDSA DER: {len(cases)} canonical/sign-pad/all-bit/range/length/tag/trailing/nonminimal cases passed in {time.monotonic()-start:.3f}s')
if __name__=='__main__':main()
