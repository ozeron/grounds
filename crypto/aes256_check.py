"""FIPS 197/SP800-38D AES-256 vectors and OpenSSL/bigint GCM differentials."""
from pathlib import Path
import random,subprocess,sys,tempfile
import gcm_check as G

def main():
 aes,gcm=sys.argv[1:];rng=random.Random(0x25638D);count=0
 with tempfile.TemporaryDirectory() as folder:
  root=Path(folder)
  def run(binary,values,mode=None,ok=True):
   nonlocal count
   paths=[]
   for i,v in enumerate(values):
    p=root/str(i);p.write_bytes(v);paths.append(str(p))
   got=subprocess.run([binary]+([mode] if mode else [])+paths,capture_output=True,text=True,timeout=110);count+=1
   if ok:assert got.returncode==0,(mode,got.returncode,got.stderr)
   else:assert got.returncode!=0,(mode,got.stdout)
   return got.stdout.splitlines()
  cases=[(bytes(range(32)),bytes.fromhex('00112233445566778899aabbccddeeff'),bytes.fromhex('8ea2b7ca516745bfeafc49904b496089')),
         (bytes(32),bytes(16),bytes.fromhex('dc95c078a2408989ad48a21492842087'))]
  cases += [(rng.randbytes(32),rng.randbytes(16),None) for _ in range(64)]
  for key,block,want in cases:
   oracle=G.aes_blocks(key,block)
   if want is not None:assert want==oracle
   assert run(aes,[key,block])==[oracle.hex()]
  for width in (0,1,16,24,31,33):run(aes,[bytes(width),bytes(16)],ok=False)
  for width in (0,15,17,32):run(aes,[bytes(32),bytes(width)],ok=False)
  gcases=[(bytes(32),bytes(12),b'',b'',b'',bytes.fromhex('530f8afbc74536b9a963b4f1c4cb738b')),
          (bytes(32),bytes(12),b'',bytes(16),bytes.fromhex('cea7403d4d606b6e074ec5d3baf39d18'),bytes.fromhex('d0d1c8a799996bf0265b98b5d48ab919'))]
  for i in range(48):
   key=rng.randbytes(32);nonce=rng.randbytes(12);aad=rng.randbytes((0,1,15,16,17,31,32,33)[i%8]);pt=rng.randbytes((0,1,15,16,17,31,32,33,111,112,128,129,1024,4097,16385,65536)[i%16]);ct,tag=G.oracle(key,nonce,aad,pt);gcases.append((key,nonce,aad,pt,ct,tag))
  for key,nonce,aad,pt,ct,tag in gcases:
   assert G.oracle(key,nonce,aad,pt)==(ct,tag)
   assert run(gcm,[key,nonce,aad,pt],'seal')==[ct.hex(),tag.hex()]
   assert run(gcm,[key,nonce,aad,ct,tag],'open')==[pt.hex()]
  key,nonce,aad,pt,ct,tag=gcases[-1]
  for i in range(16):
   bad=bytearray(tag);bad[i]^=1;run(gcm,[key,nonce,aad,ct,bytes(bad)],'open',False)
  for width in (0,1,16,24,31,33):run(gcm,[bytes(width),nonce,aad,pt],'seal',width==16)
  for width in (0,15,17):run(gcm,[key,nonce,aad,ct,bytes(width)],'open',False)
 print(f'AES-256: 2 published + 64 differential blocks; GCM 2 published + 48 differential seal/open cases through 64 KiB, 16 tag mutations and malformed widths; {count} evaluator checks passed')
if __name__=='__main__':main()
