"""Independent RFC 8446-style SHA-384 schedule and all-byte Finished mutations."""
import hashlib,hmac,random
import tls_schedule_check as S

def mac(key,data):return hmac.digest(key,data,'sha384')
def label(key,name,context):
 name=b'tls13 '+name;return mac(key,b'\x00\x30'+bytes([len(name)])+name+bytes([len(context)])+context+b'\x01')
def next_secret(secret,ikm):return mac(label(secret,b'derived',hashlib.sha384(b'').digest()),ikm)
def flow(shared,hello,server,app):
 if len(hello)==32:return S.flow(shared,hello,server,app)
 if len(shared)!=32 or len(hello)!=48:return ['invalid']
 secret=next_secret(mac(bytes(48),bytes(48)),shared)
 c,s=[label(secret,n,hello) for n in (b'c hs traffic',b's hs traffic')];ck,sk=[label(k,b'finished',b'') for k in (c,s)]
 values=[v.hex() for v in (secret,c,s,ck,sk)]
 values += [mac(sk,server).hex() if len(server)==48 else 'invalid',mac(ck,app).hex() if len(app)==48 else 'invalid']
 return values+([label(next_secret(secret,bytes(48)),n,app).hex() for n in (b'c ap traffic',b's ap traffic')] if len(app)==48 else ['invalid'])
def cases():
 rng=random.Random(0x1302);rows=[]
 for i in range(65):
  values=[bytes(32)]+[bytes(48)]*3 if i==0 else [rng.randbytes(32)]+[rng.randbytes(48) for _ in range(3)]
  rows.append(('SHA384-independent-schedule','flow',values,flow(*values)))
 for index in range(4):
  for width in (0,1,31,32,33,47,49,64):
   values=[bytes(32)]+[bytes(48)]*3;values[index]=bytes(width)
   rows.append(('SHA384-input-widths','flow',values,flow(*values)))
 key,hash=rng.randbytes(48),rng.randbytes(48);tag=mac(key,hash)
 rows += [('SHA384-Finished','finished',[key,hash],[tag.hex()]),('SHA384-verify','verify',[key,hash,tag],['true'])]
 for index in range(48):
  bad=bytearray(tag);bad[index]^=1;rows.append(('SHA384-every-tag-byte','verify',[key,hash,bytes(bad)],['false']))
  bad=bytearray(hash);bad[index]^=1;rows.append(('SHA384-every-hash-byte','verify',[key,bytes(bad),tag],['false']))
 for width in (0,32,47,49,64):
  rows.append(('SHA384-mismatched-width','verify',[key,hash,bytes(width)],['false']))
 return rows
if __name__=='__main__':
 S.cases=cases;S.main()
