"""One-time synthetic SHA-2 certificate recorder; cryptography is an oracle only."""
from datetime import datetime,timezone
import base64,hashlib,json,sys
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec,rsa,padding
import x509_algorithm_check as A
import x509_certificate_check as C

ROOT=Path(__file__).parent
keys={'p256':ec.derive_private_key(384,ec.SECP256R1()),'p384':ec.derive_private_key(512,ec.SECP384R1()),'rsa':rsa.generate_private_key(public_exponent=65537,key_size=2048)}
leaf=ec.derive_private_key(256,ec.SECP256R1())
serial=1000
now=int(datetime(2026,10,24,tzinfo=timezone.utc).timestamp())
def name(text):return x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME,text)])
def build(subject,issuer,key,issuer_key,hash,pad=None,ca=False):
 global serial
 serial+=1
 b=(x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(key.public_key()).serial_number(serial)
 .not_valid_before(datetime(2025,1,1,tzinfo=timezone.utc)).not_valid_after(datetime(2030,1,1,tzinfo=timezone.utc))
 .add_extension(x509.BasicConstraints(ca,3 if ca else None),True)
 .add_extension(x509.KeyUsage(not ca,False,False,False,False,ca,ca,False,False),True))
 if not ca:b=b.add_extension(x509.SubjectAlternativeName([x509.DNSName('sha2.example')]),False).add_extension(x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]),False)
 return b.sign(issuer_key,hash,rsa_padding=pad)
def der(cert):return cert.public_bytes(serialization.Encoding.DER)
def spki(key):return key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
roots={k:build(name(k+' root'),name(k+' root'),key,key,hashes.SHA384() if k=='p384' else hashes.SHA256(),ca=True) for k,key in keys.items()}
certs={k+'-root':base64.b64encode(der(c)).decode() for k,c in roots.items()}
rows=[];sigrows=[]
def add(label,cert,kind,pad,hash):
 raw=der(cert);key=keys[kind]
 if kind=='rsa':key.public_key().verify(cert.signature,cert.tbs_certificate_bytes,pad or padding.PKCS1v15(),hash)
 else:key.public_key().verify(cert.signature,cert.tbs_certificate_bytes,ec.ECDSA(hash))
 certs[label]=base64.b64encode(raw).decode()
 sigrows.append(dict(label=label,issuer=spki(key).hex(),certificate=raw.hex(),expected=True))
 fields=C.elements(A.complete(raw,48));signature=fields[-1][1][1:]
 for index in {0,len(signature)//2,len(signature)-1}:
  bad=bytearray(signature);bad[index]^=1
  sigrows.append(dict(label=label+'-bad-signature-'+str(index),issuer=spki(key).hex(),certificate=C.assemble(fields[0][2],fields[1][2],bytes(bad)).hex(),expected=False))
 rows.append(dict(label=label,now=now,kind='dns',identity='sha2.example',presented=[label],anchors=[kind+'-root'],expected='success',openssl_accept=True))
for kind in ['p256','p384']:
 h=hashes.SHA384();c=build(name('leaf'),roots[kind].subject,leaf,keys[kind],h);add(kind+'-sha384',c,kind,None,h)
for bits in [384,512]:
 h=getattr(hashes,'SHA'+str(bits))()
 c=build(name('leaf'),roots['rsa'].subject,leaf,keys['rsa'],h);add('rsa-v15-'+str(bits),c,'rsa',None,h)
 maxsalt=256-h.digest_size-2
 for salt in [0,1,20,h.digest_size,127,128,maxsalt]:
  p=padding.PSS(mgf=padding.MGF1(h),salt_length=salt)
  c=build(name('leaf'),roots['rsa'].subject,leaf,keys['rsa'],h,p);add(f'rsa-pss-{bits}-{salt}',c,'rsa',p,h)
# New PSS-only SPKI restrictions use the same public n/e, independently framed.
rsa_parts=C.elements(A.complete(spki(keys['rsa']),48))
for bits in [384,512]:
 ho=getattr(A,'SHA'+str(bits));hlen=bits//8
 for minimum in [0,hlen,hlen+1]:
  val=minimum.to_bytes(1,'big')
  alg=A.algorithm(A.PSS,A.tlv(48,A.tlv(160,A.algorithm(ho))+A.tlv(161,A.algorithm(A.MGF,A.algorithm(ho)))+A.tlv(162,A.tlv(2,val))))
  restricted=A.tlv(48,alg+rsa_parts[1][2])
  for sigbits in [384,512]:
   source=next(r for r in sigrows if r['label']==f'rsa-pss-{sigbits}-{sigbits//8}')
   sigrows.append(dict(source,label=f'pss-key-{bits}-{minimum}-sig-{sigbits}',issuer=restricted.hex(),expected=(sigbits==bits and minimum<=hlen)))
  source=next(r for r in sigrows if r['label']=='rsa-v15-'+str(bits))
  sigrows.append(dict(source,label=f'pss-key-v15-{bits}-{minimum}',issuer=restricted.hex(),expected=False))
# Unsupported ECDSA SHA-512 preserves fully framed certificate structure.
c=build(name('unsupported'),roots['p384'].subject,leaf,keys['p384'],hashes.SHA512())
certs['unsupported']=base64.b64encode(der(c)).decode()
rows.append(dict(rows[0],label='unsupported-ecdsa-sha512',presented=['unsupported'],anchors=['p384-root'],expected='unsupported-algorithm',openssl_accept=True))
for label,change in [('wrong-host',dict(identity='wrong.example',expected='identity-mismatch')),('expired',dict(now=int(datetime(2031,1,1,tzinfo=timezone.utc).timestamp()),expected='expired')),('untrusted',dict(anchors=['p256-root'],expected='wrong-issuer'))]:
 source=next(r for r in rows if r['label']=='p384-sha384');rows.append(dict(source,label=label,openssl_accept=False,**change))
obj=dict(provenance='LOCAL SYNTHETIC; cryptography signatures independently verified before recording; no production credentials',certificates=certs,cases=rows,signatures=sigrows)
(ROOT/'x509_sha2_vectors.json').write_text(json.dumps(obj,indent=2)+'\n')
print('recorded',len(sigrows),'signature cases,',len(rows),'chains')
