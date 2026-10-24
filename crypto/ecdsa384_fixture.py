"""One-time fixture recorder; networks only used to obtain published inputs."""
import hashlib,json,random,sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ec,utils
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.exceptions import InvalidSignature
import cryptography
A=Path(sys.argv[1])  # directory containing the two recorded source files
n=int('ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973',16)
p=2**384-2**128-2**96+2**32-1
rows=[]
def add(tag,peer,msg,sig,expected,group):
    try:
        key=ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(),peer)
        key.verify(sig,msg,ec.ECDSA(hashes.SHA384()))
        oracle=True
    except (ValueError,InvalidSignature):oracle=False
    assert expected==oracle,(tag,expected,oracle)
    try:
        r,s=utils.decode_dss_signature(sig)
        raw=(r.to_bytes(48,'big')+s.to_bytes(48,'big')).hex() if r>=0 and s>=0 else None
    except (ValueError,OverflowError):raw=None
    rows.append(dict(tag=tag,group=group,peer=peer.hex(),message=msg.hex(),digest=hashlib.sha384(msg).hexdigest(),signature=sig.hex(),raw=raw,expected=expected,cryptography=oracle))
j=json.loads((A/'ecdsa_secp384r1_sha384_test.json').read_text())
for g in j['testGroups']:
    peer=bytes.fromhex(g['publicKey']['uncompressed'])
    for t in g['tests']:
        # Grounds' DER-only profile rejects Wycheproof's permissive BER cases.
        add('wycheproof-'+str(t['tcId']),peer,bytes.fromhex(t['msg']),bytes.fromhex(t['sig']),t['result']=='valid','wycheproof')
current=None;row={};nist=0
for line in (A/'SigVer.rsp').read_text().splitlines():
    line=line.strip()
    if line.startswith('['):current=line;row={}
    elif current=='[P-384,SHA-384]' and ' = ' in line:
        key,val=line.split(' = ',1);row[key]=val
        if key=='Result':
            msg=bytes.fromhex(row['Msg'])
            peer=b'\x04'+bytes.fromhex(row['Qx'])+bytes.fromhex(row['Qy'])
            sig=utils.encode_dss_signature(int(row['R'],16),int(row['S'],16))
            add('nist-'+str(nist),peer,msg,sig,val.startswith('P'),'nist-cavp');nist+=1;row={}
rng=random.Random(0x384EC)
for i in range(24):
    key=ec.derive_private_key(rng.randrange(1,n),ec.SECP384R1())
    msg=rng.randbytes((0,1,111,112,128,129,1024,4097)[i%8])
    peer=key.public_key().public_bytes(serialization.Encoding.X962,serialization.PublicFormat.UncompressedPoint)
    sig=key.sign(msg,ec.ECDSA(hashes.SHA384(),deterministic_signing=True))
    add('random-'+str(i),peer,msg,sig,True,'differential')
    add('wrong-message-'+str(i),peer,msg+b'\0',sig,False,'differential')
# Coordinate aliases, infinity, invalid equation and scalar bounds are independent.
base=rows[-2];peer=bytes.fromhex(base['peer']);msg=bytes.fromhex(base['message']);sig=bytes.fromhex(base['signature'])
for tag,q in [('infinity',b'\0'),('empty',b''),('compressed',bytes([2+(peer[-1]&1)])+peer[1:49]),('short',peer[:-1]),('long',peer+b'\0'),('offcurve',b'\x04'+bytes(96)),('x-alias',b'\x04'+p.to_bytes(48,'big')+peer[49:]),('y-alias',peer[:49]+p.to_bytes(48,'big'))]:
    # Compressed keys may be accepted by the oracle but are outside Grounds profile.
    if tag=='compressed':
        row=dict(base,tag=tag,group='profile',peer=q.hex(),expected=False);rows.append(row)
    else:add(tag,q,msg,sig,False,'profile')
for tag,r,s in [('zero-r',0,1),('zero-s',1,0),('order-r',n,1),('order-s',1,n),('large-r',2**384-1,1),('large-s',1,2**384-1)]:
    add(tag,peer,msg,utils.encode_dss_signature(r,s),False,'profile')
metadata=dict(wycheproof_source='https://raw.githubusercontent.com/C2SP/wycheproof/main/testvectors_v1/ecdsa_secp384r1_sha384_test.json',wycheproof_sha256=hashlib.sha256((A/'ecdsa_secp384r1_sha384_test.json').read_bytes()).hexdigest(),nist_source='https://raw.githubusercontent.com/pyca/cryptography/main/vectors/cryptography_vectors/asymmetric/ECDSA/FIPS_186-3/SigVer.rsp',nist_sha256=hashlib.sha256((A/'SigVer.rsp').read_bytes()).hexdigest(),cryptography_version=cryptography.__version__,synthetic_only=True,cases=rows)
Path(__file__).with_name('ecdsa384_vectors.json').write_text(json.dumps(metadata,indent=2)+'\n')
from collections import Counter
print(Counter(r['group'] for r in rows),Counter(r['expected'] for r in rows))
