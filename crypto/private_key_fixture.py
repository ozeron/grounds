"""Regenerate SYNTHETIC credential fixtures with Python cryptography.

Not run by ordinary gates. Cryptography independently constructs DER/PEM,
loads positive formats, derives P-256 public keys, and validates RSA CRT
parameters. No private fixture value is suitable for real credentials.
"""
import base64
import datetime as dt
import hashlib
import json
import math
import sys
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization as S
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
import cryptography
from cryptography.exceptions import UnsupportedAlgorithm

ROOT = Path(__file__).parent


def tlv(tag, body):
    size = len(body)
    length = bytes([size]) if size < 128 else bytes([128+(size.bit_length()+7)//8])+size.to_bytes((size.bit_length()+7)//8, 'big')
    return bytes([tag])+length+body


def read(data):
    count = data[1]
    head = 2
    if count & 128:
        width = count & 127
        count = int.from_bytes(data[2:2+width], 'big')
        head += width
    end = head+count
    return data[0], data[head:end], data[end:]


def fields(data):
    tag, body, rest = read(data)
    assert tag == 48 and not rest
    out = []
    while body:
        tag, value, body = read(body)
        out.append(tlv(tag, value))
    return out


def integer(n):
    body = n.to_bytes(max(1, (n.bit_length()+7)//8), 'big')
    return tlv(2, (b'\x00' if body[0] & 128 else b'')+body)


def pem(label, der):
    encoded = base64.b64encode(der)
    return b'-----BEGIN '+label+b'-----\n'+b'\n'.join(encoded[i:i+64] for i in range(0, len(encoded), 64))+b'\n-----END '+label+b'-----\n'


def public(key):
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return 'p256:'+key.public_key().public_bytes(S.Encoding.X962, S.PublicFormat.UncompressedPoint).hex()
    n = key.private_numbers().public_numbers
    return 'rsa:'+n.n.to_bytes((n.n.bit_length()+7)//8, 'big').hex()+':'+n.e.to_bytes((n.e.bit_length()+7)//8, 'big').hex()


def certificate(key):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'SYNTHETIC Grounds M2')])
    return x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(23).not_valid_before(dt.datetime(2026,1,1)).not_valid_after(dt.datetime(2027,1,1)).sign(key, hashes.SHA256()).public_bytes(S.Encoding.DER)


def main():
    rows = []
    credentials = []
    keys = [ec.derive_private_key(1, ec.SECP256R1()), ec.derive_private_key(2, ec.SECP256R1()), rsa.generate_private_key(65537, 2048)]
    leaves = [certificate(key) for key in keys]

    def add(tag, mode, data, expected='none'):
        rows.append(dict(tag=tag, family='ec' if index < 2 else 'rsa', mode=mode, data=data.hex(), expected=expected))

    for index, key in enumerate(keys):
        expected = public(key)
        formats = [('pkcs8', S.PrivateFormat.PKCS8), ('sec1' if index < 2 else 'pkcs1', S.PrivateFormat.TraditionalOpenSSL)]
        for mode, fmt in formats:
            der = key.private_bytes(S.Encoding.DER, fmt, S.NoEncryption())
            text = key.private_bytes(S.Encoding.PEM, fmt, S.NoEncryption())
            assert public(S.load_der_private_key(der, None)) == expected
            assert public(S.load_pem_private_key(text, None)) == expected
            add('cryptography-'+mode, mode, der, expected)
            add('cryptography-PEM-'+mode, 'pem', text, expected)
            add('cryptography-PEM-CRLF-'+mode, 'pem', text.replace(b'\n', b'\r\n'), expected)
            credentials.append(dict(tag='matched-'+mode, leaf=leaves[index].hex(), pem=text.hex(), expected='ok'))
            credentials.append(dict(tag='wrong-leaf-'+mode, leaf=leaves[(index+1)%3].hex(), pem=text.hex(), expected='none'))
            for pos in sorted({0,1,2,3,len(der)//2,len(der)-1}):
                add(mode+'-truncation', mode, der[:pos])
            for suffix in (b'\x00', b'\x05\x00'):
                add(mode+'-trailing', mode, der+suffix)
            fs = fields(der)
            add(mode+'-wrong-version', mode, tlv(48, integer(2)+b''.join(fs[1:])))
            add(mode+'-missing-field', mode, tlv(48, b''.join(fs[:1]+fs[2:] if mode=='sec1' else fs[:-1])))
            add(mode+'-extra-field', mode, tlv(48, b''.join(fs)+b'\x05\x00'))
            if mode == 'sec1':
                # Remove optional public value (standalone curve remains).
                add('SEC1-optional-public-absent', mode, tlv(48, b''.join(fs[:3])), expected)
                add('SEC1-required-namedCurve', mode, tlv(48, b''.join(fs[:2]+fs[3:])))
                for scalar in (bytes(32), (0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551).to_bytes(32,'big'), bytes(31), bytes(33)):
                    add('SEC1-invalid-scalar', mode, tlv(48, fs[0]+tlv(4,scalar)+b''.join(fs[2:])))
                bad = bytearray(fs[-1]); bad[-1] ^= 1
                add('SEC1-public-disagrees', mode, tlv(48,b''.join(fs[:-1])+bad))
                bad = bytearray(fs[2]); bad[-1] ^= 1
                add('SEC1-wrong-curve', mode, tlv(48,b''.join(fs[:2])+bad+b''.join(fs[3:])))
            if mode == 'pkcs1':
                numbers = key.private_numbers()
                vals = [0,numbers.public_numbers.n,numbers.public_numbers.e,numbers.d,numbers.p,numbers.q,numbers.dmp1,numbers.dmq1,numbers.iqmp]
                assert numbers.p*numbers.q == numbers.public_numbers.n
                assert numbers.d % (numbers.p-1) == numbers.dmp1
                assert numbers.d % (numbers.q-1) == numbers.dmq1
                assert numbers.iqmp*numbers.q % numbers.p == 1
                # A modulo-width comparison of n against p*q must not accept
                # discarded high product limbs. This also independently checks
                # that the CRT validation rejects n != p*q.
                forged = None
                for scale in range(2,16):
                    for attempt in range(1,2048,2):
                        offset = attempt if scale%2==0 else attempt+1
                        p2 = numbers.p*scale+offset
                        q2 = numbers.q*scale+offset+2
                        n2 = p2*q2 % (1<<2048)
                        modulus = math.lcm(p2-1,q2-1)
                        if n2.bit_length()!=2048 or math.gcd(p2,q2)!=1 or math.gcd(65537,modulus)!=1:
                            continue
                        d2 = pow(65537,-1,modulus)
                        if d2 >= n2:
                            continue
                        forged = tlv(48,b''.join(map(integer,[0,n2,65537,d2,p2,q2,d2%(p2-1),d2%(q2-1),pow(q2,-1,p2)])))
                        break
                    if forged is not None:
                        break
                assert forged is not None
                try:
                    S.load_der_private_key(forged,None)
                except ValueError:
                    pass
                else:
                    raise AssertionError('independent oracle accepted n != p*q')
                add('RSA-truncated-product-rejected',mode,forged)
                for field in range(1,9):
                    mutated = list(vals); mutated[field] += 2
                    add('RSA-inconsistent-private-field', mode, tlv(48,b''.join(map(integer,mutated))))
                    bad = list(fs); bad[field] = tlv(2,b'\x00'+read(fs[field])[1])
                    add('RSA-nonminimal-private-integer', mode, tlv(48,b''.join(bad)))
        encrypted = key.private_bytes(S.Encoding.PEM,S.PrivateFormat.PKCS8,S.BestAvailableEncryption(b'synthetic-only'))
        add('encrypted-PKCS8-explicit', 'pem', encrypted, 'encrypted')
        credentials.append(dict(tag='encrypted-explicit',leaf=leaves[index].hex(),pem=encrypted.hex(),expected='encrypted'))
        legacy = key.private_bytes(S.Encoding.PEM,S.PrivateFormat.TraditionalOpenSSL,S.BestAvailableEncryption(b'synthetic-only'))
        add('encrypted-legacy-explicit', 'pem',legacy,'encrypted')
    # Admission preserves RSA SPKI algorithm restrictions: TLS profile permits
    # RSAE CertificateVerify only, so a PSS-only leaf cannot be used here.
    cert_parts = fields(leaves[2]); tbs_parts = fields(cert_parts[0])
    spki_parts = fields(tbs_parts[6])
    rsa_pem = keys[2].private_bytes(S.Encoding.PEM,S.PrivateFormat.PKCS8,S.NoEncryption())
    pss_alg = tlv(48,tlv(6,bytes.fromhex('2a864886f70d01010a')))
    tbs_parts[6] = tlv(48,pss_alg+spki_parts[1])
    pss_leaf = tlv(48,tlv(48,b''.join(tbs_parts))+b''.join(cert_parts[1:]))
    credentials.append(dict(tag='PSS-only-SPKI-rejected',leaf=pss_leaf.hex(),pem=rsa_pem.hex(),expected='none'))
    for bad_leaf in (b'',b'\x30\x00',leaves[2][:-1],leaves[2]+b'\x00'):
        credentials.append(dict(tag='malformed-leaf',leaf=bad_leaf.hex(),pem=rsa_pem.hex(),expected='none'))
    # Retain the independent library verdict for every row. Strict DER/profile
    # rejection can be stronger than a permissive loader; preserve disagreements
    # explicitly instead of turning them into alleged library rejections.
    for row in rows:
        data = bytes.fromhex(row['data'])
        try:
            loaded = (S.load_pem_private_key(data,None) if row['mode']=='pem' else S.load_der_private_key(data,None))
        except (ValueError,TypeError,UnsupportedAlgorithm):
            row['cryptography_load'] = 'rejected'
            assert row['expected'] in ('none','encrypted'),row['tag']
        else:
            observed = public(loaded)
            if row['expected'] not in ('none','encrypted'):
                assert observed == row['expected'],row['tag']
                row['cryptography_load'] = 'matching-public-key'
            else:
                row['cryptography_load'] = 'accepted-outside-binding-profile'
    result = dict(synthetic_only=True, oracle='Python cryptography '+cryptography.__version__, generation_script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), private=rows, credentials=credentials)
    (ROOT/'private_key_vectors.json').write_text(json.dumps(result,indent=2)+'\n')
    print({'private':len(rows),'credentials':len(credentials),'oracle':result['oracle']})

def verify_frozen():
    fixture=json.loads((ROOT/'private_key_vectors.json').read_text())
    assert fixture['generation_script_sha256']==hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    counts={}
    for row in fixture['private']:
        try:
            data=bytes.fromhex(row['data'])
            loaded=(S.load_pem_private_key(data,None) if row['mode']=='pem' else S.load_der_private_key(data,None))
        except (ValueError,TypeError,UnsupportedAlgorithm):
            verdict='rejected'
            assert row['expected'] in ('none','encrypted'),row['tag']
        else:
            if row['expected'] not in ('none','encrypted'):
                assert public(loaded)==row['expected'],row['tag']
                verdict='matching-public-key'
            else:
                verdict='accepted-outside-binding-profile'
        assert verdict==row['cryptography_load'],row['tag']
        counts[verdict]=counts.get(verdict,0)+1
    print(json.dumps({'total':len(fixture['private']),'oracle':fixture['oracle'],'independent_verdicts':counts}))

if __name__ == '__main__':
    verify_frozen() if sys.argv[1:]==['--verify'] else main()
