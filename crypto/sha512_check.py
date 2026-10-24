"""FIPS 180-4/RFC 6234 SHA-384/512, RFC 4231 HMAC and RFC 5869-style HKDF.

Only synthetic keys. Independent Python hashlib/hmac and cryptography oracles;
all inputs are deterministic and offline. The RFC 4231 truncation case checks
its published 128-bit prefix; the API always returns the complete HMAC.
"""
import argparse
import hashlib
import hmac
from pathlib import Path
import random
import subprocess
import tempfile

SHA_VECTORS = {
    'sha384': [
        (b'', '38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b'),
        (b'abc', 'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7'),
        (b'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu',
         '09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039'),
        (b'a' * 1000000, '9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985'),
    ],
    'sha512': [
        (b'', 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e'),
        (b'abc', 'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f'),
        (b'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu',
         '8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909'),
        (b'a' * 1000000, 'e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b'),
    ],
}
HMAC_VECTORS = [
    (b'\x0b'*20, b'Hi There', 'afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6'),
    (b'Jefe', b'what do ya want for nothing?', 'af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649'),
    (b'\xaa'*20, b'\xdd'*50, '88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27'),
    (bytes(range(1,26)), b'\xcd'*50, '3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb'),
    (b'\x0c'*20, b'Test With Truncation', '3abf34c3503b2a23a46efc619baef897'),
    (b'\xaa'*131, b'Test Using Larger Than Block-Size Key - Hash Key First',
     '4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952'),
    (b'\xaa'*131, b'This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.',
     '6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e'),
]

def expand(prk, info, length):
    last = b''
    out = b''
    for counter in range(1, (length + 47)//48 + 1):
        last = hmac.digest(prk, last + info + bytes([counter]), 'sha384')
        out += last
    return out[:length]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cryptography', action='store_true', help='also check against the fixture-recorder oracle')
    parser.add_argument('sha512')
    parser.add_argument('hkdf')
    args = parser.parse_args()
    rng = random.Random(0x512384)
    edges = (0, 1, 2, 3, 47, 48, 63, 64, 65, 110, 111, 112, 113, 127, 128, 129, 239, 240, 255, 256, 257, 1024, 4097, 65536)
    random_messages = [rng.randbytes(n) for n in edges] + [rng.randbytes(rng.randrange(8193)) for _ in range(40)]
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        msg, key, info_path = (tmp / n for n in ('msg', 'key', 'info'))
        def invoke(command, *params):
            result = subprocess.run([command, *map(str, params)], capture_output=True, text=True, timeout=30)
            assert result.returncode == 0, (result.returncode, result.stderr)
            return result.stdout.splitlines()
        for mode, vectors in SHA_VECTORS.items():
            for data, known in vectors + [(m, None) for m in random_messages]:
                expected = hashlib.new(mode, data).hexdigest()
                assert known is None or expected == known
                msg.write_bytes(data)
                assert invoke(args.sha512, mode, msg) == [expected], (mode, len(data))
            print(f'{mode}: {len(vectors)} FIPS/RFC vectors + {len(random_messages)} differential cases passed')
        hm_random = [(rng.randbytes(k), rng.randbytes(m), None) for k,m in
                     ((0,0),(1,1),(111,111),(112,112),(127,127),(128,128),(129,129),(255,4097),(48,65536))]
        for k, m, known in HMAC_VECTORS + hm_random:
            expected = hmac.digest(k, m, 'sha384').hex()
            assert known is None or expected.startswith(known)
            msg.write_bytes(m); key.write_bytes(k)
            assert invoke(args.sha512, key, msg, 'hmac') == [expected], (len(k), len(m))
        print(f'HMAC-SHA384: {len(HMAC_VECTORS)} RFC 4231 + {len(hm_random)} differential cases passed')
        # RFC 5869 test case 1, 2 and 3 inputs, instantiated with SHA-384.
        hk_cases = [(bytes(range(13)), b'\x0b'*22, bytes(range(240,250)), 42),
                    (bytes(range(96,176)), bytes(range(80)), bytes(range(176,256)), 82),
                    (b'', b'\x0b'*22, b'', 42)]
        hk_cases += [(rng.randbytes(16), rng.randbytes(128), rng.randbytes(17), n)
                     for n in (0,1,47,48,49,95,96,97,12240)]
        hk_cases += [(rng.randbytes(rng.randrange(200)), rng.randbytes(rng.randrange(300)),
                      rng.randbytes(rng.randrange(200)), rng.randrange(512)) for _ in range(20)]
        for salt, ikm, info, length in hk_cases:
            prk = hmac.digest(salt, ikm, 'sha384')
            okm = expand(prk, info, length)
            if args.cryptography:
                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.primitives.kdf.hkdf import HKDF
                assert okm == HKDF(algorithm=hashes.SHA384(), length=length, salt=salt, info=info).derive(ikm)
            key.write_bytes(salt); msg.write_bytes(ikm); info_path.write_bytes(info)
            assert invoke(args.hkdf, key, msg, info_path, length) == [prk.hex(), okm.hex()], length
        result = subprocess.run([args.hkdf, str(key), str(msg), str(info_path), '12241'], capture_output=True, text=True, timeout=30)
        assert result.returncode != 0, 'accepted more than 255 hash blocks'
        print(f'HKDF-SHA384: {len(hk_cases)} SHA-384 RFC-style/boundary/differential + 1 rejection passed')

if __name__ == '__main__':
    main()
