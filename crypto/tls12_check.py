"""TLS 1.2 PRF, extended master secret, key block, Finished and AEAD records.

Independent oracles: Python hmac/hashlib for the RFC 5246 PRF, the published
TLS 1.2 PRF test vectors (IETF TLS list, SHA-256 and SHA-384), and the
cryptography package's AESGCM/ChaCha20Poly1305 with the RFC 5246 6.2.3.3
additional data, RFC 5288 explicit nonce and RFC 7905 nonce construction.
"""
import argparse
import hashlib
import hmac
import json
from pathlib import Path
import random
import subprocess
import tempfile

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

VECTORS = [
    ('256', '9bbe436ba940f017b17652849a71db35', b'test label', 'a0ba9f936cda311827a6f796ffd5198c', 100,
     'e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a6b301791e90d35c9c9a46b4e14baf9af'
     '0fa022f7077def17abfd3797c0564bab4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff701'
     '87347b66'),
    ('384', 'b80b733d6ceefcdc71566ea48e5567df', b'test label', 'cd665cf6a8447dd6ff8b27555edb7465', 148,
     '7b0c18e9ced410ed1804f2cfa34a336a1c14dffb4900bb5fd7942107e81c83cde9ca0faa60be9fe34f82b1233c9146a0'
     'e534cb400fed2700884f9dc236f80edd8bfa961144c9e8d792eca722a7b32fc3d416d473ebc2c5fd4abfdad05d918425'
     '9b5bf8cd4d90fa0d31e2dec479e4f1a26066f2eea9a69236a3e52655c9e9aee691c8f3a26854308d5eaa3be85e099070'
     '3d73e56f'),
]


def prf(hash_name, secret, label, seed, length):
    digest = hashlib.sha384 if hash_name == '384' else hashlib.sha256
    seed, a, out = label + seed, label + seed, b''
    while len(out) < length:
        a = hmac.new(secret, a, digest).digest()
        out += hmac.new(secret, a + seed, digest).digest()
    return out[:length]


def aad(sequence, kind, length):
    return sequence.to_bytes(8, 'big') + bytes([kind, 3, 3]) + length.to_bytes(2, 'big')


def gcm(key, salt, sequence, kind, plaintext, explicit=None):
    explicit = sequence.to_bytes(8, 'big') if explicit is None else explicit
    return explicit + AESGCM(key).encrypt(salt + explicit, plaintext, aad(sequence, kind, len(plaintext)))


def chacha(key, iv, sequence, kind, plaintext):
    nonce = bytes(a ^ b for a, b in zip(iv, sequence.to_bytes(12, 'big')))
    return ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad(sequence, kind, len(plaintext)))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--report', type=Path)
    p.add_argument('command', nargs='+')
    a = p.parse_args()
    rng = random.Random(0x0303)
    rows = []
    with tempfile.TemporaryDirectory(prefix='grounds-tls12-') as folder:
        serial = 0

        def put(data):
            nonlocal serial
            serial += 1
            path = Path(folder) / str(serial)
            path.write_bytes(data)
            return str(path)

        def run(name, args, expected):
            r = subprocess.run(a.command + args, capture_output=True, text=True, timeout=120)
            got = r.stdout.splitlines()
            assert r.returncode == 0 and got == expected, (name, args, r.returncode, got, expected, r.stderr[-2000:])
            rows.append(dict(name=name, lines=len(expected)))

        # Published vectors, then randomized differential PRF outputs.
        for hash_name, secret, label, seed, length, output in VECTORS:
            run(f'published-prf-{hash_name}', ['derive', 'prf', hash_name, str(length), put(bytes.fromhex(secret)), put(label), put(bytes.fromhex(seed))],
                [f'prf:{output}'])
        for hash_name in ('256', '384'):
            for secret_size in (0, 1, 32, 48, 64, 65, 128, 129, 200):
                for length in (1, 12, 31, 32, 33, 47, 48, 49, 72, 88, 1024):
                    if (secret_size + length) % 3:
                        continue
                    secret, seed = rng.randbytes(secret_size), rng.randbytes(rng.choice([0, 13, 64, 77]))
                    label = rng.randbytes(rng.choice([1, 13, 22]))
                    run(f'prf-{hash_name}-{secret_size}-{length}', ['derive', 'prf', hash_name, str(length), put(secret), put(label), put(seed)],
                        [f'prf:{prf(hash_name, secret, label, seed, length).hex()}'])
            for length, label in ((0, b'x'), (1025, b'x'), (12, b'')):
                run(f'prf-{hash_name}-reject-{length}-{len(label)}', ['derive', 'prf', hash_name, str(length), put(b'k'), put(label), put(b's')], ['prf:none'])
            for premaster_size in (32, 48):
                premaster = rng.randbytes(premaster_size)
                session_hash = rng.randbytes(48 if hash_name == '384' else 32)
                master = prf(hash_name, premaster, b'extended master secret', session_hash, 48)
                run(f'ems-{hash_name}-{premaster_size}', ['derive', 'master', hash_name, '0', put(premaster), put(session_hash)], [f'master:{master.hex()}'])
                server_random, client_random = rng.randbytes(32), rng.randbytes(32)
                for length in (40, 72, 88):
                    block = prf(hash_name, master, b'key expansion', server_random + client_random, length)
                    run(f'key-block-{hash_name}-{length}', ['derive', 'keys', hash_name, str(length), put(master), put(server_random), put(client_random)], [f'keys:{block.hex()}'])
                for role in ('client', 'server'):
                    data = prf(hash_name, master, role.encode() + b' finished', session_hash, 12)
                    run(f'finished-{hash_name}-{role}', ['derive', role, hash_name, '0', put(master), put(session_hash)], [f'{role}:{data.hex()}'])

        # Records. Sequence numbers start at the seeded counter (0:0 for a
        # fresh owner); each record advances it by one.
        suites = [('aes128', '0', 16, 4), ('aes256', '0', 32, 4), ('chacha', '1', 32, 12)]
        for name, flag, key_size, iv_size in suites:
            key, iv = rng.randbytes(key_size), rng.randbytes(iv_size)
            oracle = (lambda s, k, m, key=key, iv=iv: chacha(key, iv, s, k, m)) if flag == '1' else (lambda s, k, m, key=key, iv=iv: gcm(key, iv, s, k, m))
            for kind in (21, 22, 23):
                messages = [rng.randbytes(n) for n in ((2, 2, 2) if kind == 21 else (0, 1, 15, 16, 17, 1000, 16384))]
                for start in ((0, 0), (0, 16777213), (7, 9)):
                    sequence = (start[0] << 32) + start[1]
                    fragments = [oracle(sequence + i, kind, m) for i, m in enumerate(messages)]
                    expected_seal = []
                    for i, f in enumerate(fragments):
                        if flag == '0' and sequence + i >= 1 << 24:
                            expected_seal.append('seal-error:usage-limit')
                            break
                        expected_seal.append(f'fragment:{f.hex()}')
                    run(f'{name}-seal-{kind}-{start}', ['seal', flag, str(start[0]), str(start[1]), str(kind), put(key), put(iv)] + [put(m) for m in messages], expected_seal)
                    run(f'{name}-open-{kind}-{start}', ['open', flag, str(start[0]), str(start[1]), str(kind), put(key), put(iv)] + [put(f) for f in fragments],
                        [f'plaintext:{m.hex()}' for m in messages])
            # Usage limits: AES-GCM shares the TLS 1.3 per-key record cap;
            # ChaCha20 stops at the 64-bit sequence boundary.
            if flag == '0':
                last = oracle(16777215, 23, b'x')
                run(f'{name}-usage-limit', ['seal', flag, '0', '16777215', '23', put(key), put(iv), put(b'x'), put(b'y')], [f'fragment:{last.hex()}', 'seal-error:usage-limit'])
                # Receivers apply no sending cap; the peer's explicit nonce is used as sent.
                explicit = rng.randbytes(8)
                foreign = gcm(key, iv, 5, 23, b'peer', explicit)
                run(f'{name}-open-peer-explicit-nonce', ['open', flag, '0', '5', '23', put(key), put(iv), put(foreign)], ['plaintext:' + b'peer'.hex()])
                run(f'{name}-open-past-cap', ['open', flag, '1', '0', '23', put(key), put(iv), put(gcm(key, iv, 1 << 32, 23, b'z'))], ['plaintext:' + b'z'.hex()])
            else:
                last = oracle(2**64 - 1, 23, b'x')
                run(f'{name}-exhausted', ['seal', flag, '4294967295', '4294967295', '23', put(key), put(iv), put(b'x'), put(b'y')], [f'fragment:{last.hex()}', 'seal-error:exhausted'])
            good = oracle(0, 23, b'hello')
            tampered = bytearray(good)
            tampered[-1] ^= 1
            body = bytearray(good)
            body[-17] ^= 0x80
            rejects = {
                'tag': bytes(tampered), 'ciphertext': bytes(body), 'truncated': good[:-1],
                'short': good[:(23 if flag == '0' else 15)], 'empty': b'',
            }
            for reject, fragment in rejects.items():
                run(f'{name}-open-reject-{reject}', ['open', flag, '0', '0', '23', put(key), put(iv), put(fragment)], ['open-error:authentication'])
            run(f'{name}-open-wrong-type', ['open', flag, '0', '0', '22', put(key), put(iv), put(good)], ['open-error:authentication'])
            run(f'{name}-open-wrong-sequence', ['open', flag, '0', '1', '23', put(key), put(iv), put(good)], ['open-error:authentication'])
            run(f'{name}-open-after-failure', ['open', flag, '0', '0', '23', put(key), put(iv), put(bytes(tampered)), put(good)], ['open-error:authentication'])
            run(f'{name}-open-oversized', ['open', flag, '0', '0', '23', put(key), put(iv), put(oracle(0, 23, bytes(16385)))], ['open-error:authentication'])
            run(f'{name}-seal-oversized', ['seal', flag, '0', '0', '23', put(key), put(iv), put(bytes(16385))], ['seal-error:invalid'])
            run(f'{name}-seal-ccs-type', ['seal', flag, '0', '0', '20', put(key), put(iv), put(b'\x01')], ['seal-error:invalid'])
            run(f'{name}-key-valid', ['seal', flag, '0', '0', '23', put(key), put(iv)], ['key:valid'])
        for flag, key_size, iv_size in (('0', 24, 4), ('0', 16, 12), ('0', 32, 3), ('1', 16, 12), ('1', 32, 4), ('1', 33, 12)):
            run(f'key-invalid-{flag}-{key_size}-{iv_size}', ['seal', flag, '0', '0', '23', put(bytes(key_size)), put(bytes(iv_size))], ['key:invalid'])
            run(f'read-key-invalid-{flag}-{key_size}-{iv_size}', ['open', flag, '0', '0', '23', put(bytes(key_size)), put(bytes(iv_size))], ['key:invalid'])
    report = dict(cases=len(rows), published_vectors=len(VECTORS), rows=rows)
    if a.report:
        a.report.parent.mkdir(parents=True, exist_ok=True)
        a.report.write_text(json.dumps(report, indent=2) + '\n')
    print(f'tls12: {len(rows)} cases passed')


if __name__ == '__main__':
    main()
