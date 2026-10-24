"""Native CertificateVerify SHA-2/SPKI binding using OpenSSL synthetic signatures."""
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    binary = sys.argv[1:]
    count = 0
    with tempfile.TemporaryDirectory(prefix='grounds-cv-sha2-') as folder:
        root = Path(folder)

        def openssl(*args):
            return subprocess.run(['openssl', *map(str, args)], capture_output=True, check=True).stdout

        keys = {}
        for name, params in (
            ('p256', ['EC', '-pkeyopt', 'ec_paramgen_curve:P-256']),
            ('p384', ['EC', '-pkeyopt', 'ec_paramgen_curve:P-384']),
            ('rsa', ['RSA', '-pkeyopt', 'rsa_keygen_bits:2048']),
        ):
            key = root / (name + '.key')
            openssl('genpkey', '-algorithm', *params, '-out', key)
            keys[name] = openssl('pkey', '-in', key, '-pubout', '-outform', 'DER')

        serial = 0

        def verify(scheme, role, public, transcript, signature, expected):
            nonlocal serial, count
            paths = []
            for value in (public, transcript, signature):
                serial += 1
                path = root / str(serial)
                path.write_bytes(value)
                paths.append(str(path))
            result = subprocess.run(binary + ['run', 'verify-sha2', str(scheme), role] + paths,
                                    capture_output=True, text=True, timeout=30)
            assert result.returncode == 0 and result.stdout.splitlines() == [str(expected).lower()], (
                scheme, role, len(transcript), result.returncode, result.stdout, result.stderr)
            count += 1

        for name, scheme, hash_name in [('p256', 1027, 'sha256'), ('p384', 1283, 'sha384'),
                                       ('rsa', 2053, 'sha384'), ('rsa', 2054, 'sha512')]:
            for width in (32, 48):
                for role in ('s', 'c'):
                    transcript = hashlib.sha384(f'{name}/{scheme}/{role}'.encode()).digest()[:width]
                    context = bytes([32]) * 64 + b'TLS 1.3, ' + (
                        b'server' if role == 's' else b'client') + b' CertificateVerify\x00' + transcript
                    data, sig = root / 'content', root / 'signature'
                    data.write_bytes(context)
                    opts = ['-sigopt', 'rsa_padding_mode:pss', '-sigopt',
                            f'rsa_pss_saltlen:{hashlib.new(hash_name).digest_size}'] if name == 'rsa' else []
                    openssl('dgst', '-' + hash_name, '-sign', root / (name + '.key'),
                            *opts, '-out', sig, data)
                    signature = sig.read_bytes()
                    args = (scheme, role, keys[name], transcript, signature)
                    verify(*args, True)
                    verify(scheme, 'c' if role == 's' else 's', *args[2:], False)
                    verify(scheme, role, keys[name], bytes([transcript[0] ^ 1]) + transcript[1:], signature, False)
                    verify(scheme, role, keys[name], transcript, signature[:-1] + bytes([signature[-1] ^ 1]), False)
                    verify(scheme, role, keys['rsa' if name != 'rsa' else 'p384'], transcript, signature, False)
                    verify(2053 if scheme == 2054 else 2054, *args[1:], False)
                    verify(scheme, role, keys[name], transcript[:-1], signature, False)
                    verify(scheme, role, keys[name], transcript, signature + b'\x00', False)
        # RSA-PSS TLS signature salt is exactly the digest width, unlike the
        # broader certificate-signature profile. Wrong salt still signs validly.
        for scheme, hash_name in [(2053, 'sha384'), (2054, 'sha512')]:
            for salt in (0, hashlib.new(hash_name).digest_size - 1):
                openssl('dgst', '-' + hash_name, '-sign', root / 'rsa.key',
                        '-sigopt', 'rsa_padding_mode:pss', '-sigopt', f'rsa_pss_saltlen:{salt}',
                        '-out', sig, data)
                verify(scheme, 'c', keys['rsa'], transcript, sig.read_bytes(), False)
    print(f'CertificateVerify SHA-2: {count} native positive/role/hash/SPKI/scheme/DER/salt cases passed')


if __name__ == '__main__':
    main()
