"""CertificateVerify signing wrappers consume private owners on every result."""
from pathlib import Path
import subprocess
import tempfile


def main():
    root = Path(__file__).resolve().parent
    prefix = 'import Base\nimport ../tls_certificate_verify.bend as C\nimport ../../crypto/rsa_private.bend as R\n\n'
    valid = {
        'ecdsa': 'def valid(owner: C.EcdsaPrivate) -> Maybe<&1, List<&2, U32>>:\n  C.sign_ecdsa(owner, C.Server{}, [])\n',
        'rsa': 'def valid(owner: R.Private) -> Maybe<&1, List<&2, U32>>:\n  C.sign_rsa(owner, C.Client{}, [], [], [])\n',
    }
    invalid = {
        'ecdsa-copy': 'def misuse(+owner: C.EcdsaPrivate) -> C.EcdsaPrivate & C.EcdsaPrivate:\n  (owner, owner)\n',
        'ecdsa-reuse': 'def misuse(+owner: C.EcdsaPrivate) -> Maybe<&1, List<&2, U32>> & Maybe<&1, List<&2, U32>>:\n  (C.sign_ecdsa(owner, C.Server{}, []), C.sign_ecdsa(owner, C.Server{}, []))\n',
        'rsa-reuse': 'def misuse(+owner: R.Private) -> Maybe<&1, List<&2, U32>> & Maybe<&1, List<&2, U32>>:\n  (C.sign_rsa(owner, C.Server{}, [], [], []), C.sign_rsa(owner, C.Server{}, [], [], []))\n',
    }
    with tempfile.TemporaryDirectory(dir=root, prefix='tls-certificate-verify-type-') as tmp:
        for wanted, examples in ((True, valid), (False, invalid)):
            for name, source in examples.items():
                path = Path(tmp) / f'{name}.bend'
                path.write_text(prefix + source)
                run = subprocess.run(['bend', str(path), '--check-only'], capture_output=True, text=True, timeout=30)
                assert (run.returncode == 0) == wanted, (name, run.stdout, run.stderr)
                if not wanted:
                    assert 'Location: misuse' in run.stdout + run.stderr, (name, run.stdout, run.stderr)
    print('TLS CertificateVerify ownership: 2 valid declarations; 3 copies/reuses rejected')


if __name__ == '__main__':
    main()
