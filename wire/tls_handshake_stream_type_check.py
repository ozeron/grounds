"""Check affine handshake decoder ownership."""
from pathlib import Path
import subprocess
import tempfile


def main():
    root = Path(__file__).resolve().parent
    prefix = 'import Base\nimport ../tls_handshake_stream.bend as S\n\n'
    valid = {
        'finish': 'def valid(owner: S.Decoder) -> Bool:\n  S.finish(owner)\n',
        'boundary': 'def valid(owner: S.Decoder) -> Maybe<&1, S.Decoder>:\n  S.boundary(owner)\n',
    }
    invalid = {
        'copy-decoder': 'def misuse(+owner: S.Decoder) -> S.Decoder & S.Decoder:\n  (owner, owner)\n',
        'finish-twice': 'def misuse(+owner: S.Decoder) -> Bool & Bool:\n  (S.finish(owner), S.finish(owner))\n',
        'copy-partial': 'def misuse(+owner: S.Partial) -> S.Partial & S.Partial:\n  (owner, owner)\n',
    }
    with tempfile.TemporaryDirectory(dir=root, prefix='tls-handshake-stream-type-') as folder:
        for wanted, examples in ((True, valid), (False, invalid)):
            for name, body in examples.items():
                path = Path(folder) / f'{name}.bend'
                path.write_text(prefix + body)
                result = subprocess.run(['bend', str(path), '--check-only'], capture_output=True, text=True, timeout=20)
                diagnostic = result.stdout + result.stderr
                assert (result.returncode == 0) == wanted, (name, diagnostic)
                if not wanted:
                    assert 'Location: misuse' in diagnostic, (name, diagnostic)
    print('TLS handshake stream ownership: two valid uses; three reuse errors rejected')


if __name__ == '__main__':
    main()
