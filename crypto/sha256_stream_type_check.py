"""Accept valid stream use; reject copying and repeated finalization."""
from pathlib import Path
import subprocess
import tempfile


def main():
    root = Path(__file__).resolve().parent
    prefix = 'import Base\nimport ../sha256_stream.bend as S\n\n'
    valid = {
        'finish': 'def valid(owner: S.Stream) -> Maybe<&2, List<&2, U32>>:\n  S.finish(owner)\n',
        'update': 'def valid(owner: S.Stream) -> Maybe<&1, S.Stream>:\n  S.update([], owner)\n',
    }
    invalid = {
        'copy': 'def misuse(+owner: S.Stream) -> S.Stream & S.Stream:\n  (owner, owner)\n',
        'finish-twice': 'def misuse(+owner: S.Stream) -> Maybe<&2, List<&2, U32>> & Maybe<&2, List<&2, U32>>:\n  (S.finish(owner), S.finish(owner))\n',
    }
    with tempfile.TemporaryDirectory(dir=root, prefix='sha-stream-type-') as folder:
        for name, body in valid.items():
            path = Path(folder) / (name + '.bend')
            path.write_text(prefix + body)
            result = subprocess.run(['bend', str(path), '--check-only'],
                                    capture_output=True, text=True, timeout=20)
            assert result.returncode == 0, (name, result.stdout + result.stderr)
        for name, body in invalid.items():
            path = Path(folder) / (name + '.bend')
            path.write_text(prefix + body)
            result = subprocess.run(['bend', str(path), '--check-only'],
                                    capture_output=True, text=True, timeout=20)
            diagnostic = result.stdout + result.stderr
            assert result.returncode != 0, (name, 'invalid owner use compiled')
            assert 'Location: misuse' in diagnostic and 'Type' in diagnostic and 'Data' in diagnostic, (name, diagnostic)
    print('SHA-256 stream ownership: two valid uses pass; copying and repeated finalization fail')


if __name__ == '__main__':
    main()
