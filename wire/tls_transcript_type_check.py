"""Compile ownership examples for the public TLS transcript interface."""
from pathlib import Path
import subprocess
import tempfile


def main():
    root = Path(__file__).resolve().parent
    prefix = 'import Base\nimport ../tls_transcript.bend as T\n\n'
    valid = {
        'append': 'def valid(owner: T.Transcript) -> Maybe<&1, T.Transcript>:\n  T.append(owner, [1, 0, 0, 0])\n',
        'snapshot': 'def valid(owner: T.Transcript) -> T.Transcript & Maybe<&2, List<&2, U32>>:\n  T.snapshot(owner)\n',
    }
    invalid = {
        'copy': 'def misuse(+owner: T.Transcript) -> T.Transcript & T.Transcript:\n  (owner, owner)\n',
        'finish-twice': 'def misuse(+owner: T.Transcript) -> Maybe<&2, List<&2, U32>> & Maybe<&2, List<&2, U32>>:\n  (T.finish(owner), T.finish(owner))\n',
    }
    with tempfile.TemporaryDirectory(dir=root, prefix='tls-transcript-type-') as folder:
        for expected, examples in ((True, valid), (False, invalid)):
            for name, body in examples.items():
                path = Path(folder) / f'{name}.bend'
                path.write_text(prefix + body)
                result = subprocess.run(['bend', str(path), '--check-only'], capture_output=True, text=True, timeout=20)
                diagnostic = result.stdout + result.stderr
                assert (result.returncode == 0) == expected, (name, diagnostic)
                if not expected:
                    assert 'Location: misuse' in diagnostic and 'Type' in diagnostic and 'Data' in diagnostic, (name, diagnostic)
    print('TLS transcript ownership: two valid uses; copying and repeated finalization rejected')


if __name__ == '__main__':
    main()
