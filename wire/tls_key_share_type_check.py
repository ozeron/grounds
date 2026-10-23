"""One-use TLS ephemeral keys: acceptance and copying/reuse rejection."""
from pathlib import Path
import subprocess
import tempfile


def main():
    root = Path(__file__).resolve().parent
    prefix = 'import Base\nimport ../tls_key_share.bend as K\n\ndef main() -> IO(Unit):\n  IO.pure(Unit, Unit{})\n\n'
    valid = {
        'consume': 'def valid(owner: K.Ephemeral) -> Maybe<&1, List<&2, U32>>:\n  K.shared(owner, [])\n',
        'drop': 'def valid(owner: K.Ephemeral) -> Unit:\n  K.retire(owner)\n',
        'generate': 'def valid() -> IO(Maybe<&1, K.Offer>):\n  K.generate(K.P256{})\n',
    }
    invalid = {
        'copy': 'def misuse(+owner: K.Ephemeral) -> K.Ephemeral & K.Ephemeral:\n  (owner, owner)\n',
        'reuse': 'def misuse(+owner: K.Ephemeral) -> Maybe<&1, List<&2, U32>> & Maybe<&1, List<&2, U32>>:\n  (K.shared(owner, []), K.shared(owner, []))\n',
        'copy-offer': 'def misuse(+owner: K.Offer) -> K.Offer & K.Offer:\n  (owner, owner)\n',
    }
    with tempfile.TemporaryDirectory(dir=root, prefix='tls-key-share-type-') as tmp:
        for wanted, examples in ((True, valid), (False, invalid)):
            for name, source in examples.items():
                path = Path(tmp) / f'{name}.bend'
                path.write_text(prefix + source)
                # Key generation owns an OS RNG effect. --check-only rejects
                # every imported foreign effect by policy, so use the ordinary
                # checked JS frontend without executing its output instead.
                run = subprocess.run(['bend', str(path), '-o', str(Path(tmp) / f'{name}.js')], capture_output=True, text=True, timeout=30)
                assert (run.returncode == 0) == wanted, (name, run.stdout, run.stderr)
                if not wanted:
                    assert 'Location: misuse' in run.stdout + run.stderr, (name, run.stdout, run.stderr)
    print('TLS key-share ownership: 3 valid declarations; 3 copies/reuses rejected')


if __name__ == '__main__':
    main()
