"""Affine TLS state/connection owners admit consumption and reject duplication."""
from pathlib import Path
import subprocess
import tempfile


def main():
    root = Path(__file__).resolve().parent
    prefix = ('import Base\nimport ../tls_client.bend as M\n'
              'import ../bend_tls_client.bend as C\n\n'
              'def main() -> IO(Unit):\n  IO.pure(Unit,Unit{})\n\n')
    examples = [
        ('state-step', True, 'def example(s: M.State) -> M.Action:\n  M.step(s,[])\n'),
        ('connection-close', True, 'def example(c: C.Connection) -> IO(Unit):\n  C.close(c)\n'),
        ('connection-deadline', True, 'def example(c: C.Connection) -> C.Connection:\n  C.deadline(c,1n)\n'),
        ('state-copy', False, 'def misuse(+s: M.State) -> M.State & M.State:\n  (s,s)\n'),
        ('connection-copy', False, 'def misuse(+c: C.Connection) -> C.Connection & C.Connection:\n  (c,c)\n'),
        ('received-copy', False, 'def misuse(+r: C.Received) -> C.Received & C.Received:\n  (r,r)\n'),
        ('send-reuse', False, 'def misuse(+c: C.Connection) -> IO(Result<&2,&1,C.Error,C.Connection>) & IO(Result<&2,&1,C.Error,C.Connection>):\n  (C.send(c,[]),C.send(c,[]))\n'),
    ]
    with tempfile.TemporaryDirectory(dir=root, prefix='tls-client-type-') as tmp:
        for name, wanted, source in examples:
            path = Path(tmp) / (name + '.bend')
            path.write_text(prefix + source)
            result = subprocess.run(['bend', str(path), '-o', str(Path(tmp) / (name + '.js'))],
                                    capture_output=True, text=True, timeout=30)
            assert (result.returncode == 0) == wanted, (name, result.stdout, result.stderr)
            if not wanted:
                assert 'Location: misuse' in result.stdout + result.stderr, (name, result.stdout, result.stderr)
    print('TLS client owners: 3 valid declarations; 4 copies/reuses rejected')


if __name__ == '__main__':
    main()
