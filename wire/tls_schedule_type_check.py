"""Check affine schedule/Finished use and reject cross-stage misuse."""
from pathlib import Path
import subprocess
import tempfile


def main():
    root = Path(__file__).resolve().parent
    prefix = 'import Base\nimport ../tls_schedule.bend as S\n\n'
    valid = {
        'application': 'def valid(owner: S.ToApplication) -> Maybe<&1, S.ApplicationTraffic>:\n  S.application(owner, S.zeros())\n',
        'finished': 'def valid(owner: S.FinishedKey) -> Maybe<&2, List<&2, U32>>:\n  S.finished(owner, S.zeros())\n',
    }
    invalid = {
        'copy-handshake': 'def misuse(+owner: S.Handshake) -> S.Handshake & S.Handshake:\n  (owner, owner)\n',
        'application-twice': 'def misuse(+owner: S.ToApplication) -> Maybe<&1, S.ApplicationTraffic> & Maybe<&1, S.ApplicationTraffic>:\n  (S.application(owner, S.zeros()), S.application(owner, S.zeros()))\n',
        'finished-twice': 'def misuse(+owner: S.FinishedKey) -> Maybe<&2, List<&2, U32>> & Maybe<&2, List<&2, U32>>:\n  (S.finished(owner, S.zeros()), S.finished(owner, S.zeros()))\n',
        'wrong-stage': 'def misuse(owner: S.HandshakeTraffic) -> Maybe<&1, S.ApplicationTraffic>:\n  S.application(owner, S.zeros())\n',
    }
    with tempfile.TemporaryDirectory(dir=root, prefix='tls-schedule-type-') as folder:
        for wanted, examples in ((True, valid), (False, invalid)):
            for name, body in examples.items():
                path = Path(folder) / f'{name}.bend'
                path.write_text(prefix + body)
                result = subprocess.run(['bend', str(path), '--check-only'], capture_output=True, text=True, timeout=20)
                diagnostic = result.stdout + result.stderr
                assert (result.returncode == 0) == wanted, (name, diagnostic)
                if not wanted:
                    assert 'Location: misuse' in diagnostic, (name, diagnostic)
    print('TLS schedule ownership: two valid uses; four copying/reuse/stage errors rejected')


if __name__ == '__main__':
    main()
