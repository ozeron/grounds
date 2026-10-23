"""Check production key-update reservation boundaries and reference identities."""
import argparse
import json
from pathlib import Path
import subprocess


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--report', type=Path)
    p.add_argument('binary', nargs=argparse.REMAINDER)
    a = p.parse_args()
    binary = a.binary[1:] if a.binary[:1] == ['--'] else a.binary
    expected = ['false','true','false','true','true','false','false','false','true','false']
    result = subprocess.run([*binary, 'diagnostics'], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0 and result.stdout.splitlines() == expected, (result.returncode,result.stdout,result.stderr)
    report = dict(cases=len(expected), passed=len(expected), binary=binary,
                  scope='AES and ChaCha sending-limit reservation; DNS/IP/SNI reference admission')
    if a.report:
        a.report.parent.mkdir(parents=True, exist_ok=True)
        a.report.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
