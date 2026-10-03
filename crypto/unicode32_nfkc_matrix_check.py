"""Exhaustive Unicode 3.2 single-scalar NFKC differential check."""
import argparse
import hashlib
import json
import subprocess
import tempfile
import unicodedata
from pathlib import Path

U = unicodedata.ucd_3_2_0
ROOT = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path)
    parser.add_argument('binary', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    binary = args.binary[1:] if args.binary[:1] == ['--'] else args.binary
    if not binary:
        parser.error('supply evaluator')
    identity = hashlib.sha256()
    count = 0
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        result = subprocess.run([*binary, str(ROOT / 'unicode32_nfkc.bin')], stdout=output, stderr=errors, timeout=110)
        errors.seek(0, 2); errors.seek(max(0, errors.tell() - 1200))
        assert result.returncode == 0, (result.returncode, errors.read())
        output.seek(0)
        for codes in [range(0x110000), range(0x110000, 0x111000), range(0xfffff000, 0x100000000)]:
            for offset in range(0, len(codes), 1024):
                wanted = bytearray()
                for code in codes[offset:offset + 1024]:
                    if code > 0x10ffff or 0xd800 <= code <= 0xdfff:
                        expected = b'X'
                    else:
                        normalized = U.normalize('NFKC', chr(code))
                        length = len(normalized)
                        expected = bytes([48 + length if length < 10 else 87 + length])
                        expected += ''.join(f'{ord(c):06x}' for c in normalized).encode()
                    wanted.extend(expected)
                    identity.update(code.to_bytes(4, 'big') + expected)
                    count += 1
                assert output.readline().rstrip(b'\n') == wanted, ('scalar chunk', hex(codes[offset]))
        assert output.read(1) == b'', 'trailing output'
    report = {'binary': binary, 'unicode_version': U.unidata_version, 'scalar_checks': count,
              'all_Unicode_code_points': 0x110000, 'out_of_repertoire_U32_values': 8192,
              'corpus_sha256': identity.hexdigest(), 'complete_StringPrep_or_Name_comparison': False}
    if args.report:
        args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
