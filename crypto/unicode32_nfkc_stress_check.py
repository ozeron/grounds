"""Check the full byte-bound expansion, ordering, equal-class stability and scalar bound."""
import argparse
import hashlib
import json
import subprocess
import unicodedata
from pathlib import Path

ROOT = Path(__file__).resolve().parent
U = unicodedata.ucd_3_2_0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path)
    parser.add_argument('--mode', choices=['expand', 'order', 'stable', 'limit'])
    parser.add_argument('binary', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    binary = args.binary[1:] if args.binary[:1] == ['--'] else args.binary
    if not binary:
        parser.error('supply evaluator')
    expansion = ''.join(chr(v) for v in [1589, 1604, 1609, 32, 1575, 1604, 1604, 1607, 32, 1593, 1604, 1610, 1607, 32, 1608, 1587, 1604, 1605])
    records = []
    for mode in [args.mode] if args.mode else ['expand', 'order', 'stable', 'limit']:
        if mode == 'limit':
            record = {'mode': mode, 'maximum_scalar_input': 262140, 'rejected_input': 262141}
        else:
            if mode == 'expand':
                codes = '\ufdfa' * 21845
                wanted = expansion * 21845
            elif mode == 'order':
                codes = 'A' + ('\u0315\u0300' * 16383) + '\u0315'
                wanted = '\u00c0' + '\u0300' * 16382 + '\u0315' * 16384
            else:
                codes = 'A' + ('\u0301\u0300' * 16383) + '\u0301'
                wanted = '\u00c1' + ('\u0300\u0301' * 16383)
            assert len(codes.encode('utf-8')) == 65535
            assert U.normalize('NFKC', codes) == wanted, mode
            record = {'mode': mode, 'input_UTF8_bytes': 65535, 'input_scalars': len(codes),
                      'output_scalars': len(wanted), 'expected_UTF32BE_sha256': hashlib.sha256(wanted.encode('utf-32-be')).hexdigest()}
            del codes, wanted
        result = subprocess.run([*binary, mode, str(ROOT / 'unicode32_nfkc.bin')], capture_output=True, timeout=100)
        assert result.returncode == 0 and result.stdout == b'true\n', (mode, result.returncode, result.stdout[-100:], result.stderr[-1000:])
        records.append(record)
        print('verified', mode, flush=True)
    report = {'binary': binary, 'unicode_version': U.unidata_version, 'cases': records, 'complete_StringPrep_or_Name_comparison': False}
    if args.report:
        args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
