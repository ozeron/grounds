"""Full scalar/byte-bound stored-preparation checks with independent 3.2 patterns."""
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from unicode32_prepare_check import expected

ROOT = Path(__file__).resolve().parent


def oracle(mode):
    if mode in ('limit', 'reject'):
        record = {'mode': mode, 'maximum_input_scalars': 65535, 'rejected_input_scalars': 65536}
    else:
        if mode == 'expand':
            codes = [0xfdfa] * 21845
            wanted = [32] + [1589, 1604, 1609, 32, 32, 1575, 1604, 1604, 1607, 32, 32, 1593, 1604, 1610, 1607, 32, 32, 1608, 1587, 1604, 1605] * 21845 + [32]
        elif mode == 'order':
            codes = [65] + [0x315, 0x300] * 16383 + [0x315]
            wanted = [32, 0xe0] + [0x300] * 16382 + [0x315] * 16384 + [32]
        elif mode == 'stable':
            codes = [65] + [0x301, 0x300] * 16383 + [0x301]
            wanted = [32, 0xe1] + [0x300, 0x301] * 16383 + [32]
        elif mode in ('fold-bound', 'fold-byte'):
            size = 65535 if mode == 'fold-bound' else 21845
            codes = [0x33c6] * size
            wanted = [32] + [99, 8725, 107, 103] * size + [32]
        elif mode == 'protected':
            codes = [32, 0x903] * 16383 + [65, 66, 67]
            wanted = [32] + [32, 0x903] * 16383 + [97, 98, 99, 32]
        else:
            codes = [32] * 65535
            wanted = [32, 32]
        assert expected(codes, True) == wanted, mode
        byte_count = len(''.join(chr(c) for c in codes).encode('utf-8'))
        assert byte_count == (196605 if mode == 'fold-bound' else 65535), (mode, byte_count)
        encoded = ''.join(chr(c) for c in wanted).encode('utf-32-be')
        record = {'mode': mode, 'input_scalars': len(codes), 'input_UTF8_bytes': byte_count,
                  'output_scalars': len(wanted), 'expected_UTF32BE_sha256': hashlib.sha256(encoded).hexdigest()}
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path)
    parser.add_argument('--oracle-only', action='store_true')
    parser.add_argument('--mode', choices=['expand', 'order', 'stable', 'fold-bound', 'fold-byte', 'protected', 'spaces', 'limit', 'reject'])
    parser.add_argument('binary', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.oracle_only:
        assert args.mode
        print(json.dumps(oracle(args.mode), sort_keys=True))
        return
    binary = args.binary[1:] if args.binary[:1] == ['--'] else args.binary
    if not binary:
        parser.error('supply evaluator')
    records = []
    for mode in [args.mode] if args.mode else ['expand', 'order', 'stable', 'fold-bound', 'fold-byte', 'protected', 'spaces', 'limit', 'reject']:
        checked = subprocess.run([sys.executable, str(Path(__file__).resolve()), '--oracle-only', '--mode', mode], capture_output=True, check=True, timeout=60)
        record = json.loads(checked.stdout)
        print("oracle verified", mode, flush=True)
        result = subprocess.run([*binary, mode, str(ROOT / 'unicode32_nfkc.bin'), str(ROOT / 'unicode32_prepare.bin')], capture_output=True, timeout=100)
        assert result.returncode == 0 and result.stdout == b'true\n', (mode, result.returncode, result.stdout[-100:], result.stderr[-1000:])
        records.append(record)
        print('verified', mode, flush=True)
    report = {'binary': binary, 'unicode_version': '3.2.0', 'cases': records,
              'scalar_preparation_only_not_transcoding_Name_or_authorization': True}
    if args.report:
        args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
