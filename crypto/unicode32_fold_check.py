"""Check the complete scalar repertoire against published RFC 3454 B.2 vectors."""
import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
from unicode32_profile_check import expected as profile

ROOT = Path(__file__).resolve().parent


def mappings():
    document = json.loads((ROOT / 'unicode32_fold_vectors.json').read_text())
    assert document['source_sha256'] == 'eb722fa698fb7e8823b835d9fd263e4cdb8f1c7b0d234edf7f0e3bd2ccbb2c79'
    rows = document['mappings']
    result = {int(code, 16): [int(value, 16) for value in values] for code, values in rows}
    assert len(rows) == len(result) == 1371
    return result


def expected(code, mapping, table):
    if code > 0x10ffff or 0xd800 <= code <= 0xdfff:
        return None
    if mapping:
        _, kind = profile(code)
        if kind == 0:
            return []
        if kind == 1:
            code = 32
    return table.get(code, [code])


def encode(values):
    return b'X' if values is None else (f'{len(values):x}' + ''.join(f'{v:06x}' for v in values)).encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path)
    parser.add_argument('--stress-only', action='store_true')
    parser.add_argument('--capture', type=Path, help='retain raw output, including a guard-stopped diagnostic run')
    parser.add_argument('binary', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    binary = args.binary[1:] if args.binary[:1] == ['--'] else args.binary
    if not binary:
        parser.error('supply evaluator')
    table = mappings()
    ranges = [range(0x110000), range(0x110000, 0x111000), range(0xfffff000, 0x100000000)]
    identity = hashlib.sha256()
    count = 0
    with (args.capture.open('x+b') if args.capture else tempfile.TemporaryFile()) as output, tempfile.TemporaryFile() as errors:
        run = subprocess.run(binary, stdout=output, stderr=errors, timeout=110)
        errors.seek(0, 2)
        errors.seek(max(0, errors.tell() - 1600))
        assert run.returncode == 0, (run.returncode, errors.read())
        output.seek(0)
        if args.stress_only:
            assert table[13254] == [99, 8725, 107, 103]
            assert output.read() == b'stress:true\n', '65535-scalar fourfold expansion/order'
            report = {'binary': binary, 'stress_only': True, 'unicode_version': '3.2.0',
                      'input_scalars': 65535, 'output_scalars_checked': 262140,
                      'expected_repeated_mapping': [99, 8725, 107, 103],
                      'NFKC_complete_stringprep_or_Name_comparison': False}
            if args.report:
                args.report.write_text(json.dumps(report, indent=2) + '\n')
            print(json.dumps(report, sort_keys=True))
            return
        for mapping in (False, True):
            for codes in ranges:
                for offset in range(0, len(codes), 256):
                    wanted = b''
                    for code in codes[offset:offset + 256]:
                        value = encode(expected(code, mapping, table))
                        wanted += value
                        identity.update(bytes([mapping]) + code.to_bytes(4, 'big') + value)
                        count += 1
                    actual = output.readline().rstrip(b'\n')
                    assert actual == wanted, ('matrix', mapping, hex(codes[offset]), actual[:60], wanted[:60])
        examples = [([], False), ([65, 223, 8490, 962], False), ([304, 944, 13254], False),
                    ([0, 65, 173, 9, 223, 65024], True), ([0, 65, 173, 9, 223, 65024], False),
                    ([65, 55296, 66], True), ([65, 0xffffffff, 66], False), ([5024, 7312, 119808], False)]
        for codes, mapping in examples:
            parts = [expected(code, mapping, table) for code in codes]
            values = None if any(v is None for v in parts) else [c for part in parts for c in part]
            assert output.readline().rstrip(b'\n') == encode(values), ('list', codes, mapping)
        assert output.read(1) == b'', 'unexpected trailing output'
    report = {'binary': binary, 'unicode_version': '3.2.0', 'published_mapping_vectors': len(table),
              'scalar_mapping_checks': count, 'code_points_per_mode': count // 2,
              'whole_list_cases': len(examples), 'corpus_sha256': identity.hexdigest(),
              'oracle': 'published RFC 3454 B.2 plus independent Unicode 3.2 literal-profile oracle',
              'NFKC_complete_stringprep_or_Name_comparison': False}
    if args.report:
        args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
