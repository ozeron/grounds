"""Generate the RFC 3454 B.2 mapping from a SHA-pinned official snapshot."""
import argparse
import hashlib
import json
import re
from pathlib import Path

SOURCE_SHA256 = 'eb722fa698fb7e8823b835d9fd263e4cdb8f1c7b0d234edf7f0e3bd2ccbb2c79'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--output-dir', type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args()
    raw = args.source.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == SOURCE_SHA256
    section = raw.decode().split('----- Start Table B.2 -----')[1].split('----- End Table B.2 -----')[0]
    rows = [(int(code, 16), [int(v, 16) for v in mapped.split()])
            for code, mapped in re.findall(r'^\s*([0-9A-F]+); ([0-9A-F ]+);', section, re.M)]
    assert len(rows) == 1371 and all(rows[i][0] < rows[i + 1][0] for i in range(len(rows) - 1))
    assert max(len(mapped) for _, mapped in rows) == 4
    index, values = [], []
    for code, mapped in rows:
        index.extend((code, len(values) * 8 + len(mapped)))
        values.extend(mapped)
    assert len(index) <= 4096 and len(values) <= 2048
    text = 'import Base\n\n# Generated RFC 3454 B.2; unicode32_fold_data.json records provenance.\n'
    text += '# Nat literals keep pinned frontend data compact; chunks bound JS expression depth.\n'
    text += '\ndef append(xs: List<&2, Nat>, ys: List<&2, Nat>) -> List<&2, Nat>:\n  List.reverse.go(&2, Nat, List.reverse(&2, Nat, xs), ys)\n'
    for name, data in [('index', index), ('values', values)]:
        chunks = [data[i:i + 128] for i in range(0, len(data), 128)]
        for part, chunk in enumerate(chunks):
            text += f'\ndef {name}.part{part}() -> List<&2, Nat>:\n  ['
            text += ',\n   '.join(', '.join(str(v) + 'n' for v in chunk[i:i + 12]) for i in range(0, len(chunk), 12)) + ']\n'
        expression = '[]'
        for part in reversed(range(len(chunks))):
            expression = f'append({name}.part{part}(), {expression})'
        text += f'\ndef {name}() -> List<&2, Nat>:\n  {expression}\n'
    (args.output_dir / 'unicode32_fold_data.bend').write_text(text)
    vectors = '{\n  "source_sha256": "' + SOURCE_SHA256 + '",\n  "table": "RFC 3454 B.2",\n  "mappings": [\n'
    vectors += ',\n'.join('    ' + json.dumps([f'{code:04X}', [f'{v:04X}' for v in mapped]]) for code, mapped in rows) + '\n  ]\n}\n'
    (args.output_dir / 'unicode32_fold_vectors.json').write_text(vectors)
    manifest = {'unicode_version': '3.2.0', 'source': 'https://www.rfc-editor.org/rfc/rfc3454.txt',
                'source_sha256': SOURCE_SHA256, 'mapping_count': len(rows), 'value_count': len(values),
                'maximum_expansion': 4, 'descriptor': '8 * values offset + length',
                'generated_bend_sha256': hashlib.sha256(text.encode()).hexdigest(),
                'published_vectors_sha256': hashlib.sha256(vectors.encode()).hexdigest()}
    (args.output_dir / 'unicode32_fold_data.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(manifest))


if __name__ == '__main__':
    main()
