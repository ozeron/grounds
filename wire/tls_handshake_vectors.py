"""Extract and independently verify RFC 8448 transcript/KDF fixtures, offline.

This is a test oracle, never a production TLS implementation. It validates the
published bytes before a Bend handshake evaluator consumes them.
"""
import argparse
import hashlib
import hmac
import json
from pathlib import Path
import re

SOURCE = 'https://www.rfc-editor.org/rfc/rfc8448.txt'
SOURCE_SHA256 = '6564d1376d1ec744fc7a9993da15ebc1b9be361908b166091f47ef605c537fba'
HRR_RANDOM = bytes.fromhex('cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c')
FIELD = re.compile(r'^      ([\w ]+) \((\d+) octets\):\s*(.*)$')
HEX = re.compile(r'(?:[0-9a-f]{2})(?: [0-9a-f]{2})*')


def digest(value):
    return hashlib.sha256(value).digest()


def mac(key, value):
    return hmac.digest(key, value, 'sha256')


def expand(prk, info, size):
    result, block = b'', b''
    for counter in range(1, (size + 31) // 32 + 1):
        block = mac(prk, block + info + bytes([counter]))
        result += block
    return result[:size]


def fields(lines):
    """Consume exactly the declared byte count, across RFC page headers."""
    result = {}
    for index, line in enumerate(lines):
        match = FIELD.fullmatch(line)
        if not match:
            continue
        name, size, first = match.groups()
        size = int(size)
        value = bytearray()
        if size:
            assert HEX.fullmatch(first), (name, first)
            value.extend(bytes.fromhex(first))
            for following in lines[index + 1:]:
                if len(value) >= size:
                    break
                stripped = following.strip()
                if following.startswith('         ') and HEX.fullmatch(stripped):
                    value.extend(bytes.fromhex(stripped))
                elif FIELD.fullmatch(following):
                    raise ValueError(f'truncated {name}')
        else:
            assert first == '(empty)', (name, first)
        assert len(value) == size, (name, size, len(value))
        assert name not in result, name
        result[name] = value.hex()
    return result


def extract(source):
    raw = source.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == SOURCE_SHA256, 'source identity mismatch'
    lines = raw.decode().splitlines()
    traces = []
    for section in (3, 5):
        start = next(i for i, line in enumerate(lines) if line.startswith(f'{section}.  '))
        stop = next(i for i, line in enumerate(lines) if line.startswith(f'{section + 1}.  '))
        starts = [i for i in range(start, stop) if re.match(r'^   \{(?:client|server)\}', lines[i])]
        operations = []
        for index, begin in enumerate(starts):
            end = starts[index + 1] if index + 1 < len(starts) else stop
            heading = lines[begin].strip()
            # Repeated client-side references have no literal fields to extract.
            literal = fields(lines[begin + 1:end])
            if not literal:
                continue
            if any(verb in heading for verb in ('construct ', 'extract secret', 'derive secret', 'calculate finished')):
                operations.append({'line': begin + 1, 'operation': heading, 'fields': literal})
        traces.append({'section': section, 'operations': operations})
    return {'source': SOURCE, 'source_sha256': SOURCE_SHA256,
            'scope': 'Published transcript, extract/derive and Finished bytes in sections 3 and 5; not certificate acceptance or live TLS',
            'traces': traces}


def verify(data):
    counts = {'messages': 0, 'extracts': 0, 'expands': 0, 'transcript_hashes': 0, 'finished': 0, 'retry_rewrites': 0}
    for trace in data['traces']:
        transcript = b''
        for row in trace['operations']:
            operation = row['operation']
            values = {key: bytes.fromhex(value) for key, value in row['fields'].items()}
            if 'construct ' in operation:
                assert len(values) == 1
                message = next(iter(values.values()))
                assert len(message) >= 4 and int.from_bytes(message[1:4], 'big') == len(message) - 4
                if message[0] == 2 and message[6:38] == HRR_RANDOM:
                    # Hash ClientHello1 into the synthetic message_hash message.
                    assert transcript[0] == 1 and len(transcript) == int.from_bytes(transcript[1:4], 'big') + 4
                    transcript = b'\xfe\x00\x00\x20' + digest(transcript)
                    counts['retry_rewrites'] += 1
                transcript += message
                counts['messages'] += 1
            elif 'extract secret' in operation:
                salt = values.get('salt', bytes(32))
                assert mac(salt, values['IKM']) == values['secret'], row['line']
                counts['extracts'] += 1
            elif 'derive secret' in operation or 'calculate finished' in operation:
                info = values['info']
                size, label_size = int.from_bytes(info[:2], 'big'), info[2]
                label = info[3:3 + label_size]
                context = info[4 + label_size:]
                assert label.startswith(b'tls13 ')
                assert info[3 + label_size] == len(context)
                assert context == values['hash']
                assert expand(values['PRK'], info, size) == values['expanded'], row['line']
                counts['expands'] += 1
                if 'calculate finished' in operation:
                    assert label == b'tls13 finished' and context == b''
                    assert mac(values['expanded'], digest(transcript)) == values['finished'], row['line']
                    counts['finished'] += 1
                else:
                    expected = digest(b'') if label == b'tls13 derived' else digest(transcript)
                    assert context == expected, (row['line'], label.decode())
                    counts['transcript_hashes'] += 1
    assert counts == {'messages': 17, 'extracts': 6, 'expands': 22,
                      'transcript_hashes': 18, 'finished': 4, 'retry_rewrites': 1}, counts
    return counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, help='Exact downloaded RFC 8448 text; requires --output')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--check', type=Path, help='Verify committed JSON without networking')
    args = parser.parse_args()
    if args.source is not None:
        if args.output is None or args.check is not None:
            parser.error('--source requires --output and excludes --check')
        data = extract(args.source)
        counts = verify(data)
        args.output.write_text(json.dumps(data, indent=2) + '\n')
    else:
        if args.check is None or args.output is not None:
            parser.error('use --source/--output or --check')
        data = json.loads(args.check.read_text())
        assert data['source'] == SOURCE and data['source_sha256'] == SOURCE_SHA256
        counts = verify(data)
    print(json.dumps({'scope': 'oracle fixtures only; no Bend execution', 'checks': counts}, sort_keys=True))


if __name__ == '__main__':
    main()
