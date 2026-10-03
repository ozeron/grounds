"""Independent selected SAN payload and empty-subject binding checks."""
import argparse
from collections import Counter
import hashlib
import itertools
import json
from pathlib import Path
import re
import subprocess
import tempfile

import x509_algorithm_check as A
import x509_certificate_check as C
import x509_extensions_check as E
import x509_hostname_check as H

SAN = bytes.fromhex('551d11')
LABEL = re.compile(rb'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?')


def inspect(data):
    try:
        names = H.frame(data)
        supported = True
        for tag, body, _ in names:
            if tag == 130:
                domain = body[2:] if body.startswith(b'*.') else body
                if len(body) > 253 or not all(LABEL.fullmatch(label) for label in domain.split(b'.')):
                    return 'none'
            elif tag != 135:
                supported = False
        return 'supported' if supported else 'deferred'
    except (ValueError, IndexError):
        return 'none'


def subject(data, extensions):
    try:
        empty = not A.complete(data, 48)
        if extensions is None:
            return not empty
        E.extensions(extensions)
        for _, body, _ in C.elements(A.complete(extensions, 48)):
            fields = C.elements(body)
            if fields[0][1] == SAN:
                critical = len(fields) == 3
                status = inspect(fields[-1][1])
                return (not empty or critical) and status != 'none' and (not critical or status == 'supported')
        return not empty
    except (ValueError, IndexError):
        return False


def cases():
    def add(group, mode, data, extensions=None, expected=None):
        actual = inspect(data) if mode == '0' else str(subject(data, extensions)).lower()
        if expected is not None:
            assert actual == expected, (group, actual, expected)
        return group, mode, data, extensions, actual
    def san(*names):
        return A.tlv(48, b''.join(A.tlv(tag, body) for tag, body in names))
    good = (130, b'api.example.test')
    for name, expected in [(b'api.example.test', 'supported'), (b'*.example.test', 'supported'),
                           (b'*', 'none'), (b'api*.test', 'none'), (b'*.*.test', 'none'),
                           (b'bad_name.test', 'none'), (b'api.test.', 'none'), (b' ', 'none'),
                           (b'xn--bcher-kva.test', 'supported')]:
        yield add('literal-DNS-policy', '0', san((130, name)), expected=expected)
    for byte in range(256):
        for data in (bytes([byte])+b'.test', b'a'+bytes([byte])+b'b.test'):
            yield add('every-DNS-octet', '0', san((130, data)))
        for tag in (129, 134):
            yield add('deferred-IA5-framing', '0', san(good, (tag, bytes([byte]))))
        yield add('every-GeneralName-tag', '0', san(good, (byte, b'a')))
    for size in range(72):
        yield add('label-length-and-endpoints', '0', san((130, b'a'*size+b'.test')))
        yield add('wildcard-label-length', '0', san((130, b'*.'+b'a'*size+b'.test')))
    for size in range(22):
        yield add('IP-exact-family-widths', '0', san(good, (135, bytes(size))))
    for names in itertools.permutations([good, (134, b'https://api.test'), (130, b'bad_name.test')]):
        yield add('later-invalid-DNS-cannot-hide', '0', san(*names), expected='none')
    for tag in (160, 163, 164, 165, 136):
        yield add('unprocessed-forms-explicitly-deferred', '0', san(good, (tag, b'\x2a')), expected='deferred')
    data = san(good, (135, bytes.fromhex('c0000201')))
    for cut in range(len(data)):
        yield add('every-payload-truncation', '0', data[:cut], expected='none')
    for index in range(len(data)):
        for bit in range(8):
            changed = bytearray(data); changed[index] ^= 1 << bit
            yield add('every-payload-bit-mutation', '0', bytes(changed))
    for count in (128, 1024, 8192):
        yield add('many-names-tail-walk', '0', san(*([(130, b'a')] * count)), expected='supported')
    for data in (b'', b'\x30\x00', b'\x30\x80\x00\x00', data+b'\x00', A.tlv(49, A.tlv(*good))):
        yield add('malformed-payload', '0', data, expected='none')
    payloads = [san(good), san((135, bytes(4))), san(good, (134, b'https://api.test')),
                san((130, b'bad_name.test')), b'\x30\x00', b'']
    for subj in (b'\x30\x00', b'\x30\x02\x30\x00', b'', b'\x30\x00\x00'):
        yield add('absent-SAN-empty-subject-rule', '1', subj)
        for payload in payloads:
            for critical in (False, True):
                extension = E.extension(SAN, payload, b'\xff' if critical else None)
                for entries in (extension, extension+extension):
                    yield add('subject-criticality-supported-deferred-and-duplicate', '1', subj, A.tlv(48, entries))
        for ext in (b'', b'\x30\x00', A.tlv(48, E.extension(b'\x2a\x03', b'x'))):
            yield add('subject-envelope-or-absent-SAN', '1', subj, ext)
    root = Path(__file__).parent
    for peer in json.loads((root/'x509_hostname_vectors.json').read_text())['records']:
        parsed = C.parse(bytes.fromhex(peer['certificate_der']))
        yield add('signed-certificate-extracted-subject-and-SAN', '1', parsed['subject'], parsed['extensions'])
    for peer in json.loads((root/'x509_san_vectors.json').read_text())['records']:
        parsed = C.parse(bytes.fromhex(peer['certificate_der']))
        yield add('signed-empty-subject-strict-OpenSSL-reference', '1', parsed['subject'], parsed['extensions'],
                  str(peer['selected_policy_accepts']).lower())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path)
    parser.add_argument('binary', nargs=argparse.REMAINDER)
    args = parser.parse_args(); binary = args.binary[1:] if args.binary[:1] == ['--'] else args.binary
    if not binary: parser.error('supply evaluator')
    counts, identity = Counter(), hashlib.sha256()
    with tempfile.TemporaryDirectory(prefix='grounds-san-') as directory:
        root = Path(directory)
        def evaluate(rows):
            command = binary+['check']
            for index, row in enumerate(rows):
                group, mode, data, extensions, expected = row
                path = root/f'{index}.der'; path.write_bytes(data); command += [mode, str(path)]
                if mode == '1':
                    if extensions is None: command.append('-')
                    else:
                        ext = root/f'{index}-extensions.der'; ext.write_bytes(extensions); command.append(str(ext))
                identity.update(json.dumps([group, mode, data.hex(), None if extensions is None else extensions.hex(), expected]).encode())
            result = subprocess.run(command, capture_output=True, text=True, timeout=25)
            assert result.returncode == 0, (result.returncode, result.stderr)
            assert result.stdout.splitlines() == [r[4] for r in rows], (sum(counts.values()), result.stdout, [r[4] for r in rows])
            counts.update(r[0] for r in rows)
        batch = []
        for row in cases():
            large = len(row[2]) > 4096
            if len(batch) == 32 or large:
                if batch: evaluate(batch); batch = []
            if large: evaluate([row])
            else: batch.append(row)
        if batch: evaluate(batch)
    report = {'total': sum(counts.values()), 'groups': dict(counts), 'corpus_sha256': identity.hexdigest(),
              'binary': binary, 'other_GeneralName_forms_processed': False,
              'Name_schema_chain_trust_time_signature_or_complete_authorization': False}
    if args.report: args.report.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__': main()
