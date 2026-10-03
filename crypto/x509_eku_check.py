"""Independent DER EKU and TLS 1.3 KU/purpose permission regressions."""
import argparse
from collections import Counter
import hashlib
import itertools
import json
from pathlib import Path
import random
import subprocess
import sys
import tempfile

import x509_algorithm_check as A
import x509_certificate_check as C
import x509_constraints_check as B
import x509_extensions_check as E

SERVER = bytes.fromhex('2b06010505070301')
CLIENT = bytes.fromhex('2b06010505070302')
ANY = bytes.fromhex('551d2500')
ROOT = Path(__file__).parent


def encoded(items):
    return A.tlv(48, b''.join(A.tlv(6, item) for item in items))


def decode(data):
    if len(data) > 65535:
        raise ValueError('input limit')
    fields = C.elements(A.complete(data, 48))
    if not fields:
        raise ValueError('empty EKU')
    return [E.oid(item[2]) for item in fields]


def permits(data, purpose, allow_any):
    try:
        if len(purpose) > 65535:
            return False
        E.oid_contents(purpose)
        if data is None:
            return True
        items = decode(data)
        return purpose in items or allow_any and ANY in items
    except (ValueError, IndexError):
        return False


def tls(usage, eku, server, allow_any):
    # Parse BIT STRING by numeric bit positions, independently from Bend's
    # octet-oriented Usage mask; bit 0 is digitalSignature.
    try:
        if usage is not None:
            raw = A.complete(usage, 3)
            if len(raw) < 2 or raw[0] > 7:
                return False
            bits = ''.join(f'{byte:08b}' for byte in raw[1:])
            used = len(bits)-raw[0]
            if not 1 <= used <= 9 or bits[used:] != '0'*raw[0] or bits[used-1] != '1':
                return False
            if bits[0] != '1':
                return False
        return permits(eku, SERVER if server else CLIENT, allow_any)
    except (ValueError, IndexError):
        return False


def oracle(mode, values, flags):
    if mode == '0':
        try:
            return ''.join(item.hex()+';' for item in decode(values[0]))
        except (ValueError, IndexError):
            return 'none'
    if mode == '1':
        return str(permits(*values, flags[0] == '1')).lower()
    return str(tls(*values, flags[0] == '1', flags[1] == '1')).lower()


def cases():
    def add(group, mode, values, flags=(), expected=None):
        actual = oracle(mode, values, flags)
        if expected is not None:
            assert actual == expected, (group, actual, expected)
        return group, mode, values, flags, actual
    for first in range(256):
        yield add('every-one-octet-purpose', '0', [encoded([bytes([first])])])
        for second in (0, 127, 128, 255):
            yield add('two-octet-purpose-boundaries', '0', [encoded([bytes([first, second])])])
    rng = random.Random(5280)
    for _ in range(128):
        oid = b''.join(E.base128(rng.getrandbits(rng.randrange(1, 1025))) for _ in range(rng.randrange(1, 5)))
        yield add('arbitrary-size-arcs', '0', [encoded([oid])], expected=oid.hex()+';')
        yield add('nonminimal-large-arc', '0', [encoded([b'\x80'+oid])], expected='none')
        yield add('unterminated-large-arc', '0', [encoded([oid+b'\x81'])], expected='none')
    for items in ([SERVER], [CLIENT], [ANY], [SERVER, CLIENT], [ANY, SERVER],
                  [SERVER, SERVER], [b'\x2a\x03', SERVER, b'\x88\x37\x03']):
        for order in sorted(set(itertools.permutations(items))):
            data = encoded(order)
            yield add('order-duplicates-and-unknown-purposes', '0', [data], expected=''.join(x.hex()+';' for x in order))
            for purpose in (SERVER, CLIENT, b'\x2a\x03', SERVER+b'\x00', SERVER[:-1], ANY):
                for any_flag in ('0', '1'):
                    yield add('exact-purpose-and-any-policy', '1', [data, purpose], [any_flag])
    for purpose in (b'', b'\x80\x00', b'\x81', SERVER, SERVER+b'\x00'):
        for any_flag in ('0', '1'):
            yield add('absent-EKU-valid-query', '1', [None, purpose], [any_flag])
    malformed = [b'', b'\x30\x00', b'\x30\x80\x00\x00', b'\x30\x81\x00',
                 A.tlv(49, A.tlv(6, SERVER)), A.tlv(48, A.tlv(4, SERVER)),
                 A.tlv(48, A.tlv(6, b'')), A.tlv(48, A.tlv(6, b'\x80\x00')),
                 encoded([SERVER])+b'\x00',
                 A.tlv(48, A.tlv(6, SERVER)+A.tlv(6, b'\x81')),
                 A.tlv(48, A.tlv(6, SERVER)+A.tlv(4, CLIENT)),
                 A.tlv(48, A.tlv(6, SERVER)+b'\x06')]
    for data in malformed:
        yield add('malformed-full-list', '0', [data], expected='none')
        for any_flag in ('0', '1'):
            yield add('match-cannot-hide-later-error', '1', [data, SERVER], [any_flag], 'false')
    good = encoded([SERVER, CLIENT, ANY])
    for cut in range(len(good)):
        yield add('every-EKU-truncation', '0', [good[:cut]], expected='none')
    for index in range(len(good)):
        for bit in range(8):
            mutated = bytearray(good); mutated[index] ^= 1 << bit
            yield add('every-EKU-bit-mutation', '0', [bytes(mutated)])
    payloads = [None, encoded([SERVER]), encoded([CLIENT]), encoded([ANY]), encoded([SERVER, CLIENT]), encoded([])]
    for mask in range(1, 512):
        for eku in payloads:
            for role, any_flag in itertools.product(('0', '1'), repeat=2):
                yield add('all-KU-bits-TLS-purpose-intersection', '2', [B.usage(mask), eku], [role, any_flag])
    for usage in (None, b'', b'\x03\x00', b'\x03\x02\x07\x00', b'\x03\x02\x00\x80'):
        for eku in payloads:
            for role, any_flag in itertools.product(('0', '1'), repeat=2):
                yield add('absent-or-malformed-KU', '2', [usage, eku], [role, any_flag])
    for total in (4096, 65535, 65536):
        for length in range(total-12, total):
            oid = b'\x81'*(length-1)+b'\x01'
            data = encoded([oid])
            if len(data) == total:
                yield add('exact-EKU-input-bound', '0', [data])
                yield add('exact-EKU-permission-bound', '1', [data, SERVER], ['0'], 'false')
                break
        else:
            raise AssertionError(total)
    for length in (4096, 65535, 65536):
        purpose = b'\x81'*(length-1)+b'\x01'
        yield add('exact-query-input-bound', '1', [None, purpose], ['0'], str(length <= 65535).lower())
    for count in (128, 1024, 8192):
        yield add('many-purpose-entries', '0', [encoded([b'\x2a']*count)])
    # Literal direction/policy expectations: these are independent regression
    # anchors rather than expectations derived only from the Python oracle.
    for data, purpose, any_flag, result in ((encoded([SERVER]), CLIENT, '1', 'false'),
            (encoded([CLIENT]), SERVER, '1', 'false'), (encoded([ANY]), SERVER, '0', 'false'),
            (encoded([ANY]), SERVER, '1', 'true'), (encoded([SERVER]), SERVER, '0', 'true')):
        yield add('literal-purpose-policy', '1', [data, purpose], [any_flag], result)
    yield add('literal-KU-denial', '2', [B.usage(4), encoded([SERVER])], ['1', '0'], 'false')
    yield add('literal-KU-grant', '2', [B.usage(1), encoded([SERVER])], ['1', '0'], 'true')
    for peer in json.loads((ROOT/'x509_eku_vectors.json').read_text())['records']:
        extensions = C.parse(bytes.fromhex(peer['certificate_der']))['extensions']
        E.extensions(extensions)
        payloads = {}
        for _, body, _ in C.elements(A.complete(extensions, 48)):
            fields = C.elements(body)
            payloads[fields[0][1]] = fields[-1][1]
        for role, expected in (('1', peer['tls13_strict_server']), ('0', peer['tls13_strict_client'])):
            yield add('frozen-OpenSSL-purpose-plus-TLS13-KU', '2',
                      [payloads.get(bytes.fromhex('551d0f')), payloads.get(bytes.fromhex('551d25'))],
                      [role, '0'], str(expected).lower())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path)
    parser.add_argument('binary', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    binary = args.binary[1:] if args.binary[:1] == ['--'] else args.binary
    if not binary:
        parser.error('supply evaluator command')
    counts, identity = Counter(), hashlib.sha256()
    with tempfile.TemporaryDirectory(prefix='grounds-eku-') as directory:
        root = Path(directory)
        def evaluate(rows):
            command = binary+['check']
            for i, (group, mode, values, flags, expected) in enumerate(rows):
                command.append(mode)
                for j, value in enumerate(values):
                    if value is None:
                        command.append('-')
                    else:
                        path = root/f'{i}-{j}.der'; path.write_bytes(value)
                        command.append(str(path))
                command.extend(flags)
                identity.update(json.dumps([group, mode, [v.hex() if v is not None else None for v in values], flags, expected]).encode())
            result = subprocess.run(command, capture_output=True, text=True, timeout=25)
            assert result.returncode == 0, (sum(counts.values()), result.returncode, result.stderr)
            assert result.stdout.splitlines() == [row[4] for row in rows], (sum(counts.values()), [r[:2] for r in rows], result.stdout, [r[4] for r in rows])
            counts.update(row[0] for row in rows)
        batch = []
        for row in cases():
            large = any(v is not None and len(v) > 4096 for v in row[2])
            if len(batch) == 32 or large:
                if batch:
                    evaluate(batch); batch = []
            if large:
                evaluate([row])
            else:
                batch.append(row)
        if batch:
            evaluate(batch)
    report = {'binary': binary, 'python': sys.version, 'total': sum(counts.values()), 'cases': dict(counts),
              'corpus_sha256': identity.hexdigest(), 'complete_certificate_authorization': False}
    if args.report:
        args.report.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
