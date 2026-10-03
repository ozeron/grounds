"""Independent extension dispatch/policy and whole-certificate regressions."""
import argparse
from collections import Counter
import hashlib
import itertools
import json
from pathlib import Path
import subprocess
import tempfile

import x509_algorithm_check as A
import x509_certificate_check as C
import x509_constraints_check as B
import x509_extensions_check as E
import x509_eku_check as K

ROOT = Path(__file__).parent
BC, KU, EKU = (bytes.fromhex(value) for value in ('551d13', '551d0f', '551d25'))


def basic(data):
    fields = C.elements(A.complete(data, 48))
    if not fields:
        return False, None
    if fields[0][2] != b'\x01\x01\xff' or len(fields) > 2:
        raise ValueError('CA boolean/order')
    if len(fields) == 1:
        return True, None
    raw = A.complete(fields[1][2], 2)
    if not raw or raw[0] & 128 or len(raw) > 1 and raw[0] == 0 and raw[1] < 128:
        raise ValueError('positive canonical integer')
    return True, int.from_bytes(raw, 'big')


def usage(data):
    raw = A.complete(data, 3)
    if len(raw) < 2 or raw[0] > 7:
        raise ValueError('bit string')
    text = ''.join(f'{byte:08b}' for byte in raw[1:])
    used = len(text)-raw[0]
    if not 1 <= used <= 9 or text[used:] != '0' * raw[0] or text[used-1] != '1':
        raise ValueError('named bits/canonical padding')
    return sum(1 << i for i, bit in enumerate(text[:used]) if bit == '1')


def oracle(data):
    if data is None:
        return 'absent|absent|'
    try:
        # Validate all OIDs, envelopes and duplicates independently before
        # dispatch; C.elements is a byte-offset Python framing oracle.
        E.extensions(data)
        recognized, opaque = {}, []
        ca, limit, mask = False, None, None
        for _, body, _ in C.elements(A.complete(data, 48)):
            fields = C.elements(body)
            oid = fields[0][1]
            critical = len(fields) == 3
            payload = fields[-1][1]
            if oid == BC:
                ca, limit = basic(payload)
                recognized[BC] = f'{str(critical).lower()}:{payload.hex()}'
            elif oid == KU:
                mask = usage(payload)
                recognized[KU] = f'{str(critical).lower()}:{payload.hex()}'
            elif oid == EKU:
                K.decode(payload)
                opaque.append(f'{oid.hex()}:{"critical:" if critical else ""}{payload.hex()};')
            elif critical:
                raise ValueError('unsupported critical')
            else:
                opaque.append(f'{oid.hex()}:{payload.hex()};')
        if mask is not None and not B.policy(ca, limit, mask):
            raise ValueError('cross-field policy')
        return '|'.join([recognized.get(BC, 'absent'), recognized.get(KU, 'absent'), ''.join(opaque)])
    except (ValueError, IndexError):
        return 'none'


def certificate(data):
    try:
        return oracle(C.parse(data)['extensions'])
    except (ValueError, IndexError):
        return 'none'


def extension(oid, payload, critical=False):
    return E.extension(oid, payload, b'\xff' if critical else None)


def tls_oracle(mode, data, role, allow_any):
    try:
        if mode == '4':
            data = C.parse(data)['extensions']
        if oracle(data) == 'none':
            return 'false'
        payloads = {}
        if data is not None:
            for _, body, _ in C.elements(A.complete(data, 48)):
                fields = C.elements(body)
                payloads[fields[0][1]] = fields[-1][1]
        return str(K.tls(payloads.get(KU), payloads.get(EKU), role == '1', allow_any == '1')).lower()
    except (ValueError, IndexError):
        return 'false'


def cases():
    def add(group, mode, data, expected=None):
        operation, *flags = mode.split('/')
        actual = (tls_oracle(operation, data, *flags) if flags else
                  certificate(data) if mode == '1' else oracle(data))
        if expected is not None:
            assert actual == expected, (group, actual, expected)
        return group, mode, data, actual
    yield add('absent', '2', None, 'absent|absent|')
    for critical in (False, True):
        for ca, limit in [(False, None), (True, None), (True, 0), (True, 2**128)]:
            for mask in range(1, 512):
                pair = [extension(BC, B.basic(ca, limit), critical), extension(KU, B.usage(mask), not critical)]
                for items in (pair, list(reversed(pair))):
                    yield add('all-bits-criticality-order-policy', '0', A.tlv(48, b''.join(items)))
    # Replay every payload-admission case against recognized OIDs in both
    # critical forms; none can bypass validation by being noncritical.
    for group, mode, values, _ in B.cases():
        if mode in ('0', '1'):
            oid = BC if mode == '0' else KU
            for critical in (False, True):
                yield add('recognized-payload-'+group, '0', A.tlv(48, extension(oid, values[0], critical)))
    unknowns = [b'\x55\x1d\x11', b'\x55\x1d\x25', b'\x2a\x03',
                b'\x55\x1d\x13\x00', b'\x55\x1d\x0f\x01']
    for oid in unknowns:
        for value in (b'', b'\x00', b'\x30\x00', bytes(range(256))):
            yield add('unsupported-critical', '0', A.tlv(48, extension(oid, value, True)), 'none')
            yield add('opaque-noncritical', '0', A.tlv(48, extension(oid, value)),
                      'none' if oid == EKU else f'absent|absent|{oid.hex()}:{value.hex()};')
    known = extension(BC, B.basic(True), True)
    opaque = [extension(oid, bytes([i])) for i, oid in enumerate(unknowns)]
    for permutation in itertools.permutations(opaque[:3]+[known]):
        yield add('deferred-exact-order', '0', A.tlv(48, b''.join(permutation)))
    for entry in [known, extension(KU, B.usage(1)), opaque[0]]:
        yield add('duplicate-identity', '0', A.tlv(48, entry+entry), 'none')
    for malformed in (b'', b'\x30\x00', b'\x30\x80\x00\x00',
                      A.tlv(48, E.extension(BC, B.basic(True), b'\x00')),
                      A.tlv(48, extension(b'\x80\x00', b'')), A.tlv(48, known)+b'\x00'):
        yield add('envelope-malformed', '0', malformed, 'none')
    peers = json.loads((ROOT/'x509_algorithm_vectors.json').read_text())['peers']
    for peer in peers:
        data = bytes.fromhex(peer['certificate_der'])
        yield add('OpenSSL-complete-certificate', '1', data)
    records = json.loads((ROOT/'x509_signature_vectors.json').read_text())['records']
    for peer in records:
        signed = bytes.fromhex(peer['certificate_der'])
        yield add('signed-unsupported-critical', '1', signed, 'none')
        outer = C.elements(A.complete(signed, 48))
        fields = C.elements(outer[0][1])
        changed, replaced = [], 0
        for tag, body, encoded in fields:
            if tag == 163:
                entries = []
                for _, inner, _ in C.elements(A.complete(body, 48)):
                    parts = C.elements(inner)
                    identifier, payload = parts[0][1], parts[-1][1]
                    critical = len(parts) == 3
                    if critical and identifier not in (BC, KU, EKU):
                        critical = False
                        replaced += 1
                    entries.append(extension(identifier, payload, critical))
                encoded = A.tlv(163, A.tlv(48, b''.join(entries)))
            changed.append(encoded)
        assert replaced > 0
        control = C.assemble(A.tlv(48, b''.join(changed)), outer[1][2], outer[2][1][1:])
        assert certificate(control) != 'none'
        yield add('critical-flag-only-control', '1', control)
    source = bytes.fromhex(peers[0]['certificate_der'])
    outer = C.elements(A.complete(source, 48))
    fields = C.elements(outer[0][1])
    mandatory = [item[2] for item in fields[1:7]]
    for version in (0, 1, 2):
        for payload in (None, A.tlv(48, known), A.tlv(48, extension(BC, B.basic(False))+extension(KU, B.usage(32)))):
            prefix = b'' if version == 0 else A.tlv(160, A.tlv(2, bytes([version])))
            tbs = A.tlv(48, prefix+b''.join(mandatory)+(A.tlv(163, payload) if payload else b''))
            yield add('certificate-version-extraction-policy', '1', C.assemble(tbs, outer[1][2]))
    for cut in range(len(source)):
        yield add('certificate-every-truncation', '1', source[:cut], 'none')
    for total in (4096, 65535, 65536):
        # Find exact input boundaries without changing the payload or skipping
        # a case merely because it is too large for the generated runtime.
        for length in range(total-20, total):
            data = A.tlv(48, extension(b'\x2a\x03', bytes(length)))
            if len(data) == total:
                yield add('exact-input-bound', '0', data)
                break
        else:
            raise AssertionError(total)
    # Keep the historical invalid opaque-EKU cases above. Add canonical EKU
    # processing in both critical forms and independently exercise purpose use.
    for group, mode, values, _, expected in K.cases():
        if mode == '0':
            for critical in (False, True):
                data = A.tlv(48, extension(EKU, values[0], critical))
                yield add('EKU-payload-'+group, '0', data,
                          'none' if expected == 'none' or len(data) > 65535 else None)
    good = extension(EKU, K.encoded([K.SERVER]), True)
    for permutation in itertools.permutations([good, known, opaque[0], opaque[2]]):
        yield add('validated-EKU-deferred-order', '0', A.tlv(48, b''.join(permutation)))
    yield add('duplicate-EKU-extension', '0', A.tlv(48, good+good), 'none')
    payloads = [None, K.encoded([K.SERVER]), K.encoded([K.CLIENT]), K.encoded([K.ANY]),
                K.encoded([K.SERVER, K.CLIENT]), K.encoded([K.SERVER+b'\x00']),
                K.encoded([]), A.tlv(48, A.tlv(6, K.SERVER)+A.tlv(6, b'\x81'))]
    for mask in (None, 1, 2, 4, 8, 16, 32, 64, 128, 256, 5, 17, 129, 257, 511):
        for eku in payloads:
            for critical in (False, True):
                entries = [extension(BC, B.basic(False), True)]
                if mask is not None:
                    entries.append(extension(KU, B.usage(mask), critical))
                if eku is not None:
                    entries.append(extension(EKU, eku, critical))
                data = A.tlv(48, b''.join(entries))
                for role, any_flag in itertools.product(('0', '1'), repeat=2):
                    yield add('TLS-extension-KU-EKU-policy', f'3/{role}/{any_flag}', data)
    for data, role, any_flag, expected in (
            (A.tlv(48, extension(EKU, K.encoded([K.SERVER]), True)), '1', '0', 'true'),
            (A.tlv(48, extension(EKU, K.encoded([K.SERVER]), True)), '0', '0', 'false'),
            (A.tlv(48, extension(EKU, K.encoded([K.ANY]), True)), '1', '0', 'false'),
            (A.tlv(48, extension(EKU, K.encoded([K.ANY]), True)), '1', '1', 'true'),
            (A.tlv(48, good+extension(b'\x2a\x03', b'', True)), '1', '0', 'false'),
            (A.tlv(48, good+extension(KU, B.usage(4))), '1', '0', 'false')):
        yield add('literal-TLS-extension-permission', f'3/{role}/{any_flag}', data, expected)
    for eku in payloads:
        for mask in (None, 1, 4, 32, 257):
            entries = [extension(BC, B.basic(False), True)]
            if eku is not None:
                entries.append(extension(EKU, eku, True))
            if mask is not None:
                entries.append(extension(KU, B.usage(mask)))
            tbs = A.tlv(48, A.tlv(160, A.tlv(2, b'\x02'))+b''.join(mandatory)+A.tlv(163, A.tlv(48, b''.join(entries))))
            data = C.assemble(tbs, outer[1][2])
            for role, any_flag in itertools.product(('0', '1'), repeat=2):
                yield add('TLS-certificate-payload-policy', f'4/{role}/{any_flag}', data)
    for peer in peers:
        data = bytes.fromhex(peer['certificate_der'])
        for role, any_flag in itertools.product(('0', '1'), repeat=2):
            yield add('OpenSSL-certificate-TLS-purpose', f'4/{role}/{any_flag}', data)
        yield add('malformed-certificate-TLS-purpose', '4/1/0', data[:-1], 'false')
    tbs = A.tlv(48, b''.join(mandatory))
    yield add('certificate-absent-KU-EKU-permitted', '4/1/0', C.assemble(tbs, outer[1][2]), 'true')
    for peer in json.loads((ROOT/'x509_eku_vectors.json').read_text())['records']:
        data = bytes.fromhex(peer['certificate_der'])
        assert certificate(data) != 'none', peer['name']
        yield add('signed-OpenSSL-EKU-metadata', '1', data)
        for role, expected in (('1', peer['tls13_strict_server']), ('0', peer['tls13_strict_client'])):
            yield add('signed-OpenSSL-EKU-TLS13-purpose', f'4/{role}/0', data, str(expected).lower())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path)
    parser.add_argument('--signature-binary', type=Path)
    parser.add_argument('--bun', action='store_true')
    parser.add_argument('binary', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    binary = args.binary[1:] if args.binary[:1] == ['--'] else args.binary
    if not binary:
        parser.error('supply evaluator command')
    counts, identity = Counter(), hashlib.sha256()
    with tempfile.TemporaryDirectory(prefix='grounds-extension-policy-') as directory:
        root = Path(directory)
        batch, controls = [], []
        def evaluate(rows):
            command = binary + ['check']
            for i, (group, mode, data, expected) in enumerate(rows):
                operation, *flags = mode.split('/')
                command.append(operation)
                if data is not None:
                    path = root / f'{i}.der'
                    path.write_bytes(data)
                    command.append(str(path))
                command.extend(flags)
                identity.update(json.dumps([group, mode, data.hex() if data is not None else None, expected]).encode())
            result = subprocess.run(command, capture_output=True, text=True, timeout=25)
            assert result.returncode == 0, (sum(counts.values()), result.returncode, result.stderr)
            actual = result.stdout.splitlines()
            assert actual == [row[3] for row in rows], (sum(counts.values()), [r[:2] for r in rows], actual, [r[3] for r in rows])
            counts.update(row[0] for row in rows)
        for row in cases():
            if row[0] == 'critical-flag-only-control':
                controls.append(row[2])
            if len(batch) == 32 or row[2] is not None and len(row[2]) > 4096:
                if batch:
                    evaluate(batch)
                    batch = []
            if row[2] is not None and len(row[2]) > 4096:
                evaluate([row])
            else:
                batch.append(row)
        if batch:
            evaluate(batch)
        signature_cases, changed_signature_cases, eku_signature_cases = 0, 0, 0
        if args.signature_binary:
            for i, peer in enumerate(json.loads((ROOT/'x509_signature_vectors.json').read_text())['records']):
                key, cert = root/f'issuer-{i}.der', root/f'signed-{i}.der'
                key.write_bytes(bytes.fromhex(peer['issuer_spki']))
                cert.write_bytes(bytes.fromhex(peer['certificate_der']))
                command = (['bun'] if args.bun else []) + [str(args.signature_binary), 'verify', str(key), str(cert)]
                result = subprocess.run(command, capture_output=True, text=True, timeout=25)
                assert result.returncode == 0 and result.stdout.strip() == 'true', (i, result.stderr, result.stdout)
                assert certificate(cert.read_bytes()) == 'none'
                signature_cases += 1
                control = root/f'control-{i}.der'
                control.write_bytes(controls[i])
                command[-1] = str(control)
                result = subprocess.run(command, capture_output=True, text=True, timeout=25)
                assert result.returncode == 0 and result.stdout.strip() == 'false', (i, result.stderr, result.stdout)
                changed_signature_cases += 1
            for i, peer in enumerate(json.loads((ROOT/'x509_eku_vectors.json').read_text())['records']):
                key, cert = root/f'eku-key-{i}.der', root/f'eku-cert-{i}.der'
                key.write_bytes(bytes.fromhex(peer['issuer_spki']))
                cert.write_bytes(bytes.fromhex(peer['certificate_der']))
                command = (['bun'] if args.bun else []) + [str(args.signature_binary), 'verify', str(key), str(cert)]
                result = subprocess.run(command, capture_output=True, text=True, timeout=25)
                assert result.returncode == 0 and result.stdout.strip() == 'true', (peer['name'], result.stderr, result.stdout)
                eku_signature_cases += 1
    report = {'binary': binary, 'total': sum(counts.values()), 'cases': dict(counts),
              'corpus_sha256': identity.hexdigest(), 'valid_Bend_signatures_rejected_by_policy': signature_cases,
              'changed_criticality_controls_rejected_by_Bend_signature': changed_signature_cases,
              'signed_EKU_fixtures_verified_by_Bend': eku_signature_cases,
              'chain_trust_hostname_or_complete_certificate_authorization': False}
    if args.report:
        args.report.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
