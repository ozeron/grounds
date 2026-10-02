"""Whole Bend certificate signatures; independent public bigint/curve oracle."""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import time

import x509_algorithm_check as A
import x509_certificate_check as C
import x509_public_key_check as K
import rsa_signature256_check as R
import ecdsa_check as E

ROOT = Path(__file__).parent


def oracle(key, certificate):
    try:
        record = C.parse(certificate)
    except (ValueError, IndexError):
        return False
    parts = K.oracle(key).split(':')
    kind, algorithm = parts[0], record['algorithm']
    digest = hashlib.sha256(record['tbs']).digest()
    signature = record['signature']
    if kind == 'p256':
        raw = E.decode_der(signature)
        return algorithm == 'ecdsa256' and raw is not None and E.reference_verify(bytes.fromhex(parts[1]), digest, raw)
    if kind not in ('rsa', 'pss-any') and not kind.startswith('pss256-'):
        return False
    if algorithm == 'ecdsa256' or kind != 'rsa' and algorithm != 'pss256':
        return False
    return R.oracle('pss' if algorithm == 'pss256' else 'v15',
                    [bytes.fromhex(parts[1]), bytes.fromhex(parts[2]), digest, signature])


def cases():
    def add(tag, key, cert, expected=None):
        result = oracle(key, cert)
        if expected is not None:
            assert result == expected, tag
        return tag, key, cert, str(result).lower()

    peers = json.loads((ROOT/'x509_signature_vectors.json').read_text())['records']
    for peer in json.loads((ROOT/'x509_algorithm_vectors.json').read_text())['peers']:
        yield add('frozen-OpenSSL-self-signature', bytes.fromhex(peer['spki_der']), bytes.fromhex(peer['certificate_der']), True)
    for peer in peers:
        key, cert = bytes.fromhex(peer['issuer_spki']), bytes.fromhex(peer['certificate_der'])
        record = C.parse(cert)
        assert record['tbs'] == bytes.fromhex(peer['tbs_der'])
        assert record['spki'] == bytes.fromhex(peer['subject_spki'])
        assert peer['openssl_dgst_verification'] == 'Verified OK'
        yield add(peer['tag'], key, cert, True)
        yield add('subject-key-is-not-issuer', record['spki'], cert, False)
        for length in range(len(cert)):
            yield add('every-certificate-truncation', key, cert[:length], False)
        outer = C.elements(A.complete(cert, 48))
        signature = record['signature']
        for index in range(len(signature)):
            changed = bytearray(signature); changed[index] ^= 1
            yield add('every-signature-byte', key, C.assemble(record['tbs'], outer[1][2], bytes(changed)), False)
        fields = C.elements(outer[0][1])
        for index, (_, body, encoded) in enumerate(fields):
            if not body:
                continue
            for position in {0, len(body)-1}:
                changed = bytearray(body); changed[position] ^= 1
                modified = [item[2] for item in fields]
                modified[index] = A.tlv(fields[index][0], bytes(changed))
                yield add('each-TBS-field-edge', key, C.assemble(A.tlv(48, b''.join(modified)), outer[1][2], signature), False)
        for suffix in (b'\x00', b'\x05\x00', cert):
            yield add('certificate-trailing', key, cert+suffix, False)
        for malformed in (b'', b'\x30\x00', key[:-1], key+b'\x00'):
            yield add('issuer-SPKI-malformed', malformed, cert, False)
        # A different key of the same admitted type must not verify.
        other = peers[2]['subject_spki'] if peer['signature_expected'] != 'ecdsa256' else peers[0]['subject_spki']
        yield add('wrong-issuer-same-key-type', bytes.fromhex(other), cert, False)
        if peer['signature_expected'] == 'v15256':
            yield add('outer-NULL-absent-equivalence', key, C.assemble(record['tbs'], A.algorithm(A.V15), signature), True)
        if peer['signature_expected'] == 'ecdsa256':
            raw = E.decode_der(signature)
            for modified in (b'', b'\x30\x00', signature+b'\x00', b'\x30\x81'+signature[1:],
                             E.der(bytes(32)+raw[32:]), E.der(raw[:32]+bytes(32)),
                             E.der(E.N.to_bytes(32, 'big')+raw[32:])):
                yield add('ECDSA-strict-DER-range', key, C.assemble(record['tbs'], outer[1][2], modified), False)
        for modified in (b'', signature[:-1], b'\x00'+signature, signature+b'\x00'):
            yield add('signature-width-form', key, C.assemble(record['tbs'], outer[1][2], modified))
        for unused in range(256):
            modified = A.tlv(48, record['tbs']+outer[1][2]+A.tlv(3, bytes([unused])+signature))
            yield add('signature-bit-alignment', key, modified, unused == 0)
        for algorithm in (A.algorithm(A.V15), A.algorithm(A.V15, b'\x05\x00'), A.algorithm(A.ECDSA),
                          A.algorithm(A.PSS), b'\x30\x00'):
            yield add('outer-algorithm-binding', key, C.assemble(record['tbs'], algorithm, signature))
    pss = next(p for p in peers if p['signature_expected'] == 'pss256')
    key, cert = bytes.fromhex(pss['issuer_spki']), bytes.fromhex(pss['certificate_der'])
    key_parts = C.elements(A.complete(key, 48))
    bits = key_parts[1][2]
    any_key = A.tlv(48, A.algorithm(A.PSS)+bits)
    yield add('PSS-only-absent-key', any_key, cert, True)
    v15 = bytes.fromhex(peers[0]['certificate_der'])
    yield add('PSS-only-refuses-v15', any_key, v15, False)
    hash_algorithm = A.algorithm(A.SHA256, b'\x05\x00')
    mgf_algorithm = A.algorithm(A.MGF, hash_algorithm)
    prefix = A.tlv(160, hash_algorithm)+A.tlv(161, mgf_algorithm)
    for salt in range(34):
        parameters = A.tlv(48, prefix+A.tlv(162, A.tlv(2, bytes([salt]))))
        restricted = A.tlv(48, A.algorithm(A.PSS, parameters)+bits)
        yield add('PSS-key-minimum-binding', restricted, cert, salt <= 32)
        yield add('PSS-restricted-refuses-v15', restricted, v15, False)
    for malformed in (A.algorithm(A.RSA), A.algorithm(A.RSA, b'\x04\x00'), A.algorithm(A.EC, b'\x05\x00')):
        yield add('issuer-algorithm-parameters', A.tlv(48, malformed+bits), cert, False)
    record = C.parse(cert)
    for null_hash in (False, True):
        for null_mgf_hash in (False, True):
            for trailer in (False, True):
                h = A.algorithm(A.SHA256, b'\x05\x00' if null_hash else b'')
                m = A.algorithm(A.MGF, A.algorithm(A.SHA256, b'\x05\x00' if null_mgf_hash else b''))
                parameters = A.tlv(48, A.tlv(160, h)+A.tlv(161, m)+A.tlv(162, A.tlv(2, b'\x20'))
                                   +(A.tlv(163, A.tlv(2, b'\x01')) if trailer else b''))
                yield add('PSS-outer-parameter-equivalence', key, C.assemble(record['tbs'], A.algorithm(A.PSS, parameters), record['signature']), True)
    # Large rejected inputs run alone, with exact cap and oversized admission.
    outer = C.elements(A.complete(cert, 48))
    for total in (4096, 65534, 65535, 65536):
        for size in range(max(1, total-len(record['tbs'])-len(outer[1][2])-12), total):
            modified = C.assemble(record['tbs'], outer[1][2], bytes(size))
            if len(modified) == total:
                yield add('certificate-total-input-bound', key, modified, False)
                break
        else:
            raise AssertionError(total)
    for size in (65535, 65536):
        yield add('issuer-total-input-bound', bytes(size), cert, False)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--report', type=Path)
    parser.add_argument('binary', nargs=argparse.REMAINDER)
    options = parser.parse_args()
    binary = options.binary[1:] if options.binary[:1] == ['--'] else options.binary
    if not binary:
        parser.error('supply the whole verifier after --')
    rows = iter(cases()); counts = Counter(); start = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='grounds-x509-signature-') as directory:
        first = 0; pending = next(rows, None)
        while pending is not None:
            batch = [pending]; pending = None
            while len(batch) < 8 and max(len(batch[0][1]), len(batch[0][2])) <= 4096:
                row = next(rows, None)
                if row is None:
                    break
                if max(len(row[1]), len(row[2])) > 4096:
                    pending = row; break
                batch.append(row)
            args = []
            for index, (_, key, cert, _) in enumerate(batch):
                issuer = Path(directory)/f'{index}-issuer.der'
                certificate = Path(directory)/f'{index}-certificate.der'
                issuer.write_bytes(key); certificate.write_bytes(cert)
                args.extend((str(issuer), str(certificate)))
            result = subprocess.run(binary+['verify']+args, capture_output=True, text=True, timeout=90)
            assert result.returncode == 0, (first, result.returncode, result.stderr[-2000:])
            actual = result.stdout.splitlines(); expected = [row[3] for row in batch]
            assert actual == expected, (first, [r[0] for r in batch], actual, expected)
            counts.update(row[0] for row in batch); first += len(batch)
            if pending is None:
                pending = next(rows, None)
        for args in ([], ['verify', 'one-path'], ['unknown-command']):
            result = subprocess.run(binary+args, capture_output=True, text=True, timeout=10)
            assert result.returncode == 2 and not result.stdout, (args, result.returncode, result.stdout)
    names = ['x509_signature.bend', 'x509_verify_cli.bend', 'x509_signature_check.py', 'x509_signature_vectors.json',
             'x509_algorithm.bend', 'x509_public_key.bend', 'x509_certificate.bend', 'sha256.bend',
             'rsa_signature256.bend', 'rsa_integer.bend', 'rsa_encoding.bend', 'ecdsa256.bend',
             'ecdsa_der256.bend', 'p256.bend', 'field256.bend', 'bytes.bend', 'der.bend',
             'x509_algorithm_vectors.json', 'x509_algorithm_check.py', 'x509_public_key_check.py',
             'x509_certificate_check.py', 'rsa_signature256_check.py', 'ecdsa_check.py', 'p256_check.py']
    report = {'binary': binary, 'total': sum(counts.values()), 'cases': dict(counts),
              'CLI_failures': 3, 'elapsed_seconds': round(time.monotonic()-start, 3),
              'whole_Bend_signature_verification': True, 'certificate_trust_validation': False,
              'input_sha256': {name: hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in names}}
    if options.report:
        options.report.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
