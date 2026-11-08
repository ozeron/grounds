"""Offline native bundle admission/limits; no host certificate authorization."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time

import x509_algorithm_check as A
import x509_certificate_check as D

ROOT = Path(__file__).parent
BUNDLE = ROOT / 'fixtures/public-chains/mozilla-2026-10-20.pem'
BUNDLE_SHA256 = '796f1389bfea13c0ed78f663b765baaff54a508e5483786bd6ece73c5e3e3cbe'


def certificates(data):
    return [base64.b64decode(re.sub(rb'\s', b'', b), validate=True)
            for b in re.findall(rb'-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----', data, re.S)]


def pem(raw):
    return b'-----BEGIN CERTIFICATE-----\n' + base64.encodebytes(raw) + b'-----END CERTIFICATE-----\n'


def nested(raw, field, value):
    # Replace one TBS field, re-encoding only the enclosing lengths. The outer
    # framing stays valid so only nested SPKI/Name/extension parsing can reject.
    tbs, algorithm, signature = D.elements(A.complete(raw, 48))
    fields = D.elements(tbs[1])
    if field == 'signature':
        # Inner and outer AlgorithmIdentifier stay identical (C.anchor binds them).
        at = (1 if fields[0][0] == 0xa0 else 0) + 1
        encoded = [f[2] for f in fields]
        encoded[at] = value
        return A.tlv(48, A.tlv(48, b''.join(encoded)) + value + signature[2])
    if field == 'extensions':
        at = len(fields) - 1
        assert fields[at][0] == 0xa3
    else:
        at = (1 if fields[0][0] == 0xa0 else 0) + dict(issuer=2, subject=4, spki=5)[field]
    encoded = [f[2] for f in fields]
    encoded[at] = value
    return A.tlv(48, A.tlv(48, b''.join(encoded)) + algorithm[2] + signature[2])


# Valid DER outside the supported key/Name profile still loads; chain search
# reports unsupported-algorithm/unsupported-name only if the anchor is used.
NESTED = [
    ('truncated-spki-oid', 'spki', '300106', 'malformed-bundle'),
    ('spki-bit-string-padding', 'spki', '300b300506032a864803020800', 'malformed-bundle'),
    ('spki-trailing-element', 'spki', '300d300506032a0304030200000500', 'malformed-bundle'),
    ('subject-rdn-not-set', 'subject', '30023000', 'malformed-bundle'),
    ('issuer-attribute-without-oid', 'issuer', '300431023000', 'malformed-bundle'),
    ('subject-noncanonical-attribute-oid', 'subject', '300b3109300706038004030c00', 'malformed-bundle'),
    ('truncated-extension', 'extensions', 'a3053003300106', 'malformed-bundle'),
    ('extension-without-value', 'extensions', 'a309300730050603551d13', 'malformed-bundle'),
    ('unknown-key-algorithm', 'spki', '300c300506032a03040303000000', 'ok:2'),
    ('unsupported-name-attribute', 'subject', '300d310b300906032a030516024142', 'ok:2'),
    # AlgorithmIdentifier parameters: every nested OID canonical and complete,
    # rsaEncryption takes NULL, id-ecPublicKey a namedCurve OID.
    ('ec-unterminated-curve-oid', 'spki', '3013300c06072a8648ce3d02010601800303000000', 'malformed-bundle'),
    ('ec-noncanonical-curve-oid', 'spki', '3014300d06072a8648ce3d0201060280010303000000', 'malformed-bundle'),
    ('ec-null-parameters', 'spki', '3012300b06072a8648ce3d020105000303000000', 'malformed-bundle'),
    ('ec-absent-parameters', 'spki', '3010300906072a8648ce3d02010303000000', 'malformed-bundle'),
    ('rsa-oid-parameters', 'spki', '3017301006092a864886f70d01010106032a03040303000000', 'malformed-bundle'),
    ('rsa-absent-parameters', 'spki', '3012300b06092a864886f70d0101010303000000', 'malformed-bundle'),
    ('key-nested-unterminated-oid', 'spki', '3011300a06032a030430030601800303000000', 'malformed-bundle'),
    ('key-nested-noncanonical-oid', 'spki', '3012300b06032a03043004060280010303000000', 'malformed-bundle'),
    ('key-nested-parameters', 'spki', '3016300f06032a0304300806032a03050201050303000000', 'ok:2'),
    # AlgorithmIdentifier takes at most one parameters element.
    ('key-two-parameters', 'spki', '3010300906032a0304050005000303000000', 'malformed-bundle'),
    ('signature-two-parameters', 'signature', '300906032a030405000500', 'malformed-bundle'),
    ('signature-nested-noncanonical-oid', 'signature', '300b06032a0304300406028001', 'malformed-bundle'),
    ('signature-unterminated-parameter-oid', 'signature', '300806032a0304060180', 'malformed-bundle'),
    ('signature-nested-parameters', 'signature', '301006032a03043009a00506032a03050500', 'ok:2'),
]

# AlgorithmIdentifier parameters (ANY) are DER to the leaves: SEQUENCE and SET
# constructed and walked; every other universal type primitive with valid
# contents; context/application/private tags framing only (constructed ones
# walked). Shared by SPKI and signature algorithms and TRUSTED AUX `other`.
# name, parameters (hex), admitted, admitted by OpenSSL 3 d2i_X509 and
# d2i_X509_AUX. Where they differ, Bend is stricter (DER, not BER): OpenSSL
# accepts any non-zero BOOLEAN octet, masks BIT STRING padding bits, accepts
# constructed strings and indefinite lengths, and never looks inside a
# SEQUENCE, SET or context-tagged parameter.
PARAMETERS = [
    ('null', '0500', True, True),
    ('null-length-1', '050100', False, False),
    ('null-constructed', '2500', False, False),
    ('boolean-true', '0101ff', True, True),
    ('boolean-false', '010100', True, True),
    ('boolean-empty', '0100', False, False),
    ('boolean-length-2', '01020000', False, False),
    ('boolean-not-der', '010101', False, True),
    ('boolean-constructed', '2100', False, False),
    ('integer', '020100', True, True),
    ('integer-high-bit', '02020080', True, True),
    ('integer-empty', '0200', False, False),
    ('integer-padded', '02020001', False, False),
    ('integer-negative-padded', '0202ff80', False, False),
    ('integer-constructed', '2203020101', False, False),
    ('enumerated', '0a0101', True, True),
    ('enumerated-empty', '0a00', False, False),
    ('enumerated-padded', '0a020001', False, False),
    ('bit-string-empty-value', '030100', True, True),
    ('bit-string-padded', '03020780', True, True),
    ('bit-string-empty', '0300', False, False),
    ('bit-string-unused-8', '03020800', False, False),
    ('bit-string-unused-255', '0301ff', False, False),
    ('bit-string-empty-unused-1', '030101', False, True),
    ('bit-string-padding-set', '03020101', False, True),
    ('bit-string-constructed', '2300', False, False),
    ('oid', '06032a0304', True, True),
    ('oid-empty', '0600', False, False),
    ('oid-unterminated', '060180', False, False),
    ('oid-noncanonical', '06028001', False, False),
    ('octet-string', '0400', True, True),
    ('octet-string-constructed', '2403040100', False, True),
    ('utf8-string', '0c0141', True, True),
    ('utf8-string-constructed', '2c00', False, True),
    ('printable-string', '1300', True, True),
    ('bmp-string', '1e020041', True, True),
    ('bmp-string-odd', '1e0141', False, False),
    ('universal-string', '1c0400000041', True, True),
    ('universal-string-length-3', '1c03000000', False, False),
    ('utc-time', '170d3236313130383030303030305a', True, True),
    ('utc-time-short', '170c' + '41' * 12, False, False),
    ('generalized-time', '180f32303236313130383030303030305a', True, True),
    ('generalized-time-short', '180e' + '41' * 14, False, False),
    ('real-empty', '0900', True, True),
    ('relative-oid', '0d0180', True, True),
    ('sequence', '30050201010500', True, True),
    ('set', '31020500', True, True),
    ('sequence-primitive', '1000', False, False),
    ('set-primitive', '1100', False, False),
    ('sequence-indefinite', '308005000000', False, True),
    ('sequence-bad-null', '3003050100', False, True),
    ('set-bad-integer', '31020200', False, True),
    ('sequence-nested-bad-boolean', '300430020100', False, True),
    ('context-primitive', '8001ff', True, True),
    ('context-constructed', 'a0038001ff', True, True),
    ('context-bad-null', 'a003050100', False, True),
    ('application-primitive', '4001ff', True, True),
    ('private-constructed', 'e0030101ff', True, True),
]
UNKNOWN_KEY = bytes.fromhex('2a0304')


def spki(parameters):
    return A.tlv(48, A.algorithm(UNKNOWN_KEY, parameters) + bytes.fromhex('0303000000'))


def libcrypto():
    """OpenSSL 3 libcrypto next to the `openssl` on PATH, else None."""
    import ctypes
    import shutil
    found = shutil.which('openssl')
    if not found:
        return None
    lib = Path(found).resolve().parent.parent / 'lib'
    for name in ('libcrypto.3.dylib', 'libcrypto.so.3'):
        if (lib / name).exists():
            c = ctypes.CDLL(str(lib / name))
            c.OpenSSL_version.restype = ctypes.c_char_p
            for f in ('d2i_X509', 'd2i_X509_AUX'):
                getattr(c, f).restype = ctypes.c_void_p
                getattr(c, f).argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_char_p), ctypes.c_long]
            c.X509_free.argtypes = [ctypes.c_void_p]
            return c
    return None


def openssl_parses(lib, function, der):
    """OpenSSL's d2i_X509 or d2i_X509_AUX consumes exactly `der`."""
    import ctypes
    buf = ctypes.create_string_buffer(der, len(der))
    p = ctypes.c_char_p(ctypes.addressof(buf))
    x = getattr(lib, function)(None, ctypes.byref(p), len(der))
    if not x:
        return False
    used = ctypes.cast(p, ctypes.c_void_p).value - ctypes.addressof(buf)
    lib.X509_free(x)
    return used == len(der)


def openssl_parameters():
    """Each PARAMETERS row's OpenSSL column, on the same certificates the
    bundle cases build (SPKI and signature through d2i_X509, AUX `other`
    through d2i_X509_AUX). None when no OpenSSL 3 libcrypto is found."""
    lib = libcrypto()
    if lib is None:
        return None
    version = lib.OpenSSL_version(0).decode()
    if not version.startswith('OpenSSL 3.'):
        return None
    raw = certificates(BUNDLE.read_bytes())[1]
    rows = []
    for name, value, _, expected in PARAMETERS:
        parameters = bytes.fromhex(value)
        other = A.tlv(48, A.tlv(0xa1, A.algorithm(UNKNOWN_KEY, parameters)))
        got = dict(spki=openssl_parses(lib, 'd2i_X509', nested(raw, 'spki', spki(parameters))),
                   signature=openssl_parses(lib, 'd2i_X509', nested(raw, 'signature', A.algorithm(UNKNOWN_KEY, parameters))),
                   aux=openssl_parses(lib, 'd2i_X509_AUX', raw + other))
        assert set(got.values()) == {expected}, (name, got, expected)
        rows.append(dict(name=name, parameters=value, openssl=expected))
    return dict(version=version, rows=rows)


def cases():
    data = BUNDLE.read_bytes()
    assert hashlib.sha256(data).hexdigest() == BUNDLE_SHA256
    roots = certificates(data)
    good = pem(roots[0])
    # Self-signatures never establish anchor trust. Mutations produce distinct
    # framed test anchors, without claiming signatures or generated credentials.
    expanded = [pem(roots[0][:-2] + i.to_bytes(2, 'big')) for i in range(257)]
    bad = good.replace(b'\n', b'\n!', 1)
    rows = [
        ('snapshot', data, f'ok:{len(roots)}'),
        ('annotated', b'# explicit CA\nlabel\n====\n' + good, 'ok:1'),
        ('crlf', good.replace(b'\n', b'\r\n'), 'ok:1'),
        ('no-final-newline', good.rstrip(), 'ok:1'),
        ('multiple', good + pem(roots[1]), 'ok:2'),
        ('empty', b'', 'empty-bundle'),
        ('text-only', b'# no certificates\n', 'empty-bundle'),
        ('bad-base64', bad, 'malformed-bundle'),
        ('partial-result-forbidden', good + bad, 'malformed-bundle'),
        ('bad-first-entry', bad + good, 'malformed-bundle'),
        ('missing-footer', good.split(b'-----END')[0], 'malformed-bundle'),
        ('missing-header', good.split(b'\n', 1)[1], 'malformed-bundle'),
        ('nested-header', good.split(b'-----END')[0] + good, 'malformed-bundle'),
        ('unknown-label', good.replace(b'CERTIFICATE', b'TRUSTED CERTIFICATE'), 'malformed-bundle'),
        ('malformed-delimiter', b'-----BEGIN CERTIFICATE----\n' + good, 'malformed-bundle'),
        ('not-a-certificate', pem(b'\x30\x00'), 'malformed-bundle'),
        ('noncanonical-signature-oid', pem(roots[0].replace(bytes.fromhex('2a8648ce3d040303'), bytes.fromhex('808648ce3d040303'))), 'malformed-bundle'),
        ('duplicate', good + good, 'duplicate-anchor'),
        *[row for name, field, value, expected in NESTED
          for row in ((name + '-after-valid', good + pem(nested(roots[1], field, bytes.fromhex(value))), expected),
                      (name + '-before-valid', pem(nested(roots[1], field, bytes.fromhex(value))) + good, expected))],
        # Every PARAMETERS row in the SPKI and signature algorithms of a plain
        # anchor next to a valid one, in either order.
        *[row for name, value, admitted, _ in PARAMETERS
          for field, element in (('spki', spki), ('signature', lambda p: A.algorithm(UNKNOWN_KEY, p)))
          for raw in (nested(roots[1], field, element(bytes.fromhex(value))),)
          for row in ((f'{field}-parameter-{name}-after-valid', good + pem(raw), 'ok:2' if admitted else 'malformed-bundle'),
                      (f'{field}-parameter-{name}-before-valid', pem(raw) + good, 'ok:2' if admitted else 'malformed-bundle'))],
        ('scale-200', b''.join(expanded[:200]), 'ok:200'),
        ('scale-256', b''.join(expanded[:256]), 'ok:256'),
        ('scale-257', b''.join(expanded), 'bundle-limit'),
        ('text-boundary', good + b' ' * (2097152 - len(good)), 'ok:1'),
        ('text-overflow', good + b' ' * (2097153 - len(good)), 'bundle-limit'),
    ]
    return rows


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--policy', action='store_true')
    p.add_argument('--report', type=Path)
    p.add_argument('binary')
    a = p.parse_args()
    results = []
    with tempfile.TemporaryDirectory(prefix='grounds-bundle-') as td:
        directory = Path(td)
        for name, data, expected in cases():
            path = directory / (name + '.pem')
            path.write_bytes(data)
            modes = ['bytes', 'file'] if a.policy else [None]
            for mode in modes:
                cmd = [a.binary] + ([mode] if mode else []) + [str(path)]
                start = time.monotonic()
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=25)
                answer = r.stdout.strip()
                # Policy CLI appends measured milliseconds only to success.
                actual = ':'.join(answer.split(':')[:2]) if answer.startswith('ok:') else answer
                assert r.returncode == 0 and actual == expected, (name, mode, r.returncode, answer, expected, r.stderr[-1000:])
                results.append(dict(name=name, mode=mode, result=actual,
                                    seconds=time.monotonic()-start))
    oracle = openssl_parameters()
    report = dict(passed=True, cases=len(results), bundle_sha256=BUNDLE_SHA256,
                  anchors=len(certificates(BUNDLE.read_bytes())), openssl_parameters=oracle, results=results)
    destination = a.report or (Path(os.environ['GROUNDS_M5_REPORT_DIR']) / ('bundle-policy.json' if a.policy else 'bundle-parser.json') if os.environ.get('GROUNDS_M5_REPORT_DIR') else None)
    if destination:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(report, indent=2) + '\n')
    print(f'Native explicit bundle admission: {len(results)} passed; malformed entries fail the whole load')
    print(f"OpenSSL parameter oracle: {len(oracle['rows'])} rows agree ({oracle['version']})" if oracle
          else 'OpenSSL parameter oracle: no OpenSSL 3 libcrypto, skipped')


if __name__ == '__main__':
    main()
