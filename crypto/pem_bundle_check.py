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
    report = dict(passed=True, cases=len(results), bundle_sha256=BUNDLE_SHA256,
                  anchors=len(certificates(BUNDLE.read_bytes())), results=results)
    destination = a.report or (Path(os.environ['GROUNDS_M5_REPORT_DIR']) / ('bundle-policy.json' if a.policy else 'bundle-parser.json') if os.environ.get('GROUNDS_M5_REPORT_DIR') else None)
    if destination:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(report, indent=2) + '\n')
    print(f'Native explicit bundle admission: {len(results)} passed; malformed entries fail the whole load')


if __name__ == '__main__':
    main()
