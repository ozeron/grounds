"""Whole-chain public-fixture differential checks; no host authorization in Bend.

OpenSSL is an independent test oracle. Explicit profile differences (including
stricter limits and anchor policy) have recorded OpenSSL acceptance separately.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent


def blob(data):
    return struct.pack('>I', len(data)) + data


def sequence(items):
    return struct.pack('>I', len(items)) + b''.join(map(blob, items))


def encoded(case, certificates):
    text = datetime.fromtimestamp(case['now'], timezone.utc).strftime('%Y%m%d%H%M%SZ').encode()
    now = b'\x18\x0f' + text
    identity = (b'\x00' + case['identity'].encode() if case['kind'] == 'dns' else
                b'\x01' + ipaddress.ip_address(case['identity']).packed)
    return sequence([now, identity, sequence([certificates[k] for k in case['presented']]),
                     sequence([certificates[k] for k in case['anchors']])])


def pem(data):
    text = base64.b64encode(data).decode()
    return '-----BEGIN CERTIFICATE-----\n' + '\n'.join(text[i:i+64] for i in range(0, len(text), 64)) + '\n-----END CERTIFICATE-----\n'


def oracle(cases, certificates, directory):
    results = []
    for case in cases:
        # No peer or trust store is a failed authentication without an oracle call.
        if not case['presented'] or not case['anchors']:
            accepted, command, output = False, [], 'empty peer or explicit trust store'
        else:
            leaf = directory / 'leaf.pem'
            chain = directory / 'chain.pem'
            anchors = directory / 'anchors.pem'
            leaf.write_text(pem(certificates[case['presented'][0]]))
            chain.write_text(''.join(pem(certificates[k]) for k in case['presented'][1:]))
            anchors.write_text(''.join(pem(certificates[k]) for k in case['anchors']))
            command = ['openssl', 'verify', '-no-CApath', '-no-CAstore', '-CAfile', str(anchors),
                       '-purpose', 'sslserver', '-attime', str(case['now']),
                       '-verify_hostname' if case['kind'] == 'dns' else '-verify_ip', case['identity']]
            if len(case['presented']) > 1:
                command += ['-untrusted', str(chain)]
            command += [str(leaf)]
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            accepted, output = result.returncode == 0, result.stdout + result.stderr
        assert accepted == case['openssl_accept'], (case['label'], accepted, case['openssl_accept'], output)
        observed = dict(label=case['label'], accepted=accepted,
            bend_expected=case['expected'], profile_difference=accepted != (case['expected'] == 'success'),
            command=command, output=output)
        if 'oracle_path' in case:
            # OpenSSL does not backtrack through some same-Name/same-SKI
            # cross-certificates. Independently verify the complete winning
            # path as well as retaining its full-presentation rejection above.
            selected = dict(case, presented=case['oracle_path'], openssl_accept=True)
            del selected['oracle_path']
            observed['complete_alternate_path'] = oracle([selected], certificates, directory)[0]
        results.append(observed)
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--oracle-only', action='store_true')
    parser.add_argument('--batch-index', type=int)
    parser.add_argument('--batch-size', type=int, default=4)
    parser.add_argument('--report', type=Path)
    parser.add_argument('binary', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    source = ROOT / 'x509_chain_vectors.json'
    fixture = json.loads(source.read_text())
    certs = {k: base64.b64decode(v, validate=True) for k, v in fixture['certificates'].items()}
    cases = fixture['cases']
    assert args.batch_size > 0
    if args.batch_index is not None:
        assert 0 <= args.batch_index < (len(cases) + args.batch_size - 1) // args.batch_size
        cases = cases[args.batch_index * args.batch_size:(args.batch_index + 1) * args.batch_size]
    binary = args.binary[1:] if args.binary[:1] == ['--'] else args.binary
    report = dict(cases=len(cases), groups=dict(Counter(c['expected'] for c in cases)),
                  fixture_sha256=hashlib.sha256(source.read_bytes()).hexdigest(), binary=binary)
    with tempfile.TemporaryDirectory(prefix='grounds-chain-') as tmp:
        directory = Path(tmp)
        if args.oracle_only:
            report['oracle'] = oracle(cases, certs, directory)
            report['openssl_version'] = subprocess.check_output(['openssl', 'version'], text=True).strip()
        else:
            assert binary, 'whole Bend evaluator required'
            actual = []
            for start in range(0, len(cases), args.batch_size):
                batch = cases[start:start + args.batch_size]
                path = directory / 'batch.bin'
                path.write_bytes(sequence([encoded(c, certs) for c in batch]))
                command = [*binary, 'check', str(ROOT / 'unicode32_nfkc.bin'),
                           str(ROOT / 'unicode32_prepare.bin'), str(path)]
                result = subprocess.run(command, capture_output=True, text=True, timeout=110)
                assert result.returncode == 0, (command, result.returncode, result.stderr[-3000:])
                answers = result.stdout.splitlines()
                assert len(answers) == len(batch), (len(answers), len(batch), result.stdout[-1000:])
                for case, answer in zip(batch, answers):
                    assert answer == case['expected'], (case['label'], answer, case['expected'])
                    actual.append(dict(label=case['label'], result=answer))
            report['results'] = actual
    destination = args.report
    if destination is None and os.environ.get('GROUNDS_M1_REPORT_DIR'):
        target = 'oracle' if args.oracle_only else ('bun' if Path(binary[0]).name == 'bun' else 'native')
        destination = Path(os.environ['GROUNDS_M1_REPORT_DIR']) / f'{target}-{args.batch_index if args.batch_index is not None else "all"}.json'
    if destination:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: v for k, v in report.items() if k not in ('results', 'oracle')}, sort_keys=True))


if __name__ == '__main__':
    main()
