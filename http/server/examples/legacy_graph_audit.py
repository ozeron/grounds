"""Audit the unchanged legacy entrypoints independently of the Bend graph."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[3]
EXAMPLES = ('hello', 'stack', 'stream', 'tls', 'redirect', 'trusted_proxy', 'auth')
# Inspect reachable generated definitions, never the shared host-effect prelude.
FORBIDDEN = re.compile(r'(?:crypto_|wire_(?:bend_tls|tls_(?:record|handshake|server))|bend_server_|transport_)')


def graph_ids(source, target):
    if target == 'c':
        return re.findall(r'^#define (?:CID_|FID_)(\w+)', source, re.M) + re.findall(r'^\w[^\n]*\b(\w+)\([^\n]*\)\s*\{', source, re.M)
    return re.findall(r'^function (\$\w+)\(', source, re.M)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--artifacts', type=Path, required=True)
    p.add_argument('--hello', type=Path, required=True)
    p.add_argument('--stream', type=Path, required=True)
    args = p.parse_args()
    args.artifacts.mkdir(parents=True, exist_ok=True)
    rows, controls = [], []
    env = dict(os.environ, BUN_OPTIONS=os.environ.get('BUN_OPTIONS', '') + ' --smol', BUN_JSC_forceRAMSize='134217728')
    for name in EXAMPLES:
        for target in (('c', 'js') if name in ('hello', 'stream') else ('c',)):
            path = args.artifacts / f'{name}.{target}'
            subprocess.run(['bend', str(ROOT / f'http/server/examples/{name}.bend'), '-o', str(path)], env=env, check=True, capture_output=True)
            identifiers = graph_ids(path.read_text(), target)
            assert identifiers, (name, target, 'no generated definitions recognized')
            forbidden = [value for value in identifiers if FORBIDDEN.search(value)]
            assert not forbidden, (name, target, forbidden)
            rows.append(dict(example=name, target=target, path=str(path.resolve()), sha256=hashlib.sha256(path.read_bytes()).hexdigest(), reachable_definition_count=len(identifiers), forbidden=[]))
    for name, native in [('hello', args.hello), ('stream', args.stream)]:
        for target, command in [('native', [str(native.resolve())]), ('bun', ['bun', str((args.artifacts / f'{name}.js').resolve())])]:
            result = subprocess.run(command, env=dict(os.environ, HTTP_TLS_ENGINE='bend'), capture_output=True, timeout=5)
            assert result.returncode != 0 and b'HTTP_TLS_ENGINE=bend requires http/server/bend_server.bend' in result.stderr, (name, target, result.returncode, result.stderr)
            controls.append(dict(example=name, target=target, exit=result.returncode, rejected_before_listen=True, stderr=result.stderr.decode(errors='replace')))
    report = dict(passed=True, graphs=rows, rejection_controls=controls, scope='All seven legacy C graphs; hello/stream Bun graphs and native/Bun fail-before-listen controls, with and without from_env')
    (args.artifacts / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(f'legacy graphs: {len(rows)} clean; engine rejection: {len(controls)} passed')


if __name__ == '__main__':
    main()
