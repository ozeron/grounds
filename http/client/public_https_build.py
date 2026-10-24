"""Build the native public HTTP example with host TLS/cookie abort controls.

Optional diagnostic prints observe the exact HTTP fetch's incoming CV scheme
and authenticated connection's suite/group. They never change an admission,
transcript, deadline, secret or network byte. Production Bend sources stay intact.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'wire'))
from bend_tls_no_delegation_build import overlay


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--trace', action='store_true')
    p.add_argument('output', type=Path)
    p.add_argument('report', type=Path)
    a = p.parse_args()
    a.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='grounds-public-native-') as td:
        destination = Path(td)
        inputs = overlay(destination)
        for directory in ['http/client', 'http/server', 'http/wire', 'json', 'decimal']:
            for source in sorted((ROOT / directory).rglob('*')):
                if source.is_file() and source.suffix in {'.bend', '.c', '.js'}:
                    relative = source.relative_to(ROOT)
                    target = destination / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(source.read_bytes())
                    inputs[str(relative)] = hashlib.sha256(source.read_bytes()).hexdigest()
        if a.trace:
            path = destination / 'wire/bend_tls_client.bend'
            source = path.read_text()
            marker = 'def messages(pipe:'
            at = source.index(marker)
            source = source[:at] + '''def public_trace(value: Result<&2,&2,U32,C.Message>) -> IO(Unit):
  match value:
    case Done{C.CertificateVerify{scheme,_}}: IO.print("m5-cv:" ++ U32.show(scheme))
    case _: IO.pure(Unit,Unit{})

''' + source[at:]
            before = '    case Con{message,rest}: IO.pure(HandshakeWork,Act{pipe,M.step(state,message),rest})'
            after = '''    case Con{+message,rest}:
      do IO<HandshakeWork>:
        public_trace(C.parse(message))
        IO.pure(HandshakeWork,Act{pipe,M.step(state,message),rest})'''
            assert source.count(before) == 1
            source = source.replace(before, after)
            before = '      IO.pure(HandshakeWork,Shook{Done{Connection{Pipe{socket,Some{read},Some{write},HS.start(),deadline},suite,group,alpn,False{}}}})'
            after = '''      do IO<HandshakeWork>:
        IO.print("m5-negotiated:" ++ U32.show(suite) ++ ":" ++ U32.show(group))
        IO.pure(HandshakeWork,Shook{Done{Connection{Pipe{socket,Some{read},Some{write},HS.start(),deadline},suite,group,alpn,False{}}}})'''
            assert source.count(before) == 1
            source = source.replace(before, after).replace('def ready_sent(read: T.ReadKey, write: T.WriteKey, suite: U32, group: U32,', 'def ready_sent(read: T.ReadKey, write: T.WriteKey, +suite: U32, +group: U32,')
            path.write_text(source)
        program = destination / 'http/client/examples/public_https.bend'
        r = subprocess.run(['bend', str(program), '-o', str(a.output.resolve())], capture_output=True, text=True)
        report = dict(exit=r.returncode, input_sha256=inputs, trace=a.trace,
                      overlay='legacy TLS/cookie aborts plus diagnostic IO.print only' if a.trace else 'legacy TLS/cookie aborts',
                      stdout=r.stdout, stderr=r.stderr)
        if a.output.exists():
            report['output_sha256'] = hashlib.sha256(a.output.read_bytes()).hexdigest()
        a.report.write_text(json.dumps(report, indent=2) + '\n')
        print(r.stdout, r.stderr, end='')
        raise SystemExit(r.returncode)


if __name__ == '__main__':
    main()
