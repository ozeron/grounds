"""Real Chrome/CDP interop with profile-local CA trust and full verification.

No browser driver dependency. Chrome's ServerCertificate SQLite/protobuf schema:
https://source.chromium.org/chromium/chromium/src/+/main:components/server_certificate_database/
Only a newly created throwaway Default profile is written, before Chrome starts.
The metadata bytes encode CertificateMetadata.trust.trust_type = TRUSTED (3).
Unknown Chrome/schema changes fail the positive/negative verification controls.
"""
import argparse
import base64
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import ssl
import struct
import subprocess
import tempfile
import time

from bend_tls_check import server


class CDP:
    """Small RFC6455 client for local CDP JSON, with bounded messages/deadlines."""
    def __init__(self, url):
        from urllib.parse import urlsplit
        u = urlsplit(url)
        self.socket = socket.create_connection((u.hostname, u.port), timeout=12)
        key = base64.b64encode(os.urandom(16)).decode()
        self.socket.sendall((f"GET {u.path} HTTP/1.1\r\nHost: {u.netloc}\r\nUpgrade: websocket\r\n"
                             f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
        head = b""
        while not head.endswith(b"\r\n\r\n"):
            head += self.exact(1)
            assert len(head) < 16384
        assert head.startswith(b"HTTP/1.1 101 "), head
        accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest())
        assert accept.lower() in head.lower(), head
        self.number = 0
        self.events = []

    def exact(self, n):
        out = bytearray()
        while len(out) < n:
            part = self.socket.recv(n - len(out))
            assert part, "CDP EOF"
            out.extend(part)
        return bytes(out)

    def receive(self):
        parts = bytearray()
        while True:
            a, b = self.exact(2)
            assert not b & 128
            n = b & 127
            if n in (126, 127):
                n = struct.unpack("!H" if n == 126 else "!Q", self.exact(2 if n == 126 else 8))[0]
            assert n < 16 * 1024 * 1024
            parts.extend(self.exact(n))
            assert a & 15 in (0, 1), a
            if a & 128:
                return json.loads(parts)

    def call(self, method, params=None, session=None):
        self.number += 1
        data = dict(id=self.number, method=method, params=params or {})
        if session:
            data['sessionId'] = session
        raw = json.dumps(data).encode()
        mask = os.urandom(4)
        n = len(raw)
        head = b'\x81' + (bytes([128 | n]) if n < 126 else b'\xfe' + struct.pack('!H', n) if n < 65536 else b'\xff' + struct.pack('!Q', n))
        self.socket.sendall(head + mask + bytes(c ^ mask[i % 4] for i, c in enumerate(raw)))
        until = time.monotonic() + 18
        while time.monotonic() < until:
            value = self.receive()
            if value.get('id') == self.number:
                assert 'error' not in value, value
                return value.get('result', {})
            self.events.append(value)
        raise TimeoutError(method)

    def evaluate(self, expression, session):
        result = self.call('Runtime.evaluate', dict(expression=expression, awaitPromise=True, returnByValue=True), session)
        assert 'exceptionDetails' not in result, result
        return result['result'].get('value')


def profile_trust(directory, der):
    profile = directory / 'Default'
    profile.mkdir()
    with sqlite3.connect(profile / 'ServerCertificate') as db:
        db.execute('CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR)')
        db.executemany('INSERT INTO meta VALUES(?,?)', [('version', '1'), ('last_compatible_version', '1')])
        db.execute('CREATE TABLE certificates(sha256hash_hex TEXT PRIMARY KEY, der_cert BLOB NOT NULL, trust_settings BLOB NOT NULL)')
        db.execute('INSERT INTO certificates VALUES(?,?,?)', (hashlib.sha256(der).hexdigest(), der, b'\x0a\x02\x08\x03'))


def chrome_binary():
    candidates = [os.environ.get('GROUNDS_CHROME'), '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
                  shutil.which('google-chrome'), shutil.which('chromium'), shutil.which('chromium-browser')]
    value = next((p for p in candidates if p and Path(p).is_file()), None)
    if not value:
        raise RuntimeError('Chrome required; set GROUNDS_CHROME to an installed Chrome executable')
    return value


@contextmanager
def chrome(binary, der, report):
    with tempfile.TemporaryDirectory(prefix='grounds-chrome-verified-') as td:
        directory = Path(td)
        profile_trust(directory, der)
        flags = ['--headless=new', '--no-first-run', '--no-default-browser-check', '--disable-background-networking',
                 '--disable-component-update', '--disable-sync', '--disable-gpu', '--no-proxy-server',
                 '--remote-debugging-port=0', '--user-data-dir=' + td,
                 '--host-resolver-rules=MAP mismatch.test 127.0.0.1', 'about:blank']
        report['chrome_flags'].append(flags)
        with (directory / 'stderr').open('w+') as log:
            process = subprocess.Popen([binary, *flags], stdout=subprocess.DEVNULL, stderr=log)
            cdp = None
            try:
                active = directory / 'DevToolsActivePort'
                deadline = time.monotonic() + 12
                while not active.exists():
                    if process.poll() is not None or time.monotonic() > deadline:
                        log.seek(0)
                        raise RuntimeError(('Chrome startup', process.poll(), log.read()[-4000:]))
                    time.sleep(.05)
                port, path = active.read_text().splitlines()[:2]
                cdp = CDP(f'ws://127.0.0.1:{port}{path}')
                report['chrome_version'] = cdp.call('Browser.getVersion')
                target = cdp.call('Target.createTarget', dict(url='about:blank'))['targetId']
                session = cdp.call('Target.attachToTarget', dict(targetId=target, flatten=True))['sessionId']
                cdp.call('Page.enable', session=session)
                cdp.call('Network.enable', session=session)
                yield cdp, session
            finally:
                if cdp:
                    cdp.socket.close()
                process.terminate()
                try:
                    process.wait(5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(3)
                report.setdefault('chrome_cleanup', []).append(dict(pid=process.pid, reaped=process.poll() is not None,
                    profile_removed_on_exit=True))


def navigate(cdp, session, url, expected_error=None):
    result = cdp.call('Page.navigate', dict(url=url), session)
    if expected_error:
        assert result.get('errorText') == expected_error, result
        return result
    assert not result.get('errorText'), result
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if cdp.evaluate('document.readyState === "complete" && document.title === "Grounds native browser"', session):
            return result
        time.sleep(.05)
    raise TimeoutError(('page', url))


EXERCISE = r'''(async () => {
  const rows = [];
  const check = (name, ok, detail) => { if (!ok) throw Error(name + ': ' + JSON.stringify(detail)); rows.push({name, passed:true, detail}); };
  check('https-page', isSecureContext && document.querySelector('#ready').textContent === 'native Bend HTTPS', location.href);
  let r = await fetch('/healthz'); let t = await r.text(); check('fetch-get', r.status === 200 && t === 'ok\n', t);
  r = await fetch('/echo', {method:'POST', body:'browser post café'}); t = await r.text(); check('fetch-post', r.status === 200 && t === 'browser post café', t);
  for (const method of ['GET','POST']) {
    const [status, body] = await new Promise((resolve,reject) => { const x = new XMLHttpRequest(); x.open(method, method === 'GET' ? '/healthz' : '/echo'); x.onload = () => resolve([x.status,x.responseText]); x.onerror = reject; x.send(method === 'POST' ? 'xhr post' : null); });
    check('xhr-' + method.toLowerCase(), status === 200 && body === (method === 'GET' ? 'ok\n' : 'xhr post'), body);
  }
  r = await fetch('/cookie'); check('unsigned-cookie-rejected', r.status === 401, r.status);
  r = await fetch('/mint'); check('signed-cookie-set', r.status === 200 && !document.cookie.includes('grounds='), r.status);
  r = await fetch('/cookie'); t = await r.text(); check('signed-cookie-roundtrip', r.status === 200 && t === 'cookie ok\n', t);
  await new Promise((resolve,reject) => {
    const ws = new WebSocket(location.origin.replace('https:', 'wss:') + '/ws'); ws.binaryType = 'arraybuffer'; let step = 0;
    const timer = setTimeout(() => { ws.close(); reject(Error('WSS timeout')); }, 6000);
    ws.onerror = () => { clearTimeout(timer); reject(Error('WSS error')); };
    ws.onopen = () => { check('wss-connect', true); ws.send('browser café'); };
    ws.onmessage = e => {
      try {
        if (step++ === 0) { check('wss-text', e.data === 'browser café', e.data); ws.send(new Uint8Array([0,1,2,127,128,255])); }
        else { const a = [...new Uint8Array(e.data)]; check('wss-binary', JSON.stringify(a) === '[0,1,2,127,128,255]', a); ws.close(1000,'done'); }
      } catch(e) { clearTimeout(timer); reject(e); }
    };
    ws.onclose = e => { clearTimeout(timer); try { check('wss-close', e.wasClean && e.code === 1000, {code:e.code, clean:e.wasClean}); resolve(); } catch(e) { reject(e); } };
  });
  return rows;
})()'''


def live(a, report):
    binary = chrome_binary()
    report['chrome_executable_version'] = subprocess.check_output([binary, '--version'], text=True).strip()
    # Trust an unrelated root first: same leaf, same hostname, full verifier refusal.
    wrong_der = ssl.PEM_cert_to_DER_cert((a.fixtures / 'other.pem').read_text())
    right_der = (a.fixtures / 'anchor.der').read_bytes()
    report['trust'] = dict(mechanism='throwaway Default/ServerCertificate user trust database; CertificateMetadata.trust_type=3',
                          ca_sha256=hashlib.sha256(right_der).hexdigest(), system_trust_modified=False,
                          verification_bypasses=False)
    from bend_tls_client_check import free_port
    port = free_port()
    with server([str(a.binary.resolve())], a.fixtures, 'ecdsa', a.suite,
                PORT=port, HTTP_WS_ORIGIN=f'https://localhost:{port}') as (_, process):
        url = f'https://localhost:{port}'
        with chrome(binary, wrong_der, report) as (cdp, session):
            result = navigate(cdp, session, url, 'net::ERR_CERT_AUTHORITY_INVALID')
            report['results'].append(dict(name='untrusted-ca-refused', passed=True, navigation=result))
        with chrome(binary, right_der, report) as (cdp, session):
            result = navigate(cdp, session, f'https://mismatch.test:{port}', 'net::ERR_CERT_COMMON_NAME_INVALID')
            report['results'].append(dict(name='hostname-mismatch-refused', passed=True, navigation=result))
            navigate(cdp, session, url)
            report['results'].extend(cdp.evaluate(EXERCISE, session))
            cookies = cdp.call('Network.getCookies', dict(urls=[url]), session)['cookies']
            cookie = next(c for c in cookies if c['name'] == 'grounds')
            assert cookie['secure'] and cookie['httpOnly'] and cookie['sameSite'] == 'Strict', cookie
            report['results'].append(dict(name='cookie-attributes', passed=True, secure=True, http_only=True, same_site='Strict'))
            responses = [e['params']['response'] for e in cdp.events if e.get('method') == 'Network.responseReceived' and e['params']['response']['url'].startswith(url)]
            security = [r.get('securityDetails') for r in responses if r.get('securityDetails')]
            assert security and all(s['protocol'] == 'TLS 1.3' for s in security), security
            expected = 'AES_128_GCM' if a.suite == 'aes' else 'CHACHA20_POLY1305'
            assert all(s['cipher'] == expected for s in security), security
            assert all(r['securityState'] == 'secure' for r in responses), responses
            report['tls_security_details'] = security[0]
            # The IP SAN is trusted too; this origin differs from the allowlist.
            navigate(cdp, session, f'https://127.0.0.1:{port}')
            report['results'].append(dict(name='ip-san-page', passed=True))
            denied = cdp.evaluate('''new Promise((resolve,reject) => {
              const w = new WebSocket(''' + json.dumps(f'wss://localhost:{port}/ws') + ''');
              const timer = setTimeout(() => reject(Error('denied Origin timeout')),5000);
              w.onopen = () => { clearTimeout(timer); w.close(); reject(Error('denied Origin opened')); };
              w.onerror = () => { clearTimeout(timer); resolve('refused'); };
            })''', session)
            assert denied == 'refused'
            # Flush network events queued immediately before the JS result.
            cdp.call('Runtime.evaluate', dict(expression='true'), session)
            denied_ids = {e['params']['requestId'] for e in cdp.events
                          if e.get('method') == 'Network.webSocketWillSendHandshakeRequest'
                          and e['params']['request']['headers'].get('Origin') == f'https://127.0.0.1:{port}'}
            rejected = [e['params'] for e in cdp.events
                        if e.get('method') == 'Network.webSocketFrameError'
                        and e['params']['requestId'] in denied_ids
                        and e['params']['errorMessage'] == 'Error during WebSocket handshake: Unexpected response code: 403']
            assert rejected, [e for e in cdp.events if 'webSocket' in e.get('method', '')]
            report['results'].append(dict(name='denied-origin-wss-403', passed=True, status=403,
                                          origin=f'https://127.0.0.1:{port}', cdp_errors=rejected))
        assert process.poll() is None
    report['results'].append(dict(name='owned-server-reaped', passed=process.poll() is not None))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, required=True)
    p.add_argument('--fixtures', type=Path, required=True)
    p.add_argument('--suite', choices=['aes','chacha'], required=True)
    p.add_argument('--report', type=Path, required=True)
    a = p.parse_args()
    report = dict(target='native', suite=a.suite, synthetic_keys_only=True, results=[], chrome_flags=[],
                  driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  server_sha256=hashlib.sha256(a.binary.read_bytes()).hexdigest())
    start = time.monotonic()
    try:
        live(a, report)
        report['passed'] = True
    except BaseException as error:
        report.update(passed=False, error=repr(error))
        raise
    finally:
        report['elapsed_seconds'] = time.monotonic() - start
        a.report.parent.mkdir(parents=True, exist_ok=True)
        a.report.write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(dict(passed=report.get('passed'), scenarios=len(report['results']), report=str(a.report))))


if __name__ == '__main__':
    main()
