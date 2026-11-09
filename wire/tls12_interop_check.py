"""Bend TLS 1.2 client against independent TLS 1.2-only servers (M7).

Peers: OpenSSL s_server -tls1_2, Python ssl with maximum_version=TLSv1_2, and
Go crypto/tls with MaxVersion=VersionTLS12 (tls12_go_peer.go), each suite
with its certificate type (synthetic P-256 and RSA-2048 chains). A
1.3-capable OpenSSL/Go peer must still negotiate TLS 1.3. Negative cases use
the peers directly (wrong host, expiry, untrust, no EMS, non-ECDHE suites)
or a record proxy in front of OpenSSL (tampered ServerKeyExchange, injected
DOWNGRD sentinel, stripped EMS, unoffered RSA/CBC suite, altered or garbled
Finished, garbled/truncated application records, HelloRequest). The proxy
uses OpenSSL's test-only key log to re-encrypt its edits; the Bend client is
never given OpenSSL or any host TLS effect.
"""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import select
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

ROOT = Path(__file__).resolve().parent
CIVIL_OFFSET = 62135596800
SUITES = {  # IANA value: (OpenSSL/Python name, certificate, Go value)
    0xC02B: ('ECDHE-ECDSA-AES128-GCM-SHA256', 'ecdsa'), 0xC02C: ('ECDHE-ECDSA-AES256-GCM-SHA384', 'ecdsa'),
    0xCCA9: ('ECDHE-ECDSA-CHACHA20-POLY1305', 'ecdsa'), 0xC02F: ('ECDHE-RSA-AES128-GCM-SHA256', 'rsa'),
    0xC030: ('ECDHE-RSA-AES256-GCM-SHA384', 'rsa'), 0xCCA8: ('ECDHE-RSA-CHACHA20-POLY1305', 'rsa'),
}
PONG = b'pong'.hex()


def run(command, **kwargs):
    return subprocess.run(command, capture_output=True, check=True, timeout=30, **kwargs)


def fixture(directory, openssl):
    """A private synthetic CA, an unrelated root and P-256/RSA leaves."""
    def command(*args):
        return run([openssl, *map(str, args)])
    for name, subject in (('ca', 'M7 synthetic TLS 1.2 root'), ('other', 'M7 unrelated root')):
        command('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-noenc',
                '-keyout', directory / f'{name}.key', '-out', directory / f'{name}.pem', '-days', '30', '-sha256',
                '-subj', f'/CN={subject}', '-addext', 'basicConstraints=critical,CA:TRUE,pathlen:0',
                '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
        command('x509', '-in', directory / f'{name}.pem', '-outform', 'DER', '-out', directory / f'{name}.der')
    extensions = directory / 'leaf.cnf'
    extensions.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n'
                          'extendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n'
                          'subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n')
    for kind, algorithm in (('ecdsa', ['ec', '-pkeyopt', 'ec_paramgen_curve:P-256']), ('rsa', ['rsa:2048'])):
        command('req', '-new', '-newkey', *algorithm, '-noenc', '-keyout', directory / f'{kind}.key',
                '-out', directory / f'{kind}.csr', '-subj', '/CN=M7 synthetic leaf', '-sha256')
        command('x509', '-req', '-in', directory / f'{kind}.csr', '-CA', directory / 'ca.pem', '-CAkey', directory / 'ca.key',
                '-set_serial', '201' if kind == 'ecdsa' else '202', '-days', '7', '-sha256', '-extfile', extensions,
                '-out', directory / f'{kind}.pem')
    return {name: hashlib.sha256((directory / name).read_bytes()).hexdigest() for name in ('ca.der', 'other.der', 'ecdsa.pem', 'rsa.pem')}


def free_port():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


def wait_port(port, process, seconds=10):
    stop = time.monotonic() + seconds
    while time.monotonic() < stop:
        if process is not None and process.poll() is not None:
            raise RuntimeError('peer exited early')
        try:
            with socket.create_connection(('127.0.0.1', port), 0.2):
                return
        except OSError:
            time.sleep(0.02)
    raise TimeoutError('peer did not listen')


# ---- peers ----
@contextmanager
def openssl_peer(directory, openssl, certificate, extra, keylog=None):
    port = free_port()
    command = [openssl, 's_server', '-accept', f'127.0.0.1:{port}', '-cert', str(directory / f'{certificate}.pem'),
               '-key', str(directory / f'{certificate}.key'), '-alpn', 'http/1.1', '-naccept', '1', '-quiet', *extra]
    if keylog:
        command += ['-keylogfile', str(keylog)]
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stop = threading.Event()

    def answer():
        # s_server prints received application bytes; answer "ping" with "pong".
        received = b''
        until = time.monotonic() + 20
        while not stop.is_set() and time.monotonic() < until and b'ping' not in received:
            ready, _, _ = select.select([process.stdout], [], [], 0.1)
            if ready:
                piece = os.read(process.stdout.fileno(), 4096)
                if not piece:
                    return
                received += piece
        if b'ping' in received:
            try:
                process.stdin.write(b'pong')
                process.stdin.flush()
            except OSError:
                pass

    thread = threading.Thread(target=answer, daemon=True)
    try:
        # s_server does not accept until it listens; probing would consume -naccept.
        time.sleep(0.4)
        thread.start()
        yield port, command
    finally:
        stop.set()
        thread.join(2)
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(3)
        except subprocess.TimeoutExpired:
            process.kill()
        for pipe in (process.stdin, process.stdout, process.stderr):
            pipe.close()


@contextmanager
def python_peer(directory, certificate, cipher):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers(cipher)
    context.set_alpn_protocols(['http/1.1'])
    context.load_cert_chain(directory / f'{certificate}.pem', directory / f'{certificate}.key')
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    listener.settimeout(20)
    result = {}

    def serve():
        try:
            raw, _ = listener.accept()
            with context.wrap_socket(raw, server_side=True) as connection:
                connection.settimeout(15)
                data = b''
                while len(data) < 4:
                    piece = connection.recv(4 - len(data))
                    if not piece:
                        break
                    data += piece
                result.update(version=connection.version(), cipher=connection.cipher()[0], received=data.decode(errors='replace'))
                connection.sendall(b'pong')
                connection.unwrap()
        except (OSError, ssl.SSLError) as error:
            result['error'] = repr(error)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield listener.getsockname()[1], ['python-ssl', ssl.OPENSSL_VERSION, cipher], result
    finally:
        thread.join(20)
        listener.close()


@contextmanager
def go_peer(binary, directory, certificate, suite, group=29, maximum=0x0303):
    command = [str(binary), '-cert', str(directory / f'{certificate}.pem'), '-key', str(directory / f'{certificate}.key'),
               '-suite', str(suite), '-group', str(group), '-max', str(maximum)]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        port = int(process.stdout.readline())
        yield port, command, process
    finally:
        try:
            process.wait(10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(2)


# ---- TLS 1.2 record proxy with key-log re-encryption ----
def prf(sha384, secret, label, seed, length):
    digest = hashlib.sha384 if sha384 else hashlib.sha256
    seed, a, out = label + seed, label + seed, b''
    while len(out) < length:
        a = hmac.new(secret, a, digest).digest()
        out += hmac.new(secret, a + seed, digest).digest()
    return out[:length]


def read_record(sock):
    header = b''
    while len(header) < 5:
        piece = sock.recv(5 - len(header))
        if not piece:
            return None
        header += piece
    size = int.from_bytes(header[3:5], 'big')
    body = b''
    while len(body) < size:
        piece = sock.recv(size - len(body))
        if not piece:
            return None
        body += piece
    return header + body


def record(kind, body):
    return bytes([kind, 3, 3]) + len(body).to_bytes(2, 'big') + body


def split_handshake(data):
    messages = []
    while data:
        size = int.from_bytes(data[1:4], 'big')
        messages.append(data[:4 + size])
        data = data[4 + size:]
    return messages


def edit_hello(message, case):
    body = bytearray(message[4:])
    session_end = 35 + body[34]
    if case == 'downgrade-sentinel':
        body[26:34] = b'DOWNGRD\x01'
    elif case in ('rsa-kx-suite', 'cbc-suite'):
        body[session_end:session_end + 2] = (0x002F if case == 'rsa-kx-suite' else 0xC013).to_bytes(2, 'big')
    elif case == 'strip-ems':
        start = session_end + 5
        items, cursor = b'', start
        while cursor < len(body):
            kind, size = int.from_bytes(body[cursor:cursor + 2], 'big'), int.from_bytes(body[cursor + 2:cursor + 4], 'big')
            if kind != 23:
                items += bytes(body[cursor:cursor + 4 + size])
            cursor += 4 + size
        body = body[:start - 2] + len(items).to_bytes(2, 'big') + items
    return bytes([2]) + len(body).to_bytes(3, 'big') + bytes(body)


class Proxy:
    """One client connection to one upstream server; server-to-client edits."""

    def __init__(self, upstream_port, case, keylog):
        self.case, self.keylog, self.upstream_port = case, keylog, upstream_port
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen(1)
        self.listener.settimeout(20)
        self.port = self.listener.getsockname()[1]
        self.applied, self.events, self.errors = False, [], []
        self.client_random = self.server_random = self.suite = None
        self.server_sequence = None
        self.client_sequence = None
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def keys(self):
        master = None
        stop = time.monotonic() + 3
        while master is None and time.monotonic() < stop:
            if self.keylog.exists():
                for line in self.keylog.read_text().splitlines():
                    fields = line.split()
                    if len(fields) == 3 and fields[0] == 'CLIENT_RANDOM' and fields[1] == self.client_random.hex():
                        master = bytes.fromhex(fields[2])
            time.sleep(0.01)
        sha384, chacha = self.suite in (0xC02C, 0xC030), self.suite in (0xCCA9, 0xCCA8)
        key, iv = (32 if sha384 or chacha else 16), (12 if chacha else 4)
        block = prf(sha384, master, b'key expansion', self.server_random + self.client_random, 2 * key + 2 * iv)
        return dict(chacha=chacha, client=(block[:key], block[2 * key:2 * key + iv]),
                    server=(block[key:2 * key], block[2 * key + iv:]))

    @staticmethod
    def aad(sequence, kind, length):
        return sequence.to_bytes(8, 'big') + bytes([kind, 3, 3]) + length.to_bytes(2, 'big')

    def open(self, keys, side, sequence, encoded):
        key, iv = keys[side]
        kind, body = encoded[0], encoded[5:]
        if keys['chacha']:
            nonce = bytes(a ^ b for a, b in zip(iv, sequence.to_bytes(12, 'big')))
            return ChaCha20Poly1305(key).decrypt(nonce, body, self.aad(sequence, kind, len(body) - 16))
        return AESGCM(key).decrypt(iv + body[:8], body[8:], self.aad(sequence, kind, len(body) - 24))

    def seal(self, keys, side, sequence, kind, plaintext):
        key, iv = keys[side]
        if keys['chacha']:
            nonce = bytes(a ^ b for a, b in zip(iv, sequence.to_bytes(12, 'big')))
            return record(kind, ChaCha20Poly1305(key).encrypt(nonce, plaintext, self.aad(sequence, kind, len(plaintext))))
        explicit = sequence.to_bytes(8, 'big')
        return record(kind, explicit + AESGCM(key).encrypt(iv + explicit, plaintext, self.aad(sequence, kind, len(plaintext))))

    def serve(self):
        try:
            self.client, _ = self.listener.accept()
            self.upstream = socket.create_connection(('127.0.0.1', self.upstream_port), 5)
            for sock in (self.client, self.upstream):
                sock.settimeout(20)
            up = threading.Thread(target=self.client_to_server, daemon=True)
            up.start()
            self.server_to_client()
            up.join(5)
        except Exception as error:
            self.errors.append(f'{type(error).__name__}: {error}')
        finally:
            for sock in (getattr(self, 'client', None), getattr(self, 'upstream', None), self.listener):
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass

    def client_to_server(self):
        while True:
            try:
                encoded = read_record(self.client)
            except OSError:
                break
            if encoded is None:
                break
            if encoded[0] == 22 and encoded[5] == 1 and self.client_random is None:
                self.client_random = encoded[11:43]
            if self.client_sequence is not None and encoded[0] == 21:
                try:
                    alert = self.open(self.keys(), 'client', self.client_sequence, encoded)
                    self.events.append(dict(client_alert=list(alert)))
                except Exception as error:
                    self.events.append(dict(client_alert_undecrypted=repr(error)))
            if self.client_sequence is not None:
                self.client_sequence += 1
            if encoded[0] == 20:
                self.client_sequence = 0
            try:
                self.upstream.sendall(encoded)
            except OSError:
                break

    def emit(self, data):
        self.client.sendall(data)

    def server_to_client(self):
        case = self.case
        while True:
            encoded = read_record(self.upstream)
            if encoded is None:
                break
            kind = encoded[0]
            if kind == 22 and self.server_sequence is None:
                messages = split_handshake(encoded[5:])
                edited = []
                for message in messages:
                    if message[0] == 2:
                        self.server_random, self.suite = message[6:38], int.from_bytes(message[39 + message[38]:41 + message[38]], 'big')
                        if case in ('downgrade-sentinel', 'rsa-kx-suite', 'cbc-suite', 'strip-ems'):
                            message, self.applied = edit_hello(message, case), True
                    if message[0] == 12 and case == 'tamper-ske':
                        message, self.applied = message[:-1] + bytes([message[-1] ^ 1]), True
                    edited.append(message)
                encoded = record(22, b''.join(edited))
            elif kind == 20:
                self.server_sequence = 0
            elif self.server_sequence is not None:
                sequence = self.server_sequence
                self.server_sequence += 1
                if sequence == 0 and case in ('altered-finished', 'garbled-finished'):
                    if case == 'garbled-finished':
                        encoded = encoded[:-1] + bytes([encoded[-1] ^ 1])
                    else:
                        keys = self.keys()
                        finished = bytearray(self.open(keys, 'server', 0, encoded))
                        finished[-1] ^= 1
                        encoded = self.seal(keys, 'server', 0, 22, bytes(finished))
                    self.applied = True
                elif sequence == 0 and case == 'hello-request':
                    keys = self.keys()
                    self.emit(encoded)
                    self.emit(self.seal(keys, 'server', 1, 22, b'\x00\x00\x00\x00'))
                    self.applied = True
                    time.sleep(1)
                    return
                elif kind == 23 and case == 'garbled-application':
                    encoded, self.applied = encoded[:-3] + bytes([encoded[-3] ^ 0x40]) + encoded[-2:], True
                elif kind == 23 and case == 'truncated-record':
                    self.emit(encoded[:7])
                    self.applied = True
                    return
            self.emit(encoded)


def client(binary, directory, port, identity='localhost', anchor='ca.der', now=None):
    civil = int(time.time()) + CIVIL_OFFSET if now is None else now
    command = binary + ['run', str(ROOT.parent / 'crypto/unicode32_nfkc.bin'), str(ROOT.parent / 'crypto/unicode32_prepare.bin'),
                        str(directory / anchor), identity, str(port), str(civil), 'plain']
    env = dict(os.environ, BEND_LIBSSL='/nonexistent/m7-host-tls', GROUNDS_TLS_CA='/nonexistent/m7-host-ca')
    result = subprocess.run(command, capture_output=True, text=True, timeout=40, env=env)
    lines = [line for line in result.stdout.splitlines() if line.startswith(('ok:', 'error:', 'connect-error:'))]
    return (lines[-1] if lines else ''), result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--openssl', default=os.environ.get('OPENSSL', 'openssl'))
    p.add_argument('--go-peer', type=Path, required=True)
    p.add_argument('--report', type=Path)
    p.add_argument('command', nargs='+')
    a = p.parse_args()
    rows, failures = [], []
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='grounds-tls12-interop-') as folder:
        directory = Path(folder)
        hashes = fixture(directory, a.openssl)

        def record_case(peer, name, expected, line, result, extra=None):
            ok = line.startswith(expected)
            row = dict(peer=peer, name=name, expected=expected, observed=line, passed=ok, exit=result.returncode,
                       stderr=result.stderr[-1500:], **(extra or {}))
            rows.append(row)
            if not ok:
                failures.append(row)
            print(json.dumps(dict(peer=peer, name=name, observed=line, passed=ok)), flush=True)

        # OpenSSL, every suite with its certificate type; P-256 and sigalg variants.
        variants = [(suite, name, cert, 29, []) for suite, (name, cert) in SUITES.items()]
        variants += [(0xC02B, SUITES[0xC02B][0], 'ecdsa', 23, []), (0xC02F, SUITES[0xC02F][0], 'rsa', 23, []),
                     (0xC02F, SUITES[0xC02F][0], 'rsa', 29, ['-sigalgs', 'RSA+SHA256']),
                     (0xC030, SUITES[0xC030][0], 'rsa', 29, ['-sigalgs', 'RSA+SHA384']),
                     (0xC02F, SUITES[0xC02F][0], 'rsa', 29, ['-sigalgs', 'rsa_pss_rsae_sha512']),
                     (0xC02B, SUITES[0xC02B][0], 'ecdsa', 29, ['-sigalgs', 'ECDSA+SHA384'])]
        for suite, cipher, cert, group, extra in variants:
            args = ['-tls1_2', '-cipher', cipher, '-groups', 'X25519' if group == 29 else 'P-256', *extra]
            with openssl_peer(directory, a.openssl, cert, args) as (port, command):
                line, result = client(a.command, directory, port)
            record_case('openssl', f'{cipher}-{group}{"-" + extra[-1] if extra else ""}', f'ok:{suite}:{group}:true:{PONG}', line, result, dict(peer_command=command))
        # Python ssl (its own OpenSSL build), every suite.
        for suite, (cipher, cert) in SUITES.items():
            with python_peer(directory, cert, cipher) as (port, command, peer_result):
                line, result = client(a.command, directory, port)
            record_case('python-ssl', cipher, f'ok:{suite}:29:true:{PONG}', line, result, dict(peer_command=command, peer_result=peer_result))
            if peer_result.get('version') != 'TLSv1.2' and line.startswith('ok:'):
                failures.append(dict(name=cipher, peer=peer_result))
        # Go crypto/tls, every suite; P-256 for two.
        for suite, (cipher, cert) in list(SUITES.items()) + [(0xC02B, SUITES[0xC02B]), (0xCCA8, SUITES[0xCCA8])]:
            group = 23 if any(r['peer'] == 'go' and r['name'].startswith(cipher) for r in rows) else 29
            with go_peer(a.go_peer, directory, cert, suite, group) as (port, command, process):
                line, result = client(a.command, directory, port)
            peer_out = process.stdout.read() if process.stdout else ''
            record_case('go', f'{cipher}-{group}', f'ok:{suite}:{group}:true:{PONG}', line, result, dict(peer_command=command, peer_output=peer_out))
        # A TLS 1.3-capable peer still negotiates TLS 1.3.
        with openssl_peer(directory, a.openssl, 'ecdsa', []) as (port, command):
            line, result = client(a.command, directory, port)
        record_case('openssl', 'tls13-capable', f'ok:4865:29:true:{PONG}', line, result)
        with go_peer(a.go_peer, directory, 'rsa', 0, 29, 0x0304) as (port, command, process):
            line, result = client(a.command, directory, port)
        record_case('go', 'tls13-capable', f'ok:4865:29:true:{PONG}', line, result)
        # Negative cases against the peers directly.
        tls12 = ['-tls1_2', '-cipher', SUITES[0xC02B][0]]
        civil = int(time.time()) + CIVIL_OFFSET
        for name, extra, kwargs, expected in (
                ('wrong-host', [], dict(identity='example.com'), 'error:42:certificate:'),
                ('expired', [], dict(now=civil + 30 * 86400), 'error:45:certificate:'),
                ('untrusted', [], dict(anchor='other.der'), 'error:48:certificate:'),
                ('server-without-ems', ['-no_ems'], {}, 'error:40:extended-master-secret-required'),
        ):
            with openssl_peer(directory, a.openssl, 'ecdsa', tls12 + extra) as (port, command):
                line, result = client(a.command, directory, port, **kwargs)
            record_case('openssl', name, expected, line, result, dict(peer_command=command))
        for name, cipher in (('server-rsa-kx-only', 'AES128-GCM-SHA256'), ('server-cbc-only', 'ECDHE-ECDSA-AES128-SHA'),
                             ('server-dhe-only', 'DHE-RSA-AES128-GCM-SHA256')):
            with openssl_peer(directory, a.openssl, 'rsa' if 'RSA' in cipher or cipher.startswith('AES') else 'ecdsa', ['-tls1_2', '-cipher', cipher]) as (port, command):
                line, result = client(a.command, directory, port)
            record_case('openssl', name, 'error:40:peer-alert', line, result, dict(peer_command=command))
        with python_peer(directory, 'ecdsa', SUITES[0xC02B][0]) as (port, command, peer_result):
            line, result = client(a.command, directory, port, identity='example.com')
        record_case('python-ssl', 'wrong-host', 'error:42:certificate:', line, result)
        with go_peer(a.go_peer, directory, 'rsa', 0xC02F) as (port, command, process):
            line, result = client(a.command, directory, port, anchor='other.der')
        record_case('go', 'untrusted', 'error:48:certificate:', line, result)
        # Proxy mutations in front of OpenSSL (AES-128-GCM and ChaCha20).
        mutations = [
            ('tamper-ske', 0xC02B, 'error:51:server-key-exchange-signature'),
            ('tamper-ske', 0xC02F, 'error:51:server-key-exchange-signature'),
            ('downgrade-sentinel', 0xC02B, 'error:47:downgrade-sentinel'),
            ('strip-ems', 0xC02B, 'error:40:extended-master-secret-required'),
            ('rsa-kx-suite', 0xC02F, 'error:47:server-selection'),
            ('cbc-suite', 0xC02B, 'error:47:server-selection'),
            ('altered-finished', 0xC02B, 'error:51:finished'),
            ('altered-finished', 0xCCA9, 'error:51:finished'),
            ('altered-finished', 0xC030, 'error:51:finished'),
            ('garbled-finished', 0xC02B, 'error:20:bad-record-mac'),
            ('garbled-application', 0xCCA8, 'error:20:bad-record-mac'),
            ('truncated-record', 0xC02B, 'error:50:truncated'),
            ('hello-request', 0xC02B, 'error:100:renegotiation-refused'),
        ]
        for case, suite, expected in mutations:
            cipher, cert = SUITES[suite]
            keylog = directory / f'{case}-{suite}.keylog'
            with openssl_peer(directory, a.openssl, cert, ['-tls1_2', '-cipher', cipher], keylog) as (port, command):
                proxy = Proxy(port, case, keylog)
                line, result = client(a.command, directory, proxy.port)
                proxy.thread.join(5)
            extra = dict(mutation_applied=proxy.applied, proxy_events=proxy.events, proxy_errors=proxy.errors)
            record_case('openssl-proxy', f'{case}-{cipher}', expected, line, result, extra)
            if not proxy.applied:
                failures.append(dict(name=case, reason='mutation not applied'))
            if case == 'hello-request' and dict(client_alert=[1, 100]) not in proxy.events:
                failures.append(dict(name=case, reason='no warning no_renegotiation alert observed', events=proxy.events))
    report = dict(cases=len(rows), failures=len(failures), elapsed_seconds=round(time.monotonic() - started, 1),
                  openssl=subprocess.run([a.openssl, 'version'], capture_output=True, text=True).stdout.strip(),
                  python_ssl=ssl.OPENSSL_VERSION, fixtures_sha256=hashes, rows=rows, failure_rows=failures)
    if a.report:
        a.report.parent.mkdir(parents=True, exist_ok=True)
        a.report.write_text(json.dumps(report, indent=2) + '\n')
    print(f'tls12 interop: {len(rows)} cases, {len(failures)} failures')
    if failures:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
