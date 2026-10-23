"""Synthetic TLS 1.3 client interop against an independent OpenSSL server.

The tested executable owns TLS. This harness only generates public test
credentials, runs a peer, and records/mutates that peer's wire traffic. No
OpenSSL effect is supplied to the Bend process. OpenSSL's test-only key log
allows authenticated CertificateVerify/Finished mutations without implementing
or substituting the client's handshake. RFC 8446 sections 4 and 5 define the
faults and expected alerts; the frozen repository profile selects algorithms.
"""

import argparse
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import select
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "crypto"))
from gcm_check import oracle as aes_gcm

HRR = bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")
SUITES = {"aes": (4865, "TLS_AES_128_GCM_SHA256"),
          "chacha": (4867, "TLS_CHACHA20_POLY1305_SHA256")}
GROUPS = {"x25519": (29, "X25519"), "p256": (23, "P-256")}
CIVIL_OFFSET = 62135596800


def cases():
    result = []
    for suite in SUITES:
        for group in GROUPS:
            for signature in ("ecdsa", "rsa"):
                result.append(dict(name=f"{suite}-{group}-{signature}", suite=suite,
                                   group=group, signature=signature))
    for name in ("keyupdate-client", "keyupdate-server", "certificate-request", "ip-identity",
                 "fragmented", "coalesced", "close-notify", "tickets", "bulk-write", "legacy-record-version", "compatibility-ccs"):
        result.append(dict(name=name, suite="aes", group="x25519", signature="ecdsa"))
    failures = {
        "wrong-hostname": 42, "untrusted-chain": 48, "expired-certificate": 45,
        "altered-certificate-verify": 51, "altered-finished": 51, "modified-record": 20,
        "unsupported-suite": 47, "unsupported-group": 47, "duplicate-extension": 50,
        "unsolicited-extension": 110, "malformed-server-hello": 50, "double-hrr": 10,
        "out-of-order": 10, "truncated-record": 50, "peer-eof": 50,
        "deadline": 80, "early-application-data": 10, "post-handshake-auth": 10,
        "malformed-keyupdate": 47, "unoffered-signature": 47,
        "request-wrong-extension": 47, "request-nonempty-context": 47,
        "certificate-nonempty-context": 47, "keyupdate-followed-ticket": 10,
        "keyupdate-followed-update": 10, "unsupported-version": 47,
        "missing-supported-version": 70, "missing-key-share": 109,
        "empty-handshake-record": 10, "invalid-ccs": 10, "late-ccs": 10, "malformed-version-length": 50, "malformed-share-length": 50,
        "malformed-retry-cookie": 50, "malformed-retry-share": 50,
        "malformed-alpn": 50, "unsupported-alpn": 120,
    }
    for name, alert in failures.items():
        result.append(dict(name=name, suite="aes", group="p256" if name in {"double-hrr", "malformed-retry-cookie", "malformed-retry-share"} else "x25519",
                           signature="ecdsa", alert=alert))
    return result


def run(command, **kwargs):
    return subprocess.run(command, capture_output=True, check=True, timeout=15, **kwargs)


def fixture(directory, openssl):
    """Generate a private synthetic CA and two leaves, never production keys."""
    def command(*args):
        return run([openssl, *map(str, args)])
    ca_key, ca = directory / "ca.key", directory / "ca.pem"
    command("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-noenc", "-keyout", ca_key, "-out", ca, "-days", "30", "-sha256",
            "-subj", "/CN=Grounds synthetic TLS test root",
            "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    command("x509", "-in", ca, "-outform", "DER", "-out", directory / "anchor.der")
    command("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-noenc", "-keyout", directory / "other.key", "-out", directory / "other.pem",
            "-days", "30", "-sha256", "-subj", "/CN=Grounds unrelated synthetic root",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    command("x509", "-in", directory / "other.pem", "-outform", "DER",
            "-out", directory / "untrusted.der")
    extensions = directory / "leaf.cnf"
    extensions.write_text("basicConstraints=critical,CA:FALSE\n"
                          "keyUsage=critical,digitalSignature\n"
                          "extendedKeyUsage=serverAuth\n"
                          "subjectAltName=DNS:localhost,IP:127.0.0.1\n"
                          "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n")
    for signature in ("ecdsa", "rsa"):
        key, csr, cert = (directory / (signature + suffix) for suffix in (".key", ".csr", ".pem"))
        algorithm = (["ec", "-pkeyopt", "ec_paramgen_curve:P-256"] if signature == "ecdsa" else ["rsa:2048"])
        command("req", "-new", "-newkey", *algorithm, "-noenc", "-keyout", key,
                "-out", csr, "-subj", "/CN=synthetic SAN-only test leaf", "-sha256")
        command("x509", "-req", "-in", csr, "-CA", ca, "-CAkey", ca_key,
                "-set_serial", "101" if signature == "ecdsa" else "102", "-days", "7",
                "-sha256", "-extfile", extensions, "-out", cert)
    return {name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
            for name in ("anchor.der", "untrusted.der", "ecdsa.pem", "rsa.pem")}


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def connect_peer(port, process):
    stop = time.monotonic() + 5
    while time.monotonic() < stop:
        if process.poll() is not None:
            raise RuntimeError("OpenSSL peer exited before listening")
        try:
            return socket.create_connection(("127.0.0.1", port), timeout=0.1)
        except (ConnectionError, TimeoutError):
            time.sleep(0.01)
    raise TimeoutError("OpenSSL peer did not listen within five seconds")


def exact(sock, length):
    data = bytearray()
    while len(data) < length:
        part = sock.recv(length - len(data))
        if not part:
            if data:
                raise EOFError("peer EOF inside record")
            return None
        data.extend(part)
    return bytes(data)


def record(sock):
    header = exact(sock, 5)
    if header is None:
        return None
    body = exact(sock, int.from_bytes(header[3:5], "big"))
    if body is None:
        raise EOFError("peer EOF after record header")
    return header + body


def frame(kind, body):
    return bytes([kind, 3, 3]) + len(body).to_bytes(2, "big") + body


def handshake(kind, body):
    return bytes([kind]) + len(body).to_bytes(3, "big") + body


def expand(secret, label, length):
    label = b"tls13 " + label
    info = length.to_bytes(2, "big") + bytes([len(label)]) + label + b"\x00"
    block, output, index = b"", b"", 1
    while len(output) < length:
        block = hmac.digest(secret, block + info + bytes([index]), "sha256")
        output += block
        index += 1
    return output[:length]


def traffic_nonce(iv, sequence):
    counter = sequence.to_bytes(12, "big")
    return bytes(a ^ b for a, b in zip(iv, counter))


class Epoch:
    """Independent test AES-GCM record transform, never used by the client."""
    def __init__(self, secret):
        self.secret = secret
        self.key = expand(secret, b"key", 16)
        self.iv = expand(secret, b"iv", 12)
        self.sequence = 0

    def decrypt(self, encoded):
        nonce = traffic_nonce(self.iv, self.sequence)
        ciphertext, tag = encoded[5:-16], encoded[-16:]
        # CTR is symmetric. Then authenticate the recovered plaintext with the
        # independent OpenSSL-AES / Python-bigint GHASH oracle.
        plaintext, _ = aes_gcm(self.key, nonce, encoded[:5], ciphertext)
        check_ciphertext, check_tag = aes_gcm(self.key, nonce, encoded[:5], plaintext)
        if not hmac.compare_digest(tag, check_tag) or check_ciphertext != ciphertext:
            raise AssertionError("independent peer record authentication failed")
        self.sequence += 1
        return plaintext

    def encrypt(self, plaintext):
        header = frame(23, bytes(len(plaintext) + 16))[:5]
        ciphertext, tag = aes_gcm(self.key, traffic_nonce(self.iv, self.sequence), header, plaintext)
        self.sequence += 1
        return header + ciphertext + tag

    def update(self):
        return Epoch(expand(self.secret, b"traffic upd", 32))


def hello_fields(encoded):
    body = encoded[9:]
    session_end = 35 + body[34]
    extension_start = session_end + 5
    return body, session_end, extension_start


def hello_mutation(encoded, name):
    body, session_end, ext_start = hello_fields(encoded)
    body = bytearray(body)
    if name == "unsupported-suite":
        body[session_end:session_end + 2] = bytes.fromhex("1302")
    elif name in {"duplicate-extension", "unsolicited-extension"}:
        extra = bytes.fromhex("002b00020304") if name == "duplicate-extension" else bytes.fromhex("fde80000")
        body.extend(extra)
        body[ext_start - 2:ext_start] = (len(body) - ext_start).to_bytes(2, "big")
    elif name == "malformed-retry-cookie":
        body.extend(b"\x00\x2c\x00\x01\x00")
        body[ext_start-2:ext_start] = (len(body)-ext_start).to_bytes(2,"big")
    elif name == "malformed-retry-share":
        cursor = ext_start
        while cursor + 4 <= len(body):
            typ,size = struct.unpack(">HH",body[cursor:cursor+4])
            if typ==51:
                body[cursor+2:cursor+4] = b"\0\1"
                del body[cursor+5:cursor+4+size]
                body[ext_start-2:ext_start]=(len(body)-ext_start).to_bytes(2,"big")
                break
            cursor += 4+size
    elif name in {"unsupported-group", "malformed-share-length"}:
        cursor = ext_start
        while cursor + 4 <= len(body):
            kind, length = struct.unpack(">HH", body[cursor:cursor + 4])
            if kind == 51:
                if name == "unsupported-group":
                    body[cursor + 4:cursor + 6] = bytes.fromhex("001e")
                else:
                    body[cursor + 6:cursor + 8] = bytes.fromhex("001f")
                break
            cursor += 4 + length
    elif name in {"unsupported-version", "missing-supported-version", "missing-key-share", "malformed-version-length"}:
        items, cursor = bytearray(), ext_start
        while cursor + 4 <= len(body):
            typ, size = struct.unpack(">HH", body[cursor:cursor + 4])
            item = body[cursor:cursor + 4 + size]
            if name == "malformed-version-length" and typ == 43:
                item = b"\x00\x2b\x00\x01\x03"
            if name == "unsupported-version" and typ == 43:
                item = item[:4] + b"\x03\x03"
            if not ((name == "missing-supported-version" and typ == 43)
                    or (name == "missing-key-share" and typ == 51)):
                items.extend(item)
            cursor += 4 + size
        body = body[:ext_start - 2] + len(items).to_bytes(2,"big") + items
    elif name == "malformed-server-hello":
        body[34] = 255
    return frame(22, handshake(2, bytes(body)))


class Proxy:
    """One connection, record-aware mutation, and peer-visible alert evidence."""
    def __init__(self, listener, upstream, keylog, case):
        self.listener, self.upstream = listener, upstream
        self.keylog, self.case = keylog, case
        self.events, self.errors = [], []
        self.client = None
        self.threads = []
        self.stop = threading.Event()
        self.hrr_count = 0
        self.client_hellos = 0
        self.mutation_applied = False
        self.server_finished = False
        self.client_finished = False
        self.server_hs = self.client_hs = None
        self.server_app = self.client_app = None
        self.server_out = None
        self.client_out = None
        self.injected_update = False
        self.suppressed_update = False

    def secret(self, label):
        stop = time.monotonic() + 3
        while time.monotonic() < stop:
            if self.keylog.exists():
                for line in self.keylog.read_text().splitlines():
                    fields = line.split()
                    if len(fields) == 3 and fields[0] == label:
                        return bytes.fromhex(fields[2])
            time.sleep(0.005)
        raise TimeoutError("OpenSSL key log missing " + label)

    def epochs(self, direction):
        if direction == "server":
            if self.server_hs is None:
                self.server_hs = Epoch(self.secret("SERVER_HANDSHAKE_TRAFFIC_SECRET"))
            if self.server_finished:
                if self.server_app is None:
                    self.server_app = Epoch(self.secret("SERVER_TRAFFIC_SECRET_0"))
                    self.server_out = Epoch(self.server_app.secret)
                return self.server_app, self.server_out
            return self.server_hs, None
        if self.client_hs is None:
            self.client_hs = Epoch(self.secret("CLIENT_HANDSHAKE_TRAFFIC_SECRET"))
        if self.client_finished:
            if self.client_app is None:
                self.client_app = Epoch(self.secret("CLIENT_TRAFFIC_SECRET_0"))
                self.client_out = Epoch(self.client_app.secret)
            return self.client_app, self.client_out
        return self.client_hs, None

    def protected(self, encoded, direction):
        incoming, outgoing = self.epochs(direction)
        sequence = incoming.sequence
        plaintext = incoming.decrypt(encoded)
        end = len(plaintext) - 1
        while end >= 0 and plaintext[end] == 0:
            end -= 1
        if end < 0:
            raise AssertionError("OpenSSL emitted empty TLSInnerPlaintext")
        kind, content = plaintext[end], plaintext[:end]
        event = dict(direction=direction, protected_type=kind, bytes=len(content))
        if kind == 21:
            event["alert"] = list(content)
        if kind == 22:
            cursor, types = 0, []
            while cursor + 4 <= len(content):
                length = int.from_bytes(content[cursor + 1:cursor + 4], "big")
                typ = content[cursor]
                types.append(typ)
                name = self.case["name"]
                if direction == "server" and not self.mutation_applied:
                    target = {"altered-certificate-verify": 15, "altered-finished": 20}.get(name)
                    if typ == target:
                        content = bytearray(content)
                        content[cursor + 3 + length] ^= 1
                        content = bytes(content)
                        plaintext = content + plaintext[end:]
                        self.mutation_applied = True
                    elif name == "unoffered-signature" and typ == 15:
                        content = content[:cursor + 4] + b"\x08\x07" + content[cursor + 6:]
                        plaintext = content + bytes([22])
                        self.mutation_applied = True
                    elif name in {"request-wrong-extension", "request-nonempty-context"} and typ == 13:
                        body = (b"\x00\x00\x06\x00\x2b\x00\x02\x03\x04" if name == "request-wrong-extension"
                                else b"\x01x" + content[cursor + 5:cursor + 4 + length])
                        content = content[:cursor] + handshake(13, body) + content[cursor + 4 + length:]
                        plaintext = content + bytes([22])
                        self.mutation_applied = True
                    elif name == "certificate-nonempty-context" and typ == 11:
                        body = b"\x01x" + content[cursor + 5:cursor + 4 + length]
                        content = content[:cursor] + handshake(11, body) + content[cursor + 4 + length:]
                        plaintext = content + bytes([22])
                        self.mutation_applied = True
                    elif name in {"malformed-alpn", "unsupported-alpn"} and typ == 8:
                        protocol = b"\x00\x03\x02h" if name == "malformed-alpn" else b"\x00\x03\x02h2"
                        extension = b"\x00\x10" + len(protocol).to_bytes(2,"big") + protocol
                        content = handshake(8,len(extension).to_bytes(2,"big")+extension)
                        plaintext = content + bytes([22])
                        self.mutation_applied = True
                    elif name == "out-of-order" and typ == 8:
                        content = handshake(20, bytes(32))
                        plaintext = content + bytes([22])
                        self.mutation_applied = True
                if typ == 20:
                    if direction == "server":
                        self.server_finished = True
                    else:
                        self.client_finished = True
                if typ == 24:
                    event["keyupdate"] = list(content[cursor + 4:cursor + 4 + length])
                    if direction == "server":
                        self.server_app = incoming.update()
                    else:
                        self.client_app = incoming.update()
                if typ == 11 and direction == "client":
                    body = content[cursor + 4:cursor + 4 + length]
                    context_length = body[0] if body else -1
                    event["empty_client_certificate"] = (context_length >= 0
                        and body[1 + context_length:] == b"\x00\x00\x00")
                cursor += 4 + length
            event["handshakes"] = types
        self.events.append(event)
        # Once inserted application records shift sequence numbers, every later
        # peer record is translated from the peer epoch to the client epoch.
        if outgoing is not None:
            encoded = outgoing.encrypt(plaintext)
            if kind == 22 and 24 in event.get("handshakes", []):
                if direction == "server":
                    self.server_out = outgoing.update()
                else:
                    self.client_out = outgoing.update()
        elif self.mutation_applied and direction == "server":
            temporary = Epoch(incoming.secret)
            temporary.sequence = sequence
            encoded = temporary.encrypt(plaintext)
        if direction == "client" and kind == 22 and event.get("keyupdate") == [0] and self.injected_update:
            # The independent server did not request this proxy-inserted update.
            # Consume the response and keep its original outbound epoch.
            self.client_out = outgoing
            outgoing.sequence -= 1
            self.suppressed_update = True
            self.events.append(dict(direction="client", suppressed_test_only_keyupdate_response=True))
            return None, kind, content
        return encoded, kind, content

    def emit(self, target, encoded):
        if self.case["name"] == "fragmented":
            for offset in range(0, len(encoded), 3):
                target.sendall(encoded[offset:offset + 3])
        else:
            target.sendall(encoded)

    def pump(self, source, target, direction):
        try:
            while not self.stop.is_set():
                encoded = record(source)
                if encoded is None:
                    break
                name, kind = self.case["name"], encoded[0]
                if direction == "client" and kind == 22:
                    self.client_hellos += 1
                    self.events.append(dict(direction=direction, handshake=encoded[5]))
                if direction == "server" and kind == 22:
                    retry = encoded[11:43] == HRR
                    self.hrr_count += int(retry)
                    if name in {"unsupported-suite", "unsupported-group", "duplicate-extension",
                                "unsolicited-extension", "malformed-server-hello", "unsupported-version",
                                "missing-supported-version", "missing-key-share", "malformed-version-length",
                                "malformed-share-length", "malformed-retry-cookie", "malformed-retry-share"}:
                        encoded = hello_mutation(encoded, name)
                        self.mutation_applied = True
                    if name == "double-hrr" and retry:
                        self.emit(target, encoded)
                        # Wait for ClientHello2 before duplicating HRR. This
                        # proves a second retry rejection in the actual state.
                        until = time.monotonic() + 5
                        while self.client_hellos < 2 and time.monotonic() < until:
                            time.sleep(0.005)
                        self.emit(target, encoded)
                        self.hrr_count += 1
                        self.mutation_applied = True
                        return
                    if name == "legacy-record-version":
                        encoded = encoded[:1] + b"\x03\x01" + encoded[3:]
                        self.mutation_applied = True
                    if name in {"compatibility-ccs", "invalid-ccs"}:
                        self.emit(target, frame(20,b"\x01" if name == "compatibility-ccs" else b"\x02"))
                        self.events.append(dict(direction="server", inserted_compatibility_ccs=True))
                        self.mutation_applied = True
                    if name == "empty-handshake-record":
                        encoded = frame(22,b"")
                        self.mutation_applied = True
                    if name == "coalesced":
                        following = record(source)
                        if following is None:
                            raise AssertionError("OpenSSL stopped after ServerHello")
                        if following[0] == 23 and self.case["suite"] == "aes":
                            following, _, _ = self.protected(following, direction)
                        self.emit(target, encoded + following)
                        self.events.append(dict(direction="server", coalesced_records=2))
                        continue
                if kind == 21:
                    self.events.append(dict(direction=direction, alert=list(encoded[5:])))
                if kind == 23 and self.case["suite"] == "aes":
                    if direction == "server" and name == "modified-record" and not self.mutation_applied:
                        encoded, _, _ = self.protected(encoded, direction)
                        encoded = encoded[:-1] + bytes([encoded[-1] ^ 1])
                        self.mutation_applied = True
                    else:
                        encoded, protected_kind, content = self.protected(encoded, direction)
                        if direction == "server" and protected_kind == 23 and not self.mutation_applied:
                            if name == "late-ccs":
                                self.emit(target, frame(20,b"\x01"))
                                self.mutation_applied = True
                            injected = {"keyupdate-server": handshake(24, b"\x01"),
                                        "post-handshake-auth": handshake(13, b"\x00\x00\x00"),
                                        "malformed-keyupdate": handshake(24, b"\x02"),
                                        "keyupdate-followed-ticket": handshake(24,b"\0") + handshake(4,bytes(8)+b"\0\0\1x\0\0"),
                                        "keyupdate-followed-update": handshake(24,b"\0") + handshake(24,b"\0")}.get(name)
                            if injected is not None:
                                # protected() already sealed the current record;
                                # rewind that output sequence to insert a record
                                # before it, then seal application bytes again.
                                self.server_out.sequence -= 1
                                self.emit(target, self.server_out.encrypt(injected + b"\x16"))
                                self.events.append(dict(direction="server", handshakes=[injected[0]],
                                                        keyupdate=[injected[-1]] if injected[0] == 24 else None,
                                                        inserted_test_only_record=True))
                                self.mutation_applied = True
                                if name == "keyupdate-server":
                                    self.injected_update = True
                                    self.server_out = self.server_out.update()
                                encoded = self.server_out.encrypt(content + b"\x17")
                if encoded is not None:
                    self.emit(target, encoded)
        except (OSError, EOFError) as error:
            self.events.append(dict(direction=direction, transport_end=str(error)))
        except Exception as error:
            self.errors.append(f"{direction}: {type(error).__name__}: {error}")
        finally:
            try:
                target.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    def serve(self):
        try:
            self.client, _ = self.listener.accept()
            self.client.settimeout(60)
            name = self.case["name"]
            if name in {"peer-eof", "truncated-record", "deadline", "early-application-data"}:
                record(self.client)
                self.client_hellos = 1
                if name == "truncated-record":
                    self.client.sendall(bytes.fromhex("1603030010020000"))
                    self.client.shutdown(socket.SHUT_WR)
                elif name == "peer-eof":
                    self.client.shutdown(socket.SHUT_WR)
                elif name == "early-application-data":
                    self.client.sendall(frame(23, b"unauthenticated"))
                else:
                    self.stop.wait(5)
                if name != "deadline":
                    try:
                        reply = record(self.client)
                        if reply and reply[0] == 21:
                            self.events.append(dict(direction="client", alert=list(reply[5:])))
                    except (OSError, EOFError):
                        pass
                return
            for source, target, direction in ((self.client, self.upstream, "client"),
                                               (self.upstream, self.client, "server")):
                thread = threading.Thread(target=self.pump, args=(source, target, direction), daemon=True)
                self.threads.append(thread)
                thread.start()
            for thread in self.threads:
                thread.join(20)
        except Exception as error:
            self.errors.append(f"proxy: {type(error).__name__}: {error}")

    def close(self):
        self.stop.set()
        for sock in (self.client, self.upstream, self.listener):
            if sock is not None:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                sock.close()
        for thread in self.threads:
            thread.join(1)


@contextmanager
def peer(directory, openssl, case):
    port = free_port()
    keylog = directory / (case["name"] + ".keylog")
    stderr_path = directory / (case["name"] + ".stderr")
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(15)
    command = [openssl, "s_server", "-accept", f"127.0.0.1:{port}", "-tls1_3",
               "-cert", str(directory / (case["signature"] + ".pem")),
               "-key", str(directory / (case["signature"] + ".key")),
               "-ciphersuites", SUITES[case["suite"]][1], "-groups", GROUPS[case["group"]][1],
               "-sigalgs", "ecdsa_secp256r1_sha256" if case["signature"] == "ecdsa" else "rsa_pss_rsae_sha256",
               "-alpn", "http/1.1", "-naccept", "1", "-quiet", "-keylogfile", str(keylog)]
    if case["name"] != "tickets":
        command += ["-num_tickets", "0"]
    if case["name"] in {"certificate-request", "request-wrong-extension", "request-nonempty-context"}:
        command += ["-verify", "1", "-CAfile", str(directory / "ca.pem")]
    if case["name"] == "close-notify":
        command += ["-no_ign_eof"]
    with stderr_path.open("wb") as stderr:
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr)
        proxy = None
        try:
            upstream = connect_peer(port, process)
            upstream.settimeout(60)
            proxy = Proxy(listener, upstream, keylog, case)
            worker = threading.Thread(target=proxy.serve, daemon=True)
            worker.start()
            yield listener.getsockname()[1], process, proxy, command
        finally:
            if proxy:
                proxy.close()
                worker.join(2)
            else:
                listener.close()
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(2)
            for pipe in (process.stdin, process.stdout):
                if pipe:
                    pipe.close()


def exchange(process, case, observations, wait_seconds=20):
    """Use s_server's ordinary application stdio, never TLS in the client."""
    try:
        ready, _, _ = select.select([process.stdout], [], [], wait_seconds)
        if not ready:
            observations["application"] = f"no peer application bytes within {wait_seconds} seconds"
            return
        wanted = b"p" * 40000 if case["name"] == "bulk-write" else b"ping"
        ping = bytearray()
        until = time.monotonic() + wait_seconds
        while len(ping) < len(wanted):
            ready, _, _ = select.select([process.stdout], [], [], max(0, until-time.monotonic()))
            if not ready:
                break
            piece = os.read(process.stdout.fileno(), min(4096, len(wanted)-len(ping)))
            if not piece:
                break
            ping.extend(piece)
        observations["received_hex"] = ping.hex()
        if ping != wanted:
            return
        process.stdin.write(b"pong")
        process.stdin.flush()
        if case["name"] == "close-notify":
            process.stdin.close()
    except (BrokenPipeError, OSError) as error:
        observations["application_error"] = str(error)


def test_case(binary, directory, openssl, case, timeout):
    started = time.monotonic()
    anchor = directory / ("untrusted.der" if case["name"] == "untrusted-chain" else "anchor.der")
    identity = "wrong.invalid" if case["name"] == "wrong-hostname" else "localhost"
    if case["name"] == "ip-identity":
        identity = "127.0.0.1"
    now = int(time.time()) + CIVIL_OFFSET
    if case["name"] == "expired-certificate":
        now += 366 * 86400
    mode = {"keyupdate-client": "update", "deadline": "timeout", "ip-identity": "ip",
            "close-notify": "close", "bulk-write": "bulk"}.get(case["name"], "normal")
    observed = {}
    with peer(directory, openssl, case) as (port, process, proxy, peer_command):
        command = binary + ["run", str(ROOT.parent / "crypto/unicode32_nfkc.bin"),
                            str(ROOT.parent / "crypto/unicode32_prepare.bin"), str(anchor),
                            identity, str(port), str(now), mode]
        app = threading.Thread(target=exchange, args=(process, case, observed, max(1, timeout - 2)), daemon=True)
        app_expected = "alert" not in case or case["name"] in {"post-handshake-auth", "malformed-keyupdate", "keyupdate-followed-ticket", "keyupdate-followed-update", "late-ccs"}
        if app_expected:
            app.start()
        try:
            client_env = dict(os.environ, BEND_LIBSSL="/nonexistent/grounds-test-libssl",
                              GROUNDS_TLS_CA="/nonexistent/grounds-test-host-ca")
            result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, env=client_env)
            observed.update(returncode=result.returncode, stdout=result.stdout, stderr=result.stderr)
        except subprocess.TimeoutExpired as error:
            observed.update(timeout=True, stdout=(error.stdout or b"").decode(errors="replace"),
                            stderr=(error.stderr or b"").decode(errors="replace"))
        if app_expected:
            app.join(1)
        time.sleep(0.05)
        observed.update(peer_command=peer_command, command=command, proxy_events=list(proxy.events),
                        proxy_errors=list(proxy.errors), hrr_count=proxy.hrr_count,
                        client_hellos=proxy.client_hellos, mutation_applied=proxy.mutation_applied)
    observed["peer_stderr"] = (directory / (case["name"] + ".stderr")).read_text(errors="replace")
    lines = observed.get("stdout", "").strip().splitlines()
    if "alert" in case:
        local = next((line for line in lines if line.startswith("error:")), "")
        passed = local.startswith(f"error:{case['alert']}:")
        observed["expected_local_alert"] = case["alert"]
        alerts = [event["alert"] for event in observed["proxy_events"]
                  if event.get("direction") == "client" and "alert" in event]
        observed["peer_observed_client_alerts"] = alerts
        # EOF/deadline may prevent writing. Other protocol failures must be
        # visible at the peer with the same alert, not merely a printed error.
        if case["name"] not in {"peer-eof", "truncated-record", "deadline"}:
            passed = passed and any(len(alert) == 2 and alert[1] == case["alert"] for alert in alerts)
        if case["name"] not in {"wrong-hostname", "untrusted-chain", "expired-certificate",
                                 "peer-eof", "truncated-record", "deadline", "early-application-data"}:
            passed = passed and observed["mutation_applied"]
        if case["name"] not in {"post-handshake-auth", "malformed-keyupdate", "keyupdate-followed-ticket", "keyupdate-followed-update", "late-ccs"}:
            passed = passed and not any(event.get("direction") == "client" and event.get("protected_type") == 23
                                        for event in observed["proxy_events"])
    else:
        expected = f"ok:{SUITES[case['suite']][0]}:{GROUPS[case['group']][0]}:true:706f6e67"
        observed["expected_stdout"] = expected
        passed = expected in lines and observed.get("received_hex") == ("70" * 40000 if case["name"] == "bulk-write" else "70696e67")
        if case["name"] in {"legacy-record-version", "compatibility-ccs"}:
            passed = passed and observed["mutation_applied"]
        if case["name"] == "bulk-write":
            sizes = [e["bytes"] for e in observed["proxy_events"]
                     if e.get("direction") == "client" and e.get("protected_type") == 23]
            passed = passed and sizes == [16384,16384,7232]
        if case["group"] == "p256":
            passed = passed and observed["hrr_count"] == 1 and observed["client_hellos"] == 2
        if case["name"] == "keyupdate-client":
            passed = passed and any(e.get("direction") == "client" and "keyupdate" in e for e in observed["proxy_events"])
        if case["name"] == "keyupdate-server":
            passed = passed and any(e.get("direction") == "server" and e.get("keyupdate") == [1] for e in observed["proxy_events"])
            passed = passed and any(e.get("direction") == "client" and e.get("keyupdate") == [0] for e in observed["proxy_events"])
        if case["name"] in {"certificate-request", "request-wrong-extension", "request-nonempty-context"}:
            passed = passed and any(e.get("empty_client_certificate") is True for e in observed["proxy_events"])
            passed = passed and not any(e.get("direction") == "client" and 15 in e.get("handshakes", []) for e in observed["proxy_events"])
        if case["name"] == "tickets":
            passed = passed and any(e.get("direction") == "server" and 4 in e.get("handshakes", []) for e in observed["proxy_events"])
        if case["name"] == "close-notify":
            passed = passed and any(e.get("direction") == "server" and e.get("alert") == [1, 0]
                                    for e in observed["proxy_events"])
        if case["name"] == "coalesced":
            passed = passed and any(e.get("coalesced_records") == 2 for e in observed["proxy_events"])
    passed = passed and observed.get("returncode") == 0 and not observed["proxy_errors"]
    return dict(case=case, passed=passed, elapsed_seconds=round(time.monotonic() - started, 3), **observed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--case", action="append", default=[])
    parser.add_argument("--batch-index", "--batch", type=int)
    parser.add_argument("--batch-size", type=int, default=2)
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--fixture-only", action="store_true")
    parser.add_argument("--timeout", type=float, default=22)
    parser.add_argument("--openssl", default="/opt/homebrew/opt/openssl@3/bin/openssl" if Path("/opt/homebrew/opt/openssl@3/bin/openssl").exists() else "openssl")
    parser.add_argument("binary", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    selected = cases()
    if args.list:
        print(json.dumps(selected, indent=2))
        return
    if args.case:
        unknown = set(args.case) - {case["name"] for case in selected}
        if unknown:
            parser.error("unknown case(s): " + ", ".join(sorted(unknown)))
        selected = [case for case in selected if case["name"] in args.case]
    if args.batch_index is not None:
        if args.batch_size < 1 or not 0 <= args.batch_index < (len(selected) + args.batch_size - 1) // args.batch_size:
            parser.error("batch index/size outside case corpus")
        selected = selected[args.batch_index * args.batch_size:(args.batch_index + 1) * args.batch_size]
    binary = args.binary[1:] if args.binary[:1] == ["--"] else args.binary
    if not binary and not args.fixture_only:
        parser.error("expected -- client-command [arguments]")
    # The existing independent AES oracle deliberately uses the openssl CLI.
    # Resolve it to the same explicitly selected executable as the peer.
    openssl = shutil.which(args.openssl)
    if not openssl:
        parser.error("OpenSSL executable not found")
    os.environ["PATH"] = str(Path(openssl).parent) + os.pathsep + os.environ.get("PATH", "")
    report = dict(binary=binary, backend=("fixture-generation" if not binary else
                  "bun" if Path(binary[0]).name == "bun" else "native"),
                  openssl_version=run([openssl, "version"], text=True).stdout.strip(),
                  synthetic_keys_only=True, client_executed=not args.fixture_only,
                  client_environment={"BEND_LIBSSL":"/nonexistent/grounds-test-libssl",
                                      "GROUNDS_TLS_CA":"/nonexistent/grounds-test-host-ca"},
                  harness_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  utc=datetime.now(timezone.utc).isoformat(), results=[])
    with tempfile.TemporaryDirectory(prefix="grounds-client-interop-") as tmp:
        directory = Path(tmp)
        report["fixture_sha256"] = fixture(directory, openssl)
        if args.fixture_only:
            print(json.dumps(report, sort_keys=True))
            return
        for case in selected:
            result = test_case(binary, directory, openssl, case, args.timeout)
            report["results"].append(result)
            print(f"{case['name']}: {'PASS' if result['passed'] else 'FAIL'}", flush=True)
            if args.report:
                args.report.parent.mkdir(parents=True, exist_ok=True)
                args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    report["counts"] = dict(Counter("passed" if case["passed"] else "failed" for case in report["results"]))
    report["total"] = len(report["results"])
    if args.report:
        args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({key: report[key] for key in ("backend", "total", "counts")}, sort_keys=True))
    if report["counts"].get("failed"):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
