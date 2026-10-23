"""Independent verified RFC 6455/TLS peers for the native Bend WSS owner."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import socket
import struct
import subprocess
import sys
import time

from bend_tls_check import server, context, request, tls_socket
from bend_tls_client_check import SUITES
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "wire"))
from bend_tls_server_check import descriptor_count

KEY = b"dGhlIHNhbXBsZSBub25jZQ=="
ORIGIN = "https://grounds.test"


def masked(op, payload=b"", fin=True):
    mask = b"\x37\xfa\x21\x3d"
    n = len(payload)
    head = bytes([op | (0x80 if fin else 0), 0x80 | (n if n < 126 else 126 if n < 65536 else 127)])
    if n >= 126:
        head += struct.pack("!H" if n < 65536 else "!Q", n)
    return head + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload))


def exact(peer, n):
    out = bytearray()
    while len(out) < n:
        part = peer.recv(n - len(out))
        assert part, ("truncated frame", n - len(out))
        out.extend(part)
    return bytes(out)


def frame(peer):
    first, second = exact(peer, 2)
    assert first & 0x80 and not first & 0x70 and not second & 0x80
    n = second & 127
    if n in (126, 127):
        n = struct.unpack("!H" if n == 126 else "!Q", exact(peer, 2 if n == 126 else 8))[0]
    assert n <= 1048576
    return first & 15, exact(peer, n)


def connect(port, directory, cookie, origin=ORIGIN, auth="Bearer synthetic", extra=b""):
    peer = context(directory).wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=5),
        server_hostname="localhost", suppress_ragged_eofs=False)
    peer.settimeout(6)
    headers = (f"GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
               f"Sec-WebSocket-Key: {KEY.decode()}\r\nSec-WebSocket-Version: 13\r\n"
               f"Origin: {origin}\r\nAuthorization: {auth}\r\nCookie: {cookie}\r\n\r\n").encode()
    try:
        peer.sendall(headers + extra)
        head = bytearray()
        while not head.endswith(b"\r\n\r\n"):
            head += exact(peer, 1)
            assert len(head) < 16384
        return peer, bytes(head)
    except BaseException:
        peer.close()
        raise


def upgrade(head):
    assert head.startswith(b"HTTP/1.1 101 Switching Protocols\r\n"), head
    expected = base64.b64encode(hashlib.sha1(KEY + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest())
    assert b"Sec-WebSocket-Accept: " + expected + b"\r\n" in head, head
    assert b"content-length:" not in head.lower()


def close(peer):
    peer.sendall(masked(8, struct.pack("!H", 1000)))
    assert frame(peer) == (8, struct.pack("!H", 1000))
    assert peer.recv(1) == b""  # SSLEOFError is enabled for missing close_notify


def live(binary, directory, go, suite, rows):
    with server([str(binary)], directory, "ecdsa", suite) as (port, process):
        with tls_socket(port, directory) as peer:
            negotiated = peer.cipher()[0]
            assert negotiated == SUITES[suite][1], ("WSS suite differs", suite, negotiated)
            assert peer.version() == "TLSv1.3" and peer.selected_alpn_protocol() == "http/1.1"
        rows.append(dict(name="negotiated-profile", suite=suite, cipher=negotiated, alpn="http/1.1"))
        cookie = request(port, directory, "/mint")[2]["set-cookie"].split(";", 1)[0]
        for name, settings, expected in [
            ("denied-origin", dict(origin="https://denied.test"), 403),
            ("missing-auth", dict(auth=""), 401),
            ("missing-cookie", dict(cookie=""), 401),
            ("tampered-cookie", dict(cookie=cookie + "x"), 401),
        ]:
            args = dict(cookie=cookie, **{})
            args.update(settings)
            peer, head = connect(port, directory, **args)
            with peer:
                assert head.startswith(f"HTTP/1.1 {expected} ".encode()), head
                assert b" 101 " not in head
            rows.append(dict(name=name, suite=suite, status=expected))

        peer, head = connect(port, directory, cookie, extra=masked(1, b"coalesced"))
        with peer:
            upgrade(head)
            assert frame(peer) == (1, b"coalesced")
            peer.sendall(masked(1, b"Hel", False) + masked(9, b"p") + masked(0, b"lo"))
            assert frame(peer) == (10, b"p")
            assert frame(peer) == (1, b"Hello")
            for op, payload in [(1, "caf\u00e9".encode()), (2, bytes(range(256))), (2, bytes(range(256)) * 256)]:
                peer.sendall(masked(op, payload))
                assert frame(peer) == (op, payload)
            # A received pong does not become an application message.
            peer.sendall(masked(10, b"unsolicited") + masked(1, b"after pong"))
            assert frame(peer) == (1, b"after pong")
            close(peer)
        rows.append(dict(name="upgrade-buffered-text-binary-fragments-ping-pong-close-notify", suite=suite, largest_bytes=65536))

        for sent, expected in [(b"\x81\x01x", 1002), (masked(1, b"\xff"), 1007),
                               (masked(0, b"orphan"), 1002), (masked(9, b"x", False), 1002)]:
            peer, head = connect(port, directory, cookie)
            with peer:
                upgrade(head)
                peer.sendall(sent)
                assert frame(peer) == (8, struct.pack("!H", expected))
                assert peer.recv(1) == b""
            rows.append(dict(name="invalid-frame", suite=suite, sent=sent.hex(), close_code=expected))

        result = subprocess.run([str(go), "wss", str(directory / "ca.pem"), f"127.0.0.1:{port}", cookie],
                                capture_output=True, text=True, timeout=10)
        assert result.returncode == 0 and result.stdout.startswith("Go WSS:"), (result.returncode, result.stdout, result.stderr)
        rows.append(dict(name="independent-go-wss", suite=suite, stdout=result.stdout.strip()))

        time.sleep(.15)
        baseline = dict(fds=descriptor_count(process.pid), tcp=descriptor_count(process.pid, True))
        for n in range(12):
            peer, head = connect(port, directory, cookie)
            with peer:
                upgrade(head)
                if n % 2:
                    peer.sendall(masked(1, b"partial", False))  # abandoned fragment
                else:
                    close(peer)
        deadline = time.monotonic() + 4
        while True:
            current = dict(fds=descriptor_count(process.pid), tcp=descriptor_count(process.pid, True))
            if current == baseline or time.monotonic() >= deadline:
                break
            time.sleep(.1)
        assert current == baseline, (baseline, current)
        assert process.poll() is None
        rows.append(dict(name="reconnect-abandon-cleanup", suite=suite, connections=12, baseline=baseline, final=current))
    assert process.poll() is not None
    rows.append(dict(name="owned-server-reaped", suite=suite, pid=process.pid))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--fixtures", type=Path, required=True)
    p.add_argument("--go", type=Path, required=True)
    p.add_argument("--suite", choices=["aes", "chacha"], required=True)
    p.add_argument("--report", type=Path, required=True)
    args = p.parse_args()
    rows = []
    report = dict(target="native", synthetic_keys_only=True, results=rows,
                  server_sha256=hashlib.sha256(args.binary.read_bytes()).hexdigest())
    started = time.monotonic()
    try:
        live(args.binary, args.fixtures, args.go, args.suite, rows)
        report["passed"] = True
    except BaseException as error:
        report.update(passed=False, error=repr(error))
        raise
    finally:
        report["elapsed_seconds"] = time.monotonic() - started
        args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(dict(passed=report.get("passed", False), scenarios=len(rows), report=str(args.report))))


if __name__ == "__main__":
    main()
