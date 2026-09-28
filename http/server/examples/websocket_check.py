"""Raw RFC 6455 interoperability checks for the Bend echo server."""

import base64
import hashlib
import socket
import struct
import sys


PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8088
GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
KEY = b"dGhlIHNhbXBsZSBub25jZQ=="


def masked(op, payload=b"", fin=True, key=b"\x37\xfa\x21\x3d"):
    first = op | (0x80 if fin else 0)
    n = len(payload)
    if n < 126:
        head = bytes([first, 0x80 | n])
    elif n < 65536:
        head = bytes([first, 0x80 | 126]) + struct.pack("!H", n)
    else:
        head = bytes([first, 0x80 | 127]) + struct.pack("!Q", n)
    return head + key + bytes(b ^ key[i % 4] for i, b in enumerate(payload))


def recv_exact(sock, n):
    out = bytearray()
    while len(out) < n:
        part = sock.recv(n - len(out))
        assert part, f"connection closed with {n - len(out)} bytes unread"
        out.extend(part)
    return bytes(out)


def frame(sock):
    first, second = recv_exact(sock, 2)
    assert first & 0x80 and not first & 0x70, (first, second)
    assert not second & 0x80, "server frame was masked"
    n = second & 0x7F
    if n == 126:
        n = struct.unpack("!H", recv_exact(sock, 2))[0]
    elif n == 127:
        n = struct.unpack("!Q", recv_exact(sock, 8))[0]
    return first & 0x0F, recv_exact(sock, n)


def connect(extra=b"", method=b"GET", version=b"HTTP/1.1"):
    sock = socket.create_connection(("127.0.0.1", PORT), timeout=5)
    sock.settimeout(10)
    req = (
        method + b" /ws " + version + b"\r\n"
        b"Host: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        b"Sec-WebSocket-Key: " + KEY + b"\r\n"
        b"Sec-WebSocket-Version: 13\r\n\r\n"
    )
    sock.sendall(req + extra)
    head = bytearray()
    while not head.endswith(b"\r\n\r\n"):
        head += recv_exact(sock, 1)
    return sock, bytes(head)


def expect_upgrade(head):
    assert head.startswith(b"HTTP/1.1 101 Switching Protocols\r\n"), head
    want = base64.b64encode(hashlib.sha1(KEY + GUID).digest())
    assert b"Sec-WebSocket-Accept: " + want + b"\r\n" in head, head
    assert b"content-length" not in head.lower(), head


sock, head = connect(masked(1, b"coalesced"))
expect_upgrade(head)
assert frame(sock) == (1, b"coalesced")
sock.sendall(masked(1, b"Hel", False) + masked(9, b"p") + masked(0, b"lo"))
assert frame(sock) == (10, b"p")
assert frame(sock) == (1, b"Hello")
for op, payload in [(1, "café".encode()), (2, bytes(range(256))), (2, bytes(range(256)) * 256)]:
    sock.sendall(masked(op, payload))
    try:
        got = frame(sock)
    except (AssertionError, TimeoutError) as exc:
        raise AssertionError(f"echo opcode={op} length={len(payload)}: {exc}") from exc
    assert got == (op, payload), f"echo opcode={op} length={len(payload)}"
sock.sendall(masked(8, struct.pack("!H", 1000)))
assert frame(sock) == (8, struct.pack("!H", 1000))
assert sock.recv(1) == b""
sock.close()
print("WebSocket: RFC accept, coalesced upgrade/frame, fragmentation, ping, text, binary, 64 KiB, close")

for sent, want in [(bytes([0x81, 1, 65]), 1002), (masked(1, b"\xff"), 1007),
                   (masked(0, b"orphan"), 1002), (masked(9, b"x", False), 1002)]:
    sock, head = connect()
    expect_upgrade(head)
    sock.sendall(sent)
    op, payload = frame(sock)
    assert (op, payload) == (8, struct.pack("!H", want)), (op, payload, want)
    sock.close()
print("WebSocket: unmasked, invalid UTF-8, orphan continuation, fragmented ping rejected")

for method, version in [(b"POST", b"HTTP/1.1"), (b"GET", b"HTTP/1.0")]:
    sock, head = connect(method=method, version=version)
    assert head.startswith(b"HTTP/1.1 400 Bad Request\r\n"), head
    sock.close()
print("WebSocket: invalid method and HTTP/1.0 upgrade refused")
