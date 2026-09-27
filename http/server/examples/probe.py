"""Raw-socket checks against a running examples/hello server on PORT."""
import socket
import sys
import time

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080


def ask(data):
    s = socket.create_connection(("127.0.0.1", PORT))
    s.sendall(data)
    s.settimeout(3)
    out = b""
    try:
        while True:
            c = s.recv(4096)
            if not c:
                break
            out += c
    except socket.timeout:
        pass
    s.close()
    return out


def expect(name, got, want):
    if want not in got:
        sys.exit(f"{name}: want {want!r}, got {got[:120]!r}")
    print(f"{name}: ok")


expect("bare LF refused", ask(b"GET / HTTP/1.1\nHost: x\n\n"), b"HTTP/1.1 400 Bad Request\r\n")
expect("HTTP/2.0 refused", ask(b"GET / HTTP/2.0\r\nHost: x\r\n\r\n"), b"HTTP/1.1 505 HTTP Version Not Supported\r\n")
expect("missing Host refused", ask(b"GET / HTTP/1.1\r\n\r\n"), b"HTTP/1.1 400 Bad Request\r\n")
two = ask(b"GET /?name=a HTTP/1.1\r\nHost: x\r\n\r\nGET /?name=b HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
expect("pipelined: first", two, b"hello, a\n")
expect("pipelined: second", two, b"hello, b\n")
slow = socket.create_connection(("127.0.0.1", PORT))
slow.sendall(b"GET /?name=slow HTTP/1.1\r\nHo")
t = time.time()
expect("served while another waits", ask(b"GET /?name=fast HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"), b"hello, fast\n")
slow.sendall(b"st: x\r\nConnection: close\r\n\r\n")
slow.settimeout(3)
expect("the waiting one", slow.recv(4096), b"hello, slow\n")
slow.close()
