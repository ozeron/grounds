"""Servers that answer the client's live test, one port each from 7301.

  python3 tests/fake.py [DIR]  # serves until killed; prints "ready" once listening.
                               # With DIR, also TLS on 7315, its certificate in DIR/cert.pem
"""
import os
import socket
import sys
import threading
import time

BASE = 7301


def read_head(conn):
    buf = b""
    while b"\r\n\r\n" not in buf:
        more = conn.recv(65536)
        if not more:
            break
        buf += more
    return buf


def answer(data, close_after=True, pause=0.0):
    def serve(conn):
        try:
            read_head(conn)
            for part in data if isinstance(data, list) else [data]:
                conn.sendall(part)
                time.sleep(pause)
            if close_after:
                conn.shutdown(socket.SHUT_WR)
                time.sleep(0.3)
        except OSError:
            pass
        conn.close()
    return serve


def stall(conn):
    read_head(conn)
    time.sleep(5)
    conn.close()


def echo(conn):
    # the request as it came, head and body, as the response body
    try:
        head = read_head(conn)
        n = 0
        for line in head.split(b"\r\n"):
            if line.lower().startswith(b"content-length:"):
                n = int(line.split(b":")[1])
        body = head[head.index(b"\r\n\r\n") + 4:]
        while len(body) < n:
            body += conn.recv(65536)
        out = head[:head.index(b"\r\n\r\n") + 4] + body
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(out)).encode() + b"\r\n\r\n" + out)
        time.sleep(0.3)
    except OSError:
        pass
    conn.close()


BIG = b"y" * 4194304

FAULTS = [
    ("chunked", answer([b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n", b"6\r\n world\r\n", b"0\r\n\r\n"], pause=0.05)),
    ("to close", answer(b"HTTP/1.1 200 OK\r\n\r\nto the end")),
    ("stall", stall),
    ("cut", answer(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc")),
    ("huge", answer(b"HTTP/1.1 200 OK\r\nContent-Length: 100000000\r\n\r\n")),
    ("continue", answer([b"HTTP/1.1 100 Continue\r\n\r\n", b"HTTP/1.1 201 Created\r\nContent-Length: 5\r\n\r\nafter"], pause=0.05)),
    ("echo", echo),
    ("garbage", answer(b"HELLO\r\n\r\n")),
    ("big", answer([b"HTTP/1.1 200 OK\r\nContent-Length: 4194304\r\n\r\n", BIG])),
    ("split head", answer([b"HTTP/1.1 404 Not", b" Found\r\nContent-Le", b"ngth: 2\r\n\r\n", b"no"], pause=0.05)),
]


def serve(port, fault):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(16)
    while True:
        conn, _ = s.accept()
        threading.Thread(target=fault, args=(conn,), daemon=True).start()




# Servers that keep connections open, for the pool, retries and redirects
# -----------------------------------------------------------------------

lock = threading.Lock()
conns = {}
tries = {}


def requests(conn):
    """Each request on a kept connection: (method, target, headers, body)."""
    buf = b""
    while True:
        while b"\r\n\r\n" not in buf:
            more = conn.recv(65536)
            if not more:
                return
            buf += more
        head, buf = buf.split(b"\r\n\r\n", 1)
        lines = head.split(b"\r\n")
        method, target, _ = lines[0].split(b" ")
        hs = {}
        for l in lines[1:]:
            k, v = l.split(b":", 1)
            hs[k.strip().lower()] = v.strip()
        n = int(hs.get(b"content-length", b"0"))
        while len(buf) < n:
            more = conn.recv(65536)
            if not more:
                return
            buf += more
        body, buf = buf[:n], buf[n:]
        yield method.decode(), target.decode(), hs, body


def reply(conn, code, body, extra=b""):
    reason = {200: b"OK", 201: b"Created", 301: b"Moved Permanently", 302: b"Found", 303: b"See Other",
              307: b"Temporary Redirect", 308: b"Permanent Redirect", 404: b"Not Found", 503: b"Service Unavailable"}[code]
    conn.sendall(b"HTTP/1.1 " + str(code).encode() + b" " + reason + b"\r\n" + extra
                 + b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)


def keep(conn):
    # answers each request with its connection's number and its own
    with lock:
        conns["keep"] = conns.get("keep", 0) + 1
        me = conns["keep"]
    try:
        for i, (m, t, hs, body) in enumerate(requests(conn)):
            reply(conn, 200, f"conn {me} req {i + 1}".encode())
    except OSError:
        pass
    conn.close()


def one_each(conn):
    # a keep-alive answer, then the connection closes unannounced, as an
    # idle timeout on the server does
    with lock:
        conns["each"] = conns.get("each", 0) + 1
        me = conns["each"]
    try:
        for m, t, hs, body in requests(conn):
            reply(conn, 200, f"{m} on conn {me}".encode())
            time.sleep(0.05)
            break
    except OSError:
        pass
    conn.close()


def flaky(conn):
    # /n/KEY answers 503 n times per KEY, then 200 with how many tries
    try:
        for m, t, hs, body in requests(conn):
            _, n, key = t.split("/")[:3]
            with lock:
                tries[key] = tries.get(key, 0) + 1
                k = tries[key]
            if k <= int(n):
                reply(conn, 503, b"busy")
            else:
                reply(conn, 200, f"{m} after {k} tries".encode())
    except OSError:
        pass
    conn.close()


def redirects(conn):
    try:
        for m, t, hs, body in requests(conn):
            parts = t.split("/")
            if parts[1] == "r":
                reply(conn, int(parts[2]), b"moved", b"Location: /done\r\n")
            elif parts[1] == "loop":
                reply(conn, 302, b"again", b"Location: /loop\r\n")
            elif parts[1] == "abs":
                reply(conn, 302, b"away", b"Location: http://127.0.0.1:7314/done\r\n")
            elif parts[1] == "tls":
                reply(conn, 302, b"to tls", b"Location: https://localhost:7315/\r\n")
            elif parts[1] == "done":
                auth = hs.get(b"authorization", b"-").decode()
                reply(conn, 200, f"{m} /done body={body.decode()} auth={auth}".encode())
            else:
                reply(conn, 404, b"no")
    except OSError:
        pass
    conn.close()


def jsons(conn):
    try:
        for m, t, hs, body in requests(conn):
            if t == "/item":
                reply(conn, 200, b'{"id": 7, "name": "cup"}', b"Content-Type: application/json\r\n")
            elif t == "/bad":
                reply(conn, 200, b"not json")
            elif t == "/echo":
                reply(conn, 201, body, b"Content-Type: application/json\r\n")
            else:
                reply(conn, 404, b'{"error": "no such item"}')
    except OSError:
        pass
    conn.close()


def tls_serve(dirname):
    import ssl
    import subprocess
    cert, key = dirname + "/cert.pem", dirname + "/key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert,
                    "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"],
                   check=True, capture_output=True)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 7315))
    s.listen(16)

    def one(c):
        try:
            t = ctx.wrap_socket(c, server_side=True)
            with lock:
                conns["tls"] = conns.get("tls", 0) + 1
                me = conns["tls"]
            for i, (m, tg, hs, body) in enumerate(requests(t)):
                if tg == "/down":
                    reply(t, 302, b"to http", b"Location: http://127.0.0.1:7314/done\r\n")
                else:
                    reply(t, 200, f"tls conn {me} req {i + 1}".encode())
        except (OSError, ssl.SSLError):
            pass
        c.close()

    while True:
        c, _ = s.accept()
        threading.Thread(target=one, args=(c,), daemon=True).start()


KEPT = [(7311, keep), (7312, one_each), (7313, flaky), (7314, redirects), (7316, jsons)]


# An event stream, for events and events_retry
# --------------------------------------------

def sse_head(conn, ctype=b"text/event-stream", code=b"200 OK"):
    conn.sendall(b"HTTP/1.1 " + code + b"\r\nContent-Type: " + ctype + b"\r\nCache-Control: no-cache\r\n\r\n")


def trickle(conn, data):
    for i in range(len(data)):
        conn.sendall(data[i:i + 1])


def events(conn):
    try:
        head = read_head(conn)
        target = head.split(b" ")[1].decode()
        last = None
        for l in head.split(b"\r\n"):
            if l.lower().startswith(b"last-event-id:"):
                last = l.split(b":", 1)[1].strip().decode()
        accept = b"accept: text/event-stream" in head.lower()
        if target == "/ev":
            sse_head(conn)
            trickle(conn, ("\ufeff: hello\n\nevent: greet\r\ndata: h\u00e9llo \u20ac\r\ndata: line two\r\nid: 1\r\n\r\n"
                           "data: no name\rid: 2\r\r: ping\n\n"
                           "data: carries id 2\n\n"
                           "event: x\ndata\n\n"
                           "data: accept " + ("yes" if accept else "no") + "\n\n").encode())
        elif target == "/stop":
            sse_head(conn)
            n = 0
            while n < 100:
                n += 1
                conn.sendall(f"id: {n}\ndata: {n}\n\n".encode())
                time.sleep(0.02)
        elif target == "/html":
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 2\r\n\r\nhi")
        elif target == "/404":
            conn.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 4\r\n\r\nnope")
        elif target == "/drop":
            sse_head(conn)
            if last is None:
                conn.sendall(b"retry: 50\nid: 1\ndata: one\n\nid: 2\ndata: two\n\n")
            else:
                k = int(last) + 1
                conn.sendall(f"id: {k}\ndata: resumed after {last}\n\n".encode())
        conn.shutdown(socket.SHUT_WR)
        time.sleep(0.2)
    except OSError:
        pass
    conn.close()


KEPT.append((7317, events))

for i, (name, fault) in enumerate(FAULTS):
    threading.Thread(target=serve, args=(BASE + i, fault), daemon=True).start()
for port, fault in KEPT:
    threading.Thread(target=serve, args=(port, fault), daemon=True).start()
if len(sys.argv) > 1:
    threading.Thread(target=tls_serve, args=(sys.argv[1],), daemon=True).start()
    while not os.path.exists(sys.argv[1] + "/key.pem"):
        time.sleep(0.05)
    time.sleep(0.3)
print("ready", flush=True)
threading.Event().wait()
