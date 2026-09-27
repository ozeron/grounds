"""Servers that answer the client's live test, one port each from 7301.

  python3 tests/fake.py        # serves until killed; prints "ready" once listening
"""
import socket
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


for i, (name, fault) in enumerate(FAULTS):
    threading.Thread(target=serve, args=(BASE + i, fault), daemon=True).start()
print("ready", flush=True)
threading.Event().wait()
