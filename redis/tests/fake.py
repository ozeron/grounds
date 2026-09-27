"""A misbehaving Redis for faults.bend: one port per fault.

  python3 tests/fake.py        # serves until killed; prints "ready" once listening

Each port reads a command, then answers the way its fault says.
"""
import socket
import sys
import threading
import time

BASE = 7001


def reply_after_read(conn, data, close=True, chunk=None, delay=0.0):
    try:
        conn.recv(65536)
        if chunk:
            for i in range(0, len(data), chunk):
                conn.sendall(data[i:i + chunk])
                time.sleep(delay)
        else:
            conn.sendall(data)
        if close:
            conn.shutdown(socket.SHUT_WR)
            time.sleep(0.5)
    except OSError:
        pass
    finally:
        conn.close()


def stall(conn):
    conn.recv(65536)
    time.sleep(30)
    conn.close()


def flood(conn):
    conn.recv(65536)
    try:
        # a simple string that never ends: only the byte cap stops it
        conn.sendall(b"+")
        while True:
            conn.sendall(b"x" * 65536)
    except OSError:
        pass
    conn.close()


def no_read(conn):
    time.sleep(30)
    conn.close()


def error_then_pong(conn):
    try:
        conn.recv(65536)
        conn.sendall(b"-ERR wrong kind\r\n")
        conn.recv(65536)
        conn.sendall(b"+PONG\r\n")
        time.sleep(0.5)
    except OSError:
        pass
    conn.close()


def two_in_one(conn):
    # both replies in one write: the second must be kept for the next command
    try:
        conn.recv(65536)
        conn.sendall(b"+FIRST\r\n+SECOND\r\n")
        conn.recv(65536)
        time.sleep(0.5)
    except OSError:
        pass
    conn.close()


def one_then_close(conn):
    # a server that restarts after every reply: a pool must reconnect
    try:
        conn.recv(65536)
        conn.sendall(b"+PONG\r\n")
    except OSError:
        pass
    conn.close()


def sized(conn):
    # with max_reply 1000: 984 bytes of body fit, 1000 do not
    try:
        conn.recv(65536)
        conn.sendall(b"$984\r\n" + b"a" * 984 + b"\r\n")
        conn.recv(65536)
        conn.sendall(b"$1000\r\n" + b"b" * 1000 + b"\r\n")
        time.sleep(0.5)
    except OSError:
        pass
    conn.close()


def push_between(conn):
    # two pipelined commands, a push between their replies
    try:
        buf = b""
        while buf.count(b"PING") < 2:
            more = conn.recv(65536)
            if not more:
                break
            buf += more
        conn.sendall(b"+A\r\n>2\r\n+message\r\n+x\r\n+B\r\n")
        time.sleep(0.5)
    except OSError:
        pass
    conn.close()


def close_now(conn):
    conn.close()


FAULTS = [
    ("stall", stall),
    ("half", lambda c: reply_after_read(c, b"$10\r\nhello")),
    ("huge", lambda c: reply_after_read(c, b"$100000000\r\n" + b"x" * 1000)),
    ("flood", flood),
    ("garbage", lambda c: reply_after_read(c, b"?what\r\n")),
    ("trickle", lambda c: reply_after_read(c, b"$20\r\n" + b"y" * 20 + b"\r\n", chunk=1, delay=0.1)),
    ("no_read", no_read),
    ("push", lambda c: reply_after_read(c, b">2\r\n+message\r\n+hi\r\n+OK\r\n")),
    ("split", lambda c: reply_after_read(c, b"*2\r\n$5\r\nhello\r\n:42\r\n", chunk=1, delay=0.002)),
    ("error", error_then_pong),
    ("two", two_in_one),
    ("restart", one_then_close),
    ("sized", sized),
    ("push between", push_between),
    ("close on accept", close_now),
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
