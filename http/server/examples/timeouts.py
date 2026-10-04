"""Timeout checks against a running examples/hello server on PORT, whose
Config is the default: idle 5 s, request 10 s. The three run at once."""
import socket
import sys
import threading
import time

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
results = {}


def until_closed(s, limit):
    s.settimeout(limit)
    out = b""
    t = time.monotonic()
    try:
        while True:
            c = s.recv(4096)
            if not c:
                return out, time.monotonic() - t
            out += c
    except socket.timeout:
        return None, time.monotonic() - t
    except ConnectionResetError:
        # closed with bytes unread: the kernel resets, and may drop the 408
        return out + b"reset", time.monotonic() - t


def idle():
    s = socket.create_connection(("127.0.0.1", PORT))
    results["idle"] = until_closed(s, 15)


def half_head():
    s = socket.create_connection(("127.0.0.1", PORT))
    s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n")
    results["half head"] = until_closed(s, 20)


def trickle():
    s = socket.create_connection(("127.0.0.1", PORT))
    t = time.monotonic()
    results["trickle"] = None
    try:
        for b in b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\n" + b"x" * 100:
            s.sendall(bytes([b]))
            time.sleep(0.5)
            if time.monotonic() - t > 20:
                break
    except OSError:
        results["trickle"] = (b"reset", time.monotonic() - t)
    if results["trickle"] is None:
        out, _ = until_closed(s, 5)
        results["trickle"] = (out, time.monotonic() - t)


ts = [threading.Thread(target=f) for f in (idle, half_head, trickle)]
for x in ts:
    x.start()
for x in ts:
    x.join()

# name: (want in the answer, the least and most seconds to close)
# idle must close with nothing sent; the trickle may see its 408 or a reset
want = {"idle": (b"", 4, 7), "half head": (b"408 Request Timeout", 9, 12), "trickle": (b"", 9, 13)}
bad = False
for name, (w, lo, hi) in want.items():
    out, secs = results[name]
    ok = out is not None and w in out and lo <= secs <= hi and (name != "idle" or out == b"")
    print(f"{name}: closed after {secs:.1f}s{', ' + out[:30].decode(errors='replace') if out else ''}{'' if ok else '  FAIL'}")
    bad = bad or not ok
sys.exit(1 if bad else 0)
