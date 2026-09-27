"""Fuzz the client's response reader through a real socket, against a reference.

  python3 tests/fuzz.py BINARY N SEED

Serves N connections on 7400 and runs BINARY N, which is tests/fuzz.bend
built: it GETs http://127.0.0.1:7400/ N times and prints one line per
response, "ok CODE LEN SUM" or "err KIND". Each connection gets a random
response, valid or mutated, sent in random pieces, then the close. The
reference parser here, written from http1.bend's rules, says what each line
must be.
"""
import random
import socket
import subprocess
import sys
import threading
import time

BIN = sys.argv[1]
N = int(sys.argv[2]) if len(sys.argv) > 2 else 1000
SEED = int(sys.argv[3]) if len(sys.argv) > 3 else 1
MAX_HEAD = 16384
MAX_BODY = 8388608
BUDGET = 65536 + MAX_BODY


class Bad(Exception):
    pass


class Big(Exception):
    pass


class Short(Exception):
    pass


def ctl(c):
    return (c < 32 or c == 127) and c != 9


def tchar(c):
    return chr(c).isalnum() and c < 128 or c in b"!#$%&'*+-.^_`|~"


def split_head(b, i):
    """The head's lines from i, as split.go cuts them: (lines, next i)."""
    n = 0
    line = bytearray()
    lines = []
    over = False
    while True:
        if over:
            raise Big
        if i >= len(b):
            raise Short
        c = b[i]
        if c == 13:
            if i + 1 >= len(b):
                raise Short
            if b[i + 1] != 10:
                raise Bad
            if not line and lines:
                return lines, i + 2
            if line:
                lines.append(bytes(line))
                line = bytearray()
            n += 2
            over = n > MAX_HEAD
            i += 2
            continue
        if c == 10:
            raise Bad
        line.append(c)
        n += 1
        over = n > MAX_HEAD
        i += 1


def status(first):
    if len(first) < 13 or first[:5] != b"HTTP/" or first[6] != 46 or first[8] != 32 or first[12] != 32:
        raise Bad
    d = first[9:12]
    if not all(48 <= x <= 57 for x in d):
        raise Bad
    if any(ctl(x) for x in first[13:]):
        raise Bad
    return int(d)


def trim(v):
    return v.strip(b" \t")


def fields(lines):
    hs = []
    for l in lines:
        if l[:1] in (b" ", b"\t"):
            raise Bad
        if b":" not in l:
            raise Bad
        name, rest = l.split(b":", 1)
        v = trim(rest)
        if not name or not all(tchar(x) for x in name) or any(ctl(x) for x in v):
            raise Bad
        hs.append((name, v))
    return hs


def framing(hs, code):
    if 100 <= code < 200 or code in (204, 304):
        return ("none",)
    te = [v for n, v in hs if n.lower() == b"transfer-encoding"]
    if te:
        if len(te) == 1 and b"," not in te[0] and trim(te[0]).lower() == b"chunked":
            return ("chunked",)
        raise Bad
    cl = None
    for n, v in hs:
        if n.lower() == b"content-length":
            if not v or not all(48 <= x <= 57 for x in v):
                raise Bad
            k = min(int(v), 4294967295)
            if cl is not None and cl != k:
                raise Bad
            cl = k
    if cl is None:
        return ("close",)
    if cl > MAX_BODY:
        raise Big
    return ("len", cl)


def chunked(b, i):
    """The body from i, as chunks.go reads it, to the end of b (then EOF)."""
    body = bytearray()
    budget = BUDGET
    total = 0
    mode = "size"
    n, anyd, left, fresh = 0, False, 0, True
    while True:
        if i >= len(b):
            raise Short
        c = b[i]
        i += 1
        if mode == "data":
            body.append(c)
            left -= 1
            if left == 0:
                mode = "datacr"
            continue
        if budget == 0:
            raise Big
        budget -= 1
        hexv = int(chr(c), 16) if chr(c) in "0123456789abcdefABCDEF" else None
        if mode == "size":
            if hexv is not None:
                n = 16 * n + hexv
                if n > MAX_BODY:
                    raise Big
                anyd = True
            elif c == 13 and anyd:
                mode = "sizelf"
            elif c == 59 and anyd:
                mode = "ext"
            else:
                raise Bad
        elif mode == "ext":
            if c == 13:
                mode = "sizelf"
            elif c == 10 or ctl(c):
                raise Bad
        elif mode == "sizelf":
            if c != 10:
                raise Bad
            if n == 0:
                mode, fresh = "trail", True
            elif total + n <= MAX_BODY:
                total += n
                mode, left = "data", n
            else:
                raise Big
        elif mode == "datacr":
            if c != 13:
                raise Bad
            mode = "datalf"
        elif mode == "datalf":
            if c != 10:
                raise Bad
            mode, n, anyd = "size", 0, False
        elif mode == "trail":
            if c == 13:
                mode = "traillf"
            elif c == 10:
                raise Bad
            else:
                fresh = False
        elif mode == "traillf":
            if c != 10:
                raise Bad
            if fresh:
                return bytes(body)
            mode, fresh = "trail", True


def reference(b):
    """("ok", code, body) or ("err", kind), for b followed by the close."""
    i = 0
    try:
        for k in range(9):
            lines, i = split_head(b, i)
            code = status(lines[0])
            hs = fields(lines[1:])
            fr = framing(hs, code)
            if 100 <= code < 200 and code != 101 and k < 8:
                continue
            break
        if fr[0] == "none":
            return ("ok", code, b"")
        if fr[0] == "len":
            if len(b) - i < fr[1]:
                raise Short
            return ("ok", code, b[i:i + fr[1]])
        if fr[0] == "close":
            body = b[i:]
            if len(body) > MAX_BODY:
                raise Big
            return ("ok", code, body)
        return ("ok", code, chunked(b, i))
    except Bad:
        return ("err", "bad")
    except Big:
        return ("err", "toolarge")
    except Short:
        return ("err", "closed")


def checksum(body):
    s = 0
    for c in body:
        s = (s * 31 + c) & 0xFFFFFFFF
    return s


def line(r):
    if r[0] == "ok":
        return f"ok {r[1]} {len(r[2])} {checksum(r[2])}"
    return "err " + r[1]


# Random responses
# ----------------

def rbytes(rng, n):
    return bytes(rng.randrange(256) for _ in range(n))


def rtext(rng, n):
    return bytes(rng.choice(b"abcXYZ019 -_.:/;,") for _ in range(n))


def rhex(rng, n):
    h = format(n, "x")
    if rng.random() < 0.2:
        h = h.upper()
    if rng.random() < 0.1:
        h = "0" * rng.randrange(1, 4) + h
    return h.encode()


def body_chunked(rng, body):
    out = b""
    i = 0
    while i < len(body):
        k = rng.randrange(1, max(2, len(body) - i + 1))
        part = body[i:i + k]
        ext = b";x=" + rtext(rng, 3) if rng.random() < 0.15 else b""
        out += rhex(rng, len(part)) + ext + b"\r\n" + part + b"\r\n"
        i += k
    out += rhex(rng, 0)[-1:] + b"\r\n"
    if rng.random() < 0.2:
        out += b"X-Trailer: " + rtext(rng, 5) + b"\r\n"
    return out + b"\r\n"


def response(rng):
    code = rng.choice([200, 200, 200, 201, 204, 301, 304, 404, 500, 101, 100, 103])
    hs = []
    for _ in range(rng.randrange(0, 4)):
        hs.append(rng.choice([b"X-A", b"Server", b"Content-Type", b"Set-Cookie"]) + b": " + rtext(rng, rng.randrange(0, 12)))
    body = rbytes(rng, rng.choice([0, 1, 5, 40, 300, 3000, 70000]))
    kind = rng.choice(["len", "len", "chunked", "chunked", "close"])
    if kind == "len":
        hs.append(b"Content-Length: " + str(len(body)).encode())
        tail = body
    elif kind == "chunked":
        hs.append(rng.choice([b"Transfer-Encoding: chunked", b"transfer-encoding:  Chunked ", b"Transfer-Encoding: chunked"]))
        tail = body_chunked(rng, body)
    else:
        tail = body
    if 100 <= code < 200 or code in (204, 304):
        tail = b""
    rng.shuffle(hs)
    head = b"HTTP/1.1 " + str(code).encode() + b" " + rtext(rng, rng.randrange(0, 8)) + b"\r\n" + b"".join(h + b"\r\n" for h in hs) + b"\r\n"
    out = head + tail
    if code in (100, 103):
        out += response(rng)
    return out


def mutate(rng, b):
    b = bytearray(b)
    for _ in range(rng.randrange(1, 4)):
        if not b:
            b = bytearray(b"\r\n")
        i = rng.randrange(len(b))
        op = rng.randrange(7)
        if op == 0:
            b[i] = rng.randrange(256)
        elif op == 1:
            b.insert(i, rng.choice([13, 10, 32, 9, 58, 59, 48, 102]))
        elif op == 2:
            del b[i]
        elif op == 3:
            b = b[:i]
        elif op == 4:
            b[i:i] = b[i:i + rng.randrange(1, 12)]
        elif op == 5:
            b[i:i] = rng.choice([b"Content-Length: 3\r\n", b"Transfer-Encoding: gzip\r\n", b"Content-Length: 99999999999\r\n", b" folded\r\n"])
        else:
            b[i] = rng.choice(b"0123456789abcdefABCDEF\r\n;: ")
    return bytes(b)


def limits(rng):
    k = rng.randrange(4)
    if k == 0:
        # a head just under or over max_head
        n = MAX_HEAD + rng.randrange(-40, 40)
        pad = b"X-Pad: " + b"p" * max(0, n - 40) + b"\r\n"
        return b"HTTP/1.1 200 OK\r\n" + pad + b"Content-Length: 0\r\n\r\n"
    if k == 1:
        n = MAX_BODY + rng.randrange(-2, 3)
        return b"HTTP/1.1 200 OK\r\nContent-Length: " + str(n).encode() + b"\r\n\r\n" + b"z" * min(n, 10)
    if k == 2:
        n = MAX_BODY + rng.randrange(-2, 3)
        return b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + format(n, "x").encode() + b"\r\n" + b"z" * 10
    # a body read to the close, just under or over max_body
    return b"HTTP/1.1 200 OK\r\n\r\n" + b"q" * (MAX_BODY + rng.randrange(-1, 2))


def case(rng):
    if rng.random() < 0.02:
        return limits(rng)
    b = response(rng)
    if rng.random() < 0.4:
        b = mutate(rng, b)
    if rng.random() < 0.05:
        b = b"\r\n" + b
    return b


def send_chunked(conn, rng, b):
    i = 0
    while i < len(b):
        n = rng.choice([1, 2, 3, 7, 64, 1000, 65536])
        conn.sendall(b[i:i + n])
        i += n
        if rng.random() < 0.02:
            time.sleep(0.001)


def serve(s, rng, want):
    for _ in range(N):
        conn, _ = s.accept()
        conn.settimeout(10)
        try:
            buf = b""
            while b"\r\n\r\n" not in buf:
                more = conn.recv(65536)
                if not more:
                    break
                buf += more
            b = case(rng)
            want.append((b, line(reference(b))))
            send_chunked(conn, rng, b)
            conn.shutdown(socket.SHUT_WR)
            # the client closes once it has what it needs; wait for that
            while conn.recv(65536):
                pass
        except OSError:
            pass
        conn.close()


def main():
    rng = random.Random(SEED)
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 7400))
    s.listen(16)
    want = []
    t = threading.Thread(target=serve, args=(s, rng, want), daemon=True)
    t.start()
    out = subprocess.run([BIN, str(N)], capture_output=True, text=True, timeout=600).stdout.split("\n")
    t.join(10)
    got = [l for l in out if l]
    same = sum(1 for (b, w), g in zip(want, got) if w == g)
    kinds = {}
    for _, w in want:
        k = w.split(" ")[0] + (" " + w.split(" ")[1] if w.startswith("err") else "")
        kinds[k] = kinds.get(k, 0) + 1
    print(f"fuzz: {N} responses, {same} read as the reference does; " + ", ".join(f"{v} {k}" for k, v in sorted(kinds.items())))
    bad = [(b, w, g) for (b, w), g in zip(want, got) if w != g]
    if len(got) != N:
        print(f"  the client printed {len(got)} lines for {N} responses")
    for b, w, g in bad[:5]:
        print("  sent", b[:160], "\n  want", w, "\n  got ", g)
    sys.exit(1 if bad or len(got) != N else 0)


main()
