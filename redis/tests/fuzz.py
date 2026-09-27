"""Fuzz the RESP parser through a real socket, against a reference parser.

  python3 tests/fuzz.py N SEED     # serves N cases on 7100, then prints a verdict

For each connection, fuzz.bend sends FUZZ. The server answers with a random
reply: valid, or mutated. It sends it in random chunks, then closes its side.
The client either parses a reply and sends GOT with that reply re-encoded
(R.write), or its connection goes down. The reference parser here decides
which must happen, and what GOT must hold, byte for byte.
"""
import random
import socket
import sys
import threading
import time

N = int(sys.argv[1]) if len(sys.argv) > 1 else 1000
SEED = int(sys.argv[2]) if len(sys.argv) > 2 else 1
MAX = 67108864  # the client's default max_reply

# Replies: (kind, value)


def text(b):
    # R.text: UTF-8, cut where a bad sequence starts
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError as e:
        return b[:e.start].decode("utf-8")


class Incomplete(Exception):
    pass


class Refused(Exception):
    pass


def line(b, i):
    j = i
    while True:
        if j >= len(b):
            raise Incomplete
        c = b[j]
        if c == 13:
            if j + 1 >= len(b):
                raise Incomplete
            if b[j + 1] == 10:
                return b[i:j], j + 2
            raise Refused("bare CR")
        if c == 10:
            raise Refused("bare LF")
        j += 1


def digits_ok(d):
    return bool(d) and all(48 <= c <= 57 for c in d)


class Big(Exception):
    pass


def num(l):
    # a length: more than ten digits is too large, whatever their value
    neg = l[:1] == b"-"
    d = l[1:] if neg else l
    if not digits_ok(d):
        return None
    if len(d) > 10:
        raise Refused("too large")
    return neg, int(d)


AGG = {ord("*"): "arr", ord("%"): "map", ord("~"): "set", ord(">"): "push", ord("|"): "attr"}
BULK = {ord("$"): "bulk", ord("!"): "bulkerr", ord("="): "verb"}


def parse_value(b, i):
    """One value at i: (value, next i). Attributes are read and dropped."""
    while True:
        if i >= len(b):
            raise Incomplete
        t = b[i]
        l, j = line(b, i + 1)
        if t == ord("+"):
            return ("simple", text(l)), j
        if t == ord("-"):
            return ("error", text(l)), j
        if t == ord(":") or t == ord("("):
            d = l[1:] if l[:1] == b"-" else l
            if not digits_ok(d):
                raise Refused("bad integer")
            return ("int" if t == ord(":") else "big", l.decode()), j
        if t == ord("_"):
            if l:
                raise Refused("bad null")
            return ("nil", None), j
        if t == ord("#"):
            if l == b"t":
                return ("bool", True), j
            if l == b"f":
                return ("bool", False), j
            raise Refused("bad boolean")
        if t == ord(","):
            return ("double", text(l)), j
        if t in BULK:
            n = num(l)
            if n == (True, 1):
                return ("nil", None), j
            if n is None or n[0]:
                raise Refused("bad bulk length")
            ln = n[1]
            if ln > MAX:
                raise Refused("too large")
            if j + ln > len(b):
                raise Incomplete
            body = b[j:j + ln]
            k = j + ln
            rest = b[k:k + 2]
            if len(rest) == 0 or rest == b"\r":
                raise Incomplete
            if rest != b"\r\n":
                raise Refused("bulk not ended by CR LF")
            kind = BULK[t]
            if kind == "verb":
                if len(body) >= 4 and body[3] == 58:
                    return ("verb", (text(body[:3]), body[4:])), k + 2
                return ("verb", ("", body)), k + 2
            return (kind, body), k + 2
        if t in AGG:
            n = num(l)
            if n == (True, 1):
                return ("nil", None), j
            if n is None or n[0]:
                raise Refused("bad aggregate length")
            cnt = n[1]
            if cnt > MAX:
                raise Refused("too large")
            kind = AGG[t]
            items = cnt * 2 if kind in ("map", "attr") else cnt
            vals = []
            for _ in range(items):
                v, j = parse_value(b, j)
                vals.append(v)
            if kind == "attr":
                i = j
                continue
            return (kind, vals), j
        raise Refused("unknown type")


def reference(b):
    """The reply the client must hand over, or None when it must go down."""
    i = 0
    try:
        while True:
            v, i = parse_value(b, i)
            if v[0] != "push":
                return v
    except (Incomplete, Refused, RecursionError):
        return None


def write(v):
    k, x = v
    if k == "simple":
        return b"+" + x.encode() + b"\r\n"
    if k == "error":
        return b"-" + x.encode() + b"\r\n"
    if k in ("int", "big"):
        return (b":" if k == "int" else b"(") + x.encode() + b"\r\n"
    if k == "nil":
        return b"_\r\n"
    if k == "bool":
        return b"#t\r\n" if x else b"#f\r\n"
    if k == "double":
        return b"," + x.encode() + b"\r\n"
    if k == "bulk":
        return b"$" + str(len(x)).encode() + b"\r\n" + x + b"\r\n"
    if k == "bulkerr":
        return b"!" + str(len(x)).encode() + b"\r\n" + x + b"\r\n"
    if k == "verb":
        f, d = x
        body = f.encode() + b":" + d
        return b"=" + str(len(body)).encode() + b"\r\n" + body + b"\r\n"
    head = {"arr": b"*", "map": b"%", "set": b"~", "push": b">"}[k]
    n = len(x) // 2 if k == "map" else len(x)
    return head + str(n).encode() + b"\r\n" + b"".join(write(y) for y in x)


# Random replies, as bytes


def rbytes(rng, n):
    return bytes(rng.randrange(256) for _ in range(n))


def rtext(rng):
    return "".join(rng.choice("abcXYZ019 :-_.€é") for _ in range(rng.randrange(0, 12))).encode()


def gen(rng, depth=0):
    r = rng.randrange(17 if depth < 3 else 11)
    if r == 0:
        return b"+" + rtext(rng) + b"\r\n"
    if r == 1:
        return b"-ERR " + rtext(rng) + b"\r\n"
    if r == 2:
        return b":" + rng.choice([b"", b"-"]) + str(rng.randrange(10 ** rng.randrange(1, 25))).encode() + b"\r\n"
    if r == 3:
        d = rbytes(rng, rng.randrange(0, 40))
        return b"$" + str(len(d)).encode() + b"\r\n" + d + b"\r\n"
    if r == 4:
        return rng.choice([b"$-1\r\n", b"*-1\r\n", b"_\r\n"])
    if r == 5:
        return rng.choice([b"#t\r\n", b"#f\r\n"])
    if r == 6:
        return b"," + rng.choice([b"3.14", b"-0.5", b"inf", b"-inf", b"nan", b"1e10"]) + b"\r\n"
    if r == 7:
        return b"(" + rng.choice([b"", b"-"]) + str(rng.randrange(10 ** 30)).encode() + b"\r\n"
    if r == 8:
        d = rtext(rng)
        return b"!" + str(len(d)).encode() + b"\r\n" + d + b"\r\n"
    if r == 9:
        d = rng.choice([b"txt", b"mkd"]) + b":" + rtext(rng)
        return b"=" + str(len(d)).encode() + b"\r\n" + d + b"\r\n"
    if r == 10:
        return b"$0\r\n\r\n"
    n = rng.randrange(0, 4)
    if r in (11, 12):
        return b"*" + str(n).encode() + b"\r\n" + b"".join(gen(rng, depth + 1) for _ in range(n))
    if r == 13:
        return b"%" + str(n).encode() + b"\r\n" + b"".join(gen(rng, depth + 1) + gen(rng, depth + 1) for _ in range(n))
    if r == 14:
        return b"~" + str(n).encode() + b"\r\n" + b"".join(gen(rng, depth + 1) for _ in range(n))
    if r == 15:
        return b">" + str(n + 1).encode() + b"\r\n" + b"+message\r\n" + b"".join(gen(rng, depth + 1) for _ in range(n)) + gen(rng, depth + 1)
    return b"|1\r\n+ttl\r\n:3\r\n" + gen(rng, depth + 1)


def mutate(rng, b):
    b = bytearray(b)
    for _ in range(rng.randrange(1, 4)):
        op = rng.randrange(6)
        if not b:
            b = bytearray(b"\r\n")
        i = rng.randrange(len(b))
        if op == 0:
            b[i] = rng.randrange(256)
        elif op == 1:
            b.insert(i, rng.choice([13, 10, 36, 42, 45, 48, 57]))
        elif op == 2:
            del b[i]
        elif op == 3:
            b = b[:i]
        elif op == 4:
            b[i:i] = b[i:i + rng.randrange(1, 8)]
        else:
            b[i] = rng.choice(b"$*%~>|_#,(!=+-:0123456789\r\n")
    return bytes(b)


def case(rng):
    b = gen(rng)
    if rng.random() < 0.35:
        b = mutate(rng, b)
    if rng.random() < 0.1:
        b = b + gen(rng)
    return b


def send_chunked(conn, rng, b):
    i = 0
    while i < len(b):
        n = rng.choice([1, 1, 2, 3, 7, 64, 4096])
        conn.sendall(b[i:i + n])
        i += n
        if rng.random() < 0.05:
            time.sleep(0.001)


def read_command(conn, buf):
    # a whole command: *N then N bulk strings; returns (args, rest) or None
    while True:
        try:
            v, i = parse_value(buf, 0)
            return [a[1] for a in v[1]], buf[i:]
        except Incomplete:
            pass
        more = conn.recv(65536)
        if not more:
            return None
        buf += more


def main():
    rng = random.Random(SEED)
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 7100))
    s.listen(16)
    print("ready", flush=True)
    good = bad = downs = 0
    fails = []
    for n in range(N):
        conn, _ = s.accept()
        conn.settimeout(10)
        got = read_command(conn, b"")
        b = case(rng)
        want = reference(b)
        # GOT is read while the reply is still going out: a client may parse
        # its reply, send GOT and close before the last bytes are sent
        box = []

        def reader():
            try:
                box.append(read_command(conn, b""))
            except OSError:
                box.append(None)

        t = threading.Thread(target=reader)
        t.start()
        try:
            send_chunked(conn, rng, b)
            conn.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        t.join(15)
        got = box[0] if box else None
        conn.close()
        if want is None and got is None:
            downs += 1
        elif want is not None and got is not None and got[0][1] == write(want):
            good += 1
        else:
            bad += 1
            if len(fails) < 5:
                fails.append((b, want and write(want), got and got[0][1]))
    print(f"fuzz: {N} cases, {good} parsed as the reference, {downs} went down as it did, {bad} differ")
    for b, w, g in fails:
        print("  sent", b[:120], "\n  want", w and w[:120], "\n  got ", g and g[:120])
    sys.exit(1 if bad else 0)


main()
