"""Fuzz the client's event stream reader through a real socket, against a reference.

  python3 tests/fuzz_events.py BINARY N SEED

Serves N event streams on a run-local URL and runs BINARY N URL, which is
tests/fuzz_events.bend built. Each stream is random lines of fields,
comments and junk, with LF, CR and CRLF endings, sometimes a BOM, sent
chunked or to the close in random pieces that split UTF-8 chars. The
reference parser here, written from the WHATWG event stream rules, says
which events the client must print, and which last id it must end with.
"""
import random
import socket
import sys
import time
from fuzz_harness import run

BIN = sys.argv[1]
N = int(sys.argv[2]) if len(sys.argv) > 2 else 500
SEED = int(sys.argv[3]) if len(sys.argv) > 3 else 1


def reference(text):
    """WHATWG HTML, "Parsing an event stream": the events and the last id."""
    if text.startswith("﻿"):
        text = text[1:]
    out = []
    data, name, buf, last = "", "", None, None
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    # the text after the last line end is not a line yet
    for ln in lines[:-1]:
        if ln == "":
            last = buf
            if data == "":
                name = ""
                continue
            out.append((name or "message", data[:-1] if data.endswith("\n") else data, buf))
            data, name = "", ""
            continue
        if ln.startswith(":"):
            continue
        if ":" in ln:
            f, v = ln.split(":", 1)
            if v.startswith(" "):
                v = v[1:]
        else:
            f, v = ln, ""
        if f == "data":
            data += v + "\n"
        elif f == "event":
            name = v
        elif f == "id":
            if "\0" not in v:
                buf = v
    return out, last


def codes(s):
    return "".join(f"{ord(c)}." for c in s)


def idshow(m):
    return "-" if m is None else "=" + codes(m)


def lines_of(text):
    evs, last = reference(text)
    return [f"ev {codes(n)} {codes(d)} {idshow(i)}" for n, d, i in evs] + [f"end {idshow(last)}"]


CHARS = ["a", "b", "z", "0", "7", " ", "  ", ":", "é", "€", "😀", "\0", "﻿", "data: ", "id:", "\t"]
FIELDS = ["data", "data", "data", "event", "id", "retry", "", "dat", "Data", "data ", "x", "evé"]
ENDS = ["\n", "\n", "\n", "\r", "\r\n"]


def value(rng):
    return "".join(rng.choice(CHARS) for _ in range(rng.randrange(0, 6)))


def stream(rng):
    parts = []
    if rng.random() < 0.1:
        parts.append("﻿")
    for _ in range(rng.randrange(0, 40)):
        k = rng.random()
        end = rng.choice(ENDS)
        if k < 0.25:
            parts.append(end)
        elif k < 0.3:
            parts.append(":" + value(rng) + end)
        else:
            f = rng.choice(FIELDS)
            if f == "retry" and rng.random() < 0.5:
                v = str(rng.randrange(0, 5000))
            else:
                v = value(rng)
            sep = rng.choice([":", ": ", ":  ", ""]) if v or rng.random() < 0.5 else ""
            parts.append(f + sep + v + end)
    if rng.random() < 0.8:
        parts.append("\n\n")
    return "".join(parts)


def send_pieces(conn, rng, b, chunked):
    i = 0
    while i < len(b):
        n = rng.choice([1, 2, 3, 5, 7, 64, 1000])
        piece = b[i:i + n]
        conn.sendall(b"%x\r\n%s\r\n" % (len(piece), piece) if chunked else piece)
        i += n
        if rng.random() < 0.05:
            time.sleep(0.001)
    if chunked:
        conn.sendall(b"0\r\n\r\n")


def serve(connections, rng, want):
    for conn in connections:
        try:
            text = stream(rng)
            want.append((text, lines_of(text)))
            chunked = rng.random() < 0.5
            kind = rng.choice([b"text/event-stream", b"text/event-stream; charset=utf-8"])
            head = b"HTTP/1.1 200 OK\r\nContent-Type: " + kind + b"\r\n"
            head += b"Transfer-Encoding: chunked\r\n\r\n" if chunked else b"Connection: close\r\n\r\n"
            conn.sendall(head)
            send_pieces(conn, rng, text.encode("utf-8"), chunked)
            conn.shutdown(socket.SHUT_WR)
            while conn.recv(65536):
                pass
        except OSError:
            pass


def main():
    rng = random.Random(SEED)
    want, r = run(BIN, N, lambda connections, want: serve(connections, rng, want))
    out = r.stdout.split("\n")
    got = [l for l in out if l]
    # split the client's lines into one group per stream, at each end or err
    groups, cur = [], []
    for l in got:
        cur.append(l)
        if l.startswith("end ") or l.startswith("err "):
            groups.append(cur)
            cur = []
    bad = [(text, w, g) for (text, w), g in zip(want, groups) if w != g]
    events = sum(len(w) - 1 for _, w in want)
    same = sum(w == g for (_, w), g in zip(want, groups))
    print(f"fuzz_events: {N} streams, {events} events, {same} read as the reference does")
    if len(groups) != N:
        print(f"  the client ended {len(groups)} streams of {N}")
    if len(want) != N:
        print(f"  the server served {len(want)} of {N} streams")
    if r.returncode != 0:
        print(f"  the client exited {r.returncode}: {r.stderr.strip()[-300:]}")
    for text, w, g in bad[:5]:
        print("  sent", repr(text[:200]), "\n  want", w, "\n  got ", g)
    sys.exit(1 if bad or cur or len(groups) != N or len(want) != N or r.returncode != 0 else 0)


main()
