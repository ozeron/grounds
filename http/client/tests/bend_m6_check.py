"""M6 live checks: the native Bend HTTP client over Bend TLS against independent
Python TLS peers: framing and smuggling-style responses, redirect chains across
origins, keep-alive reuse by connection count, phase deadlines, and large
streamed bodies with a client memory bound."""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import threading
import time
import zlib

import importlib.util  # noqa: E402

# the client harness shares its module name with the server's; load it by path
_spec = importlib.util.spec_from_file_location("client_bend_tls_check", Path(__file__).resolve().parent / "bend_tls_check.py")
base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(base)

ROOT = base.ROOT
BIG = 4 * 1024 * 1024
CHUNKS = [1, 7, 100, 4096, 16384, 65535, 3, 1000, 32768, 250]


def big_body():
    return b"".join(hashlib.sha256(i.to_bytes(4, "big")).digest() for i in range(BIG // 32))


BODY = big_body()
# the slow upload: 2 MiB, the i-th byte i mod 251 (tests/bend_tls.bend: fill)
UPLOAD = bytes(i % 251 for i in range(2 * 1024 * 1024))


def chunked(data, sizes=CHUNKS):
    out, i, k = [], 0, 0
    while i < len(data):
        n = min(sizes[k % len(sizes)], len(data) - i)
        out.append(b"%x;k=%d\r\n" % (n, k) + data[i:i + n] + b"\r\n")
        i, k = i + n, k + 1
    return b"".join(out) + b"0\r\nX-Trailer: done\r\n\r\n"


def adler(data):
    value = zlib.adler32(data)
    return value & 0xffff, value >> 16


def head(status="200 OK", *lines):
    return ("HTTP/1.1 " + status + "\r\n" + "".join(line + "\r\n" for line in lines) + "\r\n").encode()


# path -> raw response bytes, written as they are; "notify" ends with close_notify
RAW = {
    "/te-cl": head("200 OK", "Content-Length: 3", "Transfer-Encoding: chunked") + b"5\r\nhello\r\n0\r\n\r\n",
    "/cl-conflict": head("200 OK", "Content-Length: 5", "Content-Length: 6") + b"hello!",
    "/cl-list": head("200 OK", "Content-Length: 5, 5") + b"hello",
    "/cl-list-conflict": head("200 OK", "Content-Length: 5, 6") + b"hello!",
    "/cl-dup": head("200 OK", "Content-Length: 5", "Content-Length: 5") + b"hello",
    "/cl-list-dup": head("200 OK", "Content-Length: 5,5", "Content-Length: 5") + b"hello",
    "/cl-list-empty": head("200 OK", "Content-Length: 5,,5") + b"hello",
    "/cl-bad": head("200 OK", "Content-Length: 5x") + b"hello",
    "/cl-plus": head("200 OK", "Content-Length: +5") + b"hello",
    "/te-gzip": head("200 OK", "Transfer-Encoding: gzip, chunked") + b"5\r\nhello\r\n0\r\n\r\n",
    "/te-identity": head("200 OK", "Transfer-Encoding: identity") + b"hello",
    "/te-two": head("200 OK", "Transfer-Encoding: chunked", "Transfer-Encoding: chunked") + b"5\r\nhello\r\n0\r\n\r\n",
    "/chunk-bad-hex": head("200 OK", "Transfer-Encoding: chunked") + b"zz\r\nhello\r\n0\r\n\r\n",
    "/chunk-negative": head("200 OK", "Transfer-Encoding: chunked") + b"-5\r\nhello\r\n0\r\n\r\n",
    "/chunk-no-crlf": head("200 OK", "Transfer-Encoding: chunked") + b"5\r\nhelloXX0\r\n\r\n",
    "/chunk-ext-trailer": head("200 OK", "Transfer-Encoding: chunked") + b"2;a=b;c\r\nhe\r\n3; q=\"x\"\r\nllo\r\n0\r\nX-T: 1\r\nX-U: 2\r\n\r\n",
    "/chunk-huge": head("200 OK", "Transfer-Encoding: chunked") + b"ffffffffffff\r\nhello\r\n",
    "/chunk-over-max": head("200 OK", "Transfer-Encoding: chunked") + chunked(bytes(2048), [512]),
    "/cl-over-max": head("200 OK", "Content-Length: 2048") + bytes(2048),
    "/bare-lf": b"HTTP/1.1 200 OK\nContent-Length: 5\n\nhello",
    "/fold": head("200 OK", "Content-Length: 5", "X-A: a", " b") + b"hello",
    "/space-colon": head("200 OK", "Content-Length : 5") + b"hello",
    "/nul-header": head("200 OK", "Content-Length: 5", "X-A: a\x00b") + b"hello",
    "/head-big": head("200 OK", "Content-Length: 5", "X-Big: " + "a" * 20000) + b"hello",
    "/head-300": head("200 OK", "Content-Length: 5", "X-Big: " + "a" * 300) + b"hello",
    "/101": head("101 Switching Protocols", "Upgrade: websocket", "Connection: Upgrade"),
    "/100-continue": head("100 Continue") + head("200 OK", "Content-Length: 2") + b"ok",
    "/eight-1xx": head("103 Early Hints", "Link: </x>") * 8 + head("200 OK", "Content-Length: 2") + b"ok",
    "/nine-1xx": head("103 Early Hints", "Link: </x>") * 9 + head("200 OK", "Content-Length: 2") + b"ok",
    "/status-999": head("999 Nope", "Content-Length: 2") + b"ok",
    "/status-099": head("099 Nope", "Content-Length: 2") + b"ok",
    "/status-short": b"HTTP/1.1 200\r\nContent-Length: 2\r\n\r\nok",
    "/204-cl": head("204 No Content", "Content-Length: 5"),
    "/304-te": head("304 Not Modified", "Transfer-Encoding: chunked"),
    "/extra-bytes": head("200 OK", "Content-Length: 2") + b"okXYZ",
}
# path -> (raw bytes, end): end "notify" sends close_notify after the bytes
CLOSING = {
    "/close-delimited": (head("200 OK") + b"to the close", "notify"),
    "/close-over-max": (head("200 OK") + bytes(2048), "notify"),
    "/cl-truncated": (head("200 OK", "Content-Length: 10") + b"hello", "notify"),
    "/chunk-truncated": (head("200 OK", "Transfer-Encoding: chunked") + b"a\r\nhello", "notify"),
    "/close-hdr": (head("200 OK", "Content-Length: 5", "Connection: close") + b"hello", "notify"),
}


class M6Peer(base.Peer):
    def do_DELETE(self):
        self.do_GET()

    def do_HEAD(self):
        self.record(b"")
        if self.path == "/head-cl":
            self.connection.sendall(head("200 OK", "Content-Length: 100"))
        else:
            self.connection.sendall(head("200 OK", "Content-Length: 5"))

    def record(self, body):
        self.server.requests.append(dict(path=self.path, method=self.command, body=body.hex(),
                                         headers=list(self.headers.items()), connection=self.client_address))

    def send(self, status, headers=(), content=b""):
        self.send_response(status)
        self.send_header("Content-Length", str(len(content)))
        for key, value in headers:
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(content)

    def redirect(self, status, location):
        self.send(status, [("Location", location)])

    def slow_upload(self):
        # read the first MiB slowly (64 KiB per 50 ms, so at least 800 ms):
        # the client's writes block on a full window while each read still
        # makes progress. The rest is read at once, so the response follows
        # the end of the upload well within read_ms
        digest, left, slow = hashlib.sha256(), int(self.headers.get("content-length", "0")), 1024 * 1024
        while left:
            piece = self.rfile.read(min(65536, left))
            if not piece:
                break
            digest.update(piece)
            left -= len(piece)
            slow -= len(piece)
            if slow > 0:
                time.sleep(0.05)
        self.server.requests.append(dict(path=self.path, method=self.command, body_sha256=digest.hexdigest(),
                                         headers=list(self.headers.items()), connection=self.client_address))
        self.send(200, [], b"hello")

    def do_GET(self):
        if self.path == "/upload-slow":
            return self.slow_upload()
        body = self.rfile.read(int(self.headers.get("content-length", "0")))
        self.record(body)
        path, server = self.path, self.server
        names = {k.lower() for k in self.headers.keys()}
        auth = "authorization" in names and "cookie" in names
        try:
            if path in RAW:
                self.connection.sendall(RAW[path])
            elif path in CLOSING:
                data, _ = CLOSING[path]
                self.connection.sendall(data)
                try:
                    self.connection.unwrap().close()
                except (ssl.SSLError, OSError):
                    pass
                self.close_connection = True
            elif path == "/head-cl":
                self.send(200, [], b"h" * 100)
            elif path == "/big-chunked":
                self.connection.sendall(head("200 OK", "Transfer-Encoding: chunked") + chunked(BODY))
            elif path == "/big-cl":
                self.send(200, [], BODY)
            # the stalls: a client with a read deadline hangs up during
            # them, so never wait for another request on the connection
            elif path == "/slow-head":
                self.close_connection = True
                time.sleep(1.0)
                self.send(200, [], b"hello")
            elif path == "/slow-body":
                self.close_connection = True
                self.connection.sendall(head("200 OK", "Content-Length: 5") + b"he")
                time.sleep(1.0)
                self.connection.sendall(b"llo")
            elif path == "/drip":
                self.connection.sendall(head("200 OK", "Content-Length: 20"))
                for _ in range(20):
                    time.sleep(0.1)
                    self.connection.sendall(b"d")
            elif path == "/sse-stall":
                self.close_connection = True
                self.connection.sendall(head("200 OK", "Content-Type: text/event-stream", "Transfer-Encoding: chunked")
                                        + b"9\r\ndata: a\n\n\r\n")
                time.sleep(1.0)
                self.connection.sendall(b"9\r\ndata: b\n\n\r\n0\r\n\r\n")
            elif path == "/503":
                self.send(503, [], b"")
            elif path == "/headers":
                items = self.headers.items()
                lowered = [k.lower() for k, _ in items]
                assert ("X-Ok", "1") in items and ("X-Tab", "a\tb") in items, items
                assert not {"bad name", "x-ctl", "x", "x-del", "transfer-encoding", "transfer-encoding "} & set(lowered), items
                assert self.headers.get_all("host") == [f"localhost:{server.server_port}"], items
                assert body == b"hi", body
                self.send(200, [], b"hello")
            elif path == "/frag":
                self.send(200, [], b"hello")
            # a chain: same origin relative, then network-path to another origin, then ../
            elif path == "/chain/a":
                assert auth, self.headers.items()
                self.redirect(301, "b?x=1")
            elif path == "/chain/b?x=1":
                assert auth, self.headers.items()
                self.redirect(302, f"//localhost:{server.other_port}/chain/c#frag")
            elif path == "/chain/c":
                assert not ({"authorization", "cookie"} & names), self.headers.items()
                self.redirect(307, "../chain/d")
            elif path == "/chain/d":
                assert not ({"authorization", "cookie"} & names), self.headers.items()
                self.send(200, [], b"chain")
            elif path == "/abs-same":
                self.redirect(302, f"https://LOCALHOST:{server.server_port}/needs-auth")
            elif path == "/needs-auth":
                assert auth, self.headers.items()
                self.send(200, [], b"hello")
            elif path in {"/p301", "/p302", "/p303"}:
                self.redirect(int(path[2:]), "/landing")
            elif path == "/landing":
                assert self.command == "GET" and body == b"", (self.command, body)
                assert not ({"content-type", "content-language", "content-length"} & names), self.headers.items()
                assert auth, self.headers.items()
                self.send(200, [], b"hello")
            elif path in {"/p307", "/p308"}:
                self.redirect(int(path[2:]), "/echo-post")
            elif path == "/p308-cross":
                self.redirect(308, f"https://127.0.0.1:{server.other_port}/echo-post-cross")
            elif path in {"/echo-post", "/echo-post-cross"}:
                assert self.command == "POST" and json.loads(body) == {"name": "cup"}, (self.command, body)
                assert self.headers["content-type"] == "application/json", self.headers.items()
                assert self.headers["content-language"] == "en", self.headers.items()
                assert auth == (path == "/echo-post"), self.headers.items()
                assert "authorization" not in names or path == "/echo-post", self.headers.items()
                self.send(200, [], b"hello")
            elif path == "/d307":
                self.redirect(307, "/del-landing")
            elif path == "/del-landing":
                assert self.command == "DELETE" and body == b"gone", (self.command, body)
                assert "authorization" in names
                self.send(200, [], b"hello")
            elif path == "/loop":
                self.redirect(302, "/loop")
            elif path == "/down":
                self.redirect(302, f"http://localhost:{server.server_port}/")
            elif path == "/mailto":
                self.redirect(302, "mailto:a@example.com")
            elif path == "/xo":
                self.redirect(302, f"https://localhost:{server.other_port}/xo-final")
            elif path == "/xo-final":
                self.send(200, [], b"hello")
            # credentials across origins, through network-path and absolute
            # Locations with dot segments
            elif path == "/pa":
                self.redirect(302, f"//localhost:{server.other_port}/x/../pa-final")
            elif path == "/pa-abs":
                self.redirect(302, f"https://localhost:{server.other_port}/y/./z/../../pa-final?q=/../k")
            elif path in {"/pa-final", "/pa-final?q=/../k"}:
                assert not ({"authorization", "cookie", "proxy-authorization"} & names), self.headers.items()
                self.send(200, [], b"hello")
            elif path == "/pa-same":
                self.redirect(302, "/pa-same-final")
            elif path == "/pa-same-final":
                assert {"authorization", "cookie", "proxy-authorization"} <= names, self.headers.items()
                self.send(200, [], b"hello")
            else:
                return self.fallback(body)
        except (ssl.SSLError, OSError):
            # the client may hang up first (a deadline, a limit); what it
            # printed is checked, and assertions above still fail the case
            self.close_connection = True

    def fallback(self, body):
        if self.path == "/stale":
            self.send(200, [], b"hello")
            self.close_connection = True
        else:
            self.send(200, [], b"hello")


@contextmanager
def peer(directory):
    server = base.Server(("127.0.0.1", 0), M6Peer)
    server.requests, server.errors, server.sni, server.other_port = [], [], {}, None
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(directory / "ecdsa.pem", directory / "ecdsa.key")
    context.set_alpn_protocols(["http/1.1"])
    server.context = context
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        yield server
        assert not server.errors, server.errors
    finally:
        server.shutdown()
        server.server_close()
        thread.join(3)
        assert not thread.is_alive()


@contextmanager
def peers(directory):
    with peer(directory) as a, peer(directory) as b:
        a.other_port, b.other_port = b.server_port, a.server_port
        yield a, b


def run(binary, directory, url, mode):
    """The client's output lines, elapsed seconds and peak RSS (bytes)."""
    now = int(datetime.now(timezone.utc).timestamp()) + base.CIVIL_OFFSET
    command = [str(binary), str(ROOT / "crypto/unicode32_nfkc.bin"), str(ROOT / "crypto/unicode32_prepare.bin"),
               str(directory / "ca.pem"), str(now), url, mode]
    start = time.monotonic()
    process = subprocess.Popen(command, env=dict(os.environ, **base.POISON), stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True)
    timer = threading.Timer(30, process.kill)
    timer.start()
    try:
        out, err = [], []
        reader = threading.Thread(target=lambda: err.append(process.stderr.read()))
        reader.start()
        out.append(process.stdout.read())
        reader.join()
        _, status, usage = os.wait4(process.pid, 0)
        process.returncode = os.waitstatus_to_exitcode(status)
    finally:
        timer.cancel()
        process.stdout.close()
        process.stderr.close()
    elapsed = time.monotonic() - start
    assert process.returncode == 0, (command, process.returncode, out, err)
    rss = usage.ru_maxrss if sys.platform == "darwin" else usage.ru_maxrss * 1024
    return out[0].strip().splitlines(), elapsed, rss


def connections(server, start):
    return len({r["connection"] for r in server.requests[start:]})


def framing(binary, directory, rows):
    cases = [
        ("/te-cl", "get", ["ok:200:5"]),
        ("/te-cl", "pool2", ["ok:200:5"] * 2),
        ("/cl-conflict", "get", ["error:bad response"]),
        ("/cl-list", "get", ["ok:200:5"]),
        ("/cl-list", "pool2", ["ok:200:5"] * 2),
        ("/cl-list-conflict", "get", ["error:bad response"]),
        ("/cl-dup", "get", ["ok:200:5"]),
        ("/cl-list-dup", "get", ["ok:200:5"]),
        ("/cl-list-empty", "get", ["error:bad response"]),
        ("/cl-bad", "get", ["error:bad response"]),
        ("/cl-plus", "get", ["error:bad response"]),
        ("/te-gzip", "get", ["error:bad response"]),
        ("/te-identity", "get", ["error:bad response"]),
        ("/te-two", "get", ["error:bad response"]),
        ("/chunk-bad-hex", "get", ["error:bad response"]),
        ("/chunk-negative", "get", ["error:bad response"]),
        ("/chunk-no-crlf", "get", ["error:bad response"]),
        ("/chunk-ext-trailer", "get", ["ok:200:5"]),
        ("/chunk-huge", "get", ["error:response too large"]),
        ("/chunk-over-max", "small", ["error:response too large"]),
        ("/cl-over-max", "small", ["error:response too large"]),
        ("/close-over-max", "small", ["error:response too large"]),
        ("/close-delimited", "get", ["ok:200:12"]),
        ("/cl-truncated", "get", ["error:closed"]),
        ("/chunk-truncated", "get", ["error:closed"]),
        ("/bare-lf", "get", ["error:bad response"]),
        ("/fold", "get", ["error:bad response"]),
        ("/space-colon", "get", ["error:bad response"]),
        ("/nul-header", "get", ["error:bad response"]),
        ("/head-big", "get", ["error:response too large"]),
        ("/head-300", "small-head", ["error:response too large"]),
        ("/head-300", "get", ["ok:200:5"]),
        ("/101", "get", ["error:bad response"]),
        ("/101", "stream", ["error:bad response"]),
        ("/100-continue", "get", ["ok:200:2"]),
        ("/eight-1xx", "get", ["ok:200:2"]),
        ("/nine-1xx", "get", ["error:bad response"]),
        ("/status-999", "get", ["error:bad response"]),
        ("/status-099", "get", ["error:bad response"]),
        ("/status-short", "get", ["error:bad response"]),
        ("/204-cl", "pool2", ["ok:204:0"] * 2),
        ("/304-te", "get", ["ok:304:0"]),
        ("/head-cl", "pool-head", ["ok:200:0", "ok:200:100"]),
        ("/extra-bytes", "pool2", ["ok:200:2"] * 2),
        ("/close-hdr", "pool2", ["ok:200:5"] * 2),
        ("/headers", "headers", ["ok:200:5"]),
        ("/frag#section?x", "get", ["ok:200:5"]),
        ("/ua", "get", ["ok:200:5"]),
        ("/ua", "pool2", ["ok:200:5"] * 2),
        ("/ua", "stream", ["part:68656c6c6f", "ok:200"]),
        ("/ua", "ua-custom", ["ok:200:5"]),
        ("/ua", "ua-none", ["ok:200:5"]),
        ("/ua", "ua-set", ["ok:200:5"]),
    ]
    # how many connections a pooled case must use: reuse only when allowed
    reuse = {"/te-cl": 2, "/204-cl": 1, "/head-cl": 1, "/extra-bytes": 2, "/close-hdr": 2, "/cl-list": 1, "/ua": 1}
    # the User-Agent values each request carried: the default unless the
    # caller set one or turned it off
    agents = {"get": ["grounds-bend"], "pool2": ["grounds-bend"], "stream": ["grounds-bend"],
              "ua-custom": ["mine/1"], "ua-none": [], "ua-set": ["probe/2"]}
    with peer(directory) as server:
        url = f"https://localhost:{server.server_port}"
        for path, mode, expected in cases:
            start = len(server.requests)
            output, elapsed, _ = run(binary, directory, url + path, mode)
            assert output == expected, (path, mode, output, expected)
            seen = server.requests[start:]
            if mode in {"pool2", "pool-head"}:
                assert connections(server, start) == reuse[path], (path, seen)
            if path.startswith("/frag"):
                assert [r["path"] for r in seen] == ["/frag"], seen
            if path == "/ua":
                for r in seen:
                    got = [v for k, v in r["headers"] if k.lower() == "user-agent"]
                    assert got == agents[mode], (mode, r["headers"])
            rows.append(dict(name=path + ":" + mode, output=output, requests=len(seen),
                             connections=connections(server, start), elapsed_seconds=elapsed))
            print(path, mode, "passed", flush=True)


def redirects(binary, directory, rows):
    with peers(directory) as (a, b):
        url = f"https://localhost:{a.server_port}"
        cases = [
            ("/chain/a", "auth", ["ok:200:5"], ["/chain/a", "/chain/b?x=1"], ["/chain/c", "/chain/d"]),
            ("/abs-same", "auth", ["ok:200:5"], ["/abs-same", "/needs-auth"], []),
            ("/p303", "post", ["ok:200:5"], ["/p303", "/landing"], []),
            ("/p302", "post", ["ok:200:5"], ["/p302", "/landing"], []),
            ("/p301", "post", ["ok:200:5"], ["/p301", "/landing"], []),
            ("/p307", "post", ["ok:200:5"], ["/p307", "/echo-post"], []),
            ("/p308", "post", ["ok:200:5"], ["/p308", "/echo-post"], []),
            ("/p308-cross", "post", ["ok:200:5"], ["/p308-cross"], ["/echo-post-cross"]),
            ("/d307", "delete", ["ok:200:5"], ["/d307", "/del-landing"], []),
            ("/loop", "get", ["error:too many redirects"], ["/loop"] * 6, []),
            ("/down", "get", ["ok:302:0"], ["/down"], []),
            ("/mailto", "get", ["ok:302:0"], ["/mailto"], []),
            ("/xo", "noredirect", ["ok:302:0"], ["/xo"], []),
            ("/pa", "proxy-auth", ["ok:200:5"], ["/pa"], ["/pa-final"]),
            ("/pa-abs", "proxy-auth", ["ok:200:5"], ["/pa-abs"], ["/pa-final?q=/../k"]),
            ("/pa-same", "proxy-auth", ["ok:200:5"], ["/pa-same", "/pa-same-final"], []),
        ]
        for path, mode, expected, on_a, on_b in cases:
            sa, sb = len(a.requests), len(b.requests)
            output, elapsed, _ = run(binary, directory, url + path, mode)
            assert output == expected, (path, mode, output, expected)
            got_a = [r["path"] for r in a.requests[sa:]]
            got_b = [r["path"] for r in b.requests[sb:]]
            assert (got_a, got_b) == (on_a, on_b), (path, got_a, got_b)
            rows.append(dict(name=path + ":" + mode, output=output, origin_a=got_a, origin_b=got_b, elapsed_seconds=elapsed))
            print(path, mode, "passed", flush=True)


def pool(binary, directory, rows):
    with peers(directory) as (a, b):
        url = f"https://localhost:{a.server_port}"
        # path, mode, output, connections on a, on b
        cases = [
            ("/", "pool10", ["ok:200:5"] * 10, 1, 0),
            ("/", "pool-idle", ["ok:200:5"] * 2, 2, 0),
            ("/xo", "pool3w", ["ok:200:5"] * 3, 1, 1),
            ("/close-hdr", "pool2", ["ok:200:5"] * 2, 2, 0),
            ("/head-cl", "pool-head", ["ok:200:0", "ok:200:100"], 1, 0),
        ]
        for path, mode, expected, ca, cb in cases:
            sa, sb = len(a.requests), len(b.requests)
            output, elapsed, _ = run(binary, directory, url + path, mode)
            assert output == expected, (path, mode, output, expected)
            assert (connections(a, sa), connections(b, sb)) == (ca, cb), (path, a.requests[sa:], b.requests[sb:])
            if mode == "pool3w":
                assert len(a.requests) - sa == 3 and len(b.requests) - sb == 3
            rows.append(dict(name=path + ":" + mode, output=output, requests_a=len(a.requests) - sa,
                             connections_a=ca, connections_b=cb, elapsed_seconds=elapsed))
            print(path, mode, "passed", flush=True)
        # a stale kept connection: GET is fine, and the POST that follows on it
        # fails rather than being sent again, since it is not idempotent
        sa = len(a.requests)
        output, elapsed, _ = run(binary, directory, url + "/stale", "pool-post")
        assert output[0] == "ok:200:5" and len(output) == 2 and output[1].startswith("error:"), output
        assert [r["method"] for r in a.requests[sa:]] == ["GET"], a.requests[sa:]
        rows.append(dict(name="/stale:pool-post", output=output, elapsed_seconds=elapsed))
        print("/stale pool-post passed", flush=True)


def elapsed_ms(output):
    lines = [line for line in output if line.startswith("elapsed:")]
    assert len(lines) == 1, output
    return int(lines[0].split(":")[1])


def deadlines(binary, directory, rows):
    silent = socket.socket()
    silent.bind(("127.0.0.1", 0))
    silent.listen(8)  # never accepts: TCP completes, TLS never answers
    try:
        with peer(directory) as server:
            url = f"https://localhost:{server.server_port}"
            cases = [
                ("connect-stall", f"https://localhost:{silent.getsockname()[1]}/", "connect-timeout", "error:timeout", 400, 1500),
                ("connect-ok", url + "/", "connect-timeout", "ok:200:5", 0, 1500),
                ("head-stall", url + "/slow-head", "read-timeout", "error:timeout", 250, 900),
                ("body-stall", url + "/slow-body", "read-timeout", "error:timeout", 250, 900),
                ("body-stall-total-only", url + "/slow-body", "timed", "ok:200:5", 900, 2900),
                ("head-stall-total-only", url + "/slow-head", "timed", "ok:200:5", 900, 2900),
                ("drip-total", url + "/drip", "total-timeout", "error:timeout", 700, 1400),
                ("drip-ok", url + "/drip", "read-timeout", "ok:200:20", 1900, 2950),
                # read_ms applies to streamed reads, one-shot and pooled
                ("stream-head-stall", url + "/slow-head", "stream-read", "error:timeout", 250, 900),
                ("stream-body-stall", url + "/slow-body", "stream-read", "error:timeout", 250, 900),
                ("pool-stream-body-stall", url + "/slow-body", "pool-stream-read", "error:timeout", 250, 900),
                ("stream-drip-ok", url + "/drip", "stream-read", "ok:200", 1900, 2950),
                # read_ms never bounds a write: a 2 MiB upload the peer reads
                # slowly takes well over 300 ms and still succeeds
                ("upload-slow", url + "/upload-slow", "upload", "ok:200:5", 700, 9000),
                ("pool-upload-slow", url + "/upload-slow", "pool-upload", "ok:200:5", 700, 9000),
                # backoff never runs past the total deadline: 5 s backoff,
                # 800 ms total, so the 503 is the answer at once; with room,
                # both retries run (100 + 200 ms)
                ("retry-budget", url + "/503", "retry-budget", "ok:503:0", 0, 500),
                ("pool-retry-budget", url + "/503", "pool-retry-budget", "ok:503:0", 0, 500),
                ("retry-fits", url + "/503", "retry-fits", "ok:503:0", 280, 1500),
                # a pool of one held by a 2 s stream: a GET with a 400 ms
                # total deadline gives up waiting for it
                ("pool-saturated", url + "/drip", "pool-saturated", "error:timeout", 300, 900),
            ]
            # the peer's receive window stays small, so a slow reader makes
            # the client's writes wait
            server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
            tries = {"retry-budget": 1, "pool-retry-budget": 1, "retry-fits": 3}
            for name, target, mode, expected, low, high in cases:
                start = len(server.requests)
                output, elapsed, _ = run(binary, directory, target, mode)
                ms = elapsed_ms(output)
                assert output[0] == expected and low <= ms <= high, (name, output, low, high)
                seen = server.requests[start:]
                if name in tries:
                    assert [r["path"] for r in seen] == ["/503"] * tries[name], (name, seen)
                if name.endswith("upload-slow"):
                    assert [r.get("body_sha256") for r in seen] == [hashlib.sha256(UPLOAD).hexdigest()], (name, seen)
                if name == "pool-saturated":
                    # the stream that held the connection still ends well,
                    # and the GET that gave up was never sent
                    assert output[-1] == "ok:200" and [r["path"] for r in seen] == ["/drip"], (output, seen)
                rows.append(dict(name=name, output=output, elapsed_ms=ms, bounds_ms=[low, high], process_seconds=elapsed))
                print(name, "passed", ms, "ms", flush=True)
            # events: the first event, then the 1 s stall is a read timeout
            for mode in ("events-read", "pool-events-read"):
                output, elapsed, _ = run(binary, directory, url + "/sse-stall", mode)
                assert len(output) == 2 and output[0].startswith("event:") and output[0].split(":")[2] == "a" \
                    and output[1] == "error:timeout", (mode, output)
                rows.append(dict(name="sse-stall:" + mode, output=output, process_seconds=elapsed))
                print("sse-stall", mode, "passed", flush=True)
    finally:
        silent.close()


def stream(binary, directory, rows):
    with peer(directory) as server:
        url = f"https://localhost:{server.server_port}"
        base_out, _, base_rss = run(binary, directory, url + "/", "get")
        assert base_out == ["ok:200:5"], base_out
        rows.append(dict(name="baseline", output=base_out, max_rss_bytes=base_rss))
        whole = "ok:200:%d:%d:%d" % ((len(BODY),) + adler(BODY))
        for path in ("/big-chunked", "/big-cl"):
            output, elapsed, rss = run(binary, directory, url + path, "stream-sum")
            assert output[-1] == "ok:200", output[-3:]
            offset = 0
            for line in output[:-1]:
                _, n, x, y = line.split(":")
                n = int(n)
                assert n > 0 and adler(BODY[offset:offset + n]) == (int(x), int(y)), (path, offset, line)
                offset += n
            assert offset == len(BODY), (path, offset)
            # streamed, never held: the client grows by less than the body
            # itself over a 5-byte GET (held, it takes about 100 MiB)
            assert rss - base_rss < len(BODY), (path, rss, base_rss)
            rows.append(dict(name=path + ":stream", pieces=len(output) - 1, bytes=offset, max_rss_bytes=rss,
                             baseline_rss_bytes=base_rss, elapsed_seconds=elapsed))
            print(path, "stream passed", len(output) - 1, "pieces", rss // 1048576, "MiB", flush=True)
        output, elapsed, rss = run(binary, directory, url + "/big-chunked", "sum")
        assert output == [whole], (output, whole)
        rows.append(dict(name="/big-chunked:buffered", output=output, max_rss_bytes=rss, elapsed_seconds=elapsed))
        print("/big-chunked buffered passed", rss // 1048576, "MiB", flush=True)
        output, _, _ = run(binary, directory, url + "/big-chunked", "small")
        assert output == ["error:response too large"], output
        rows.append(dict(name="/big-chunked:small", output=output))
        print("/big-chunked small passed", flush=True)


# IPv6 (M6 item 3): a peer bound on ::1 with an IPv6 iPAddress SAN, URLs with
# bracketed literals in compressed and expanded forms, no SNI for a literal,
# Host with brackets, a missing IPv6 SAN refused, pooled reuse by canonical
# origin, redirects (same origin written differently keeps credentials; a
# redirect to a name is cross-origin and re-verified with SNI), and the
# dual-stack name localhost reaching an IPv6-only and an IPv4-only peer (the
# second after ::1 refuses). On macOS, a .local name that multicast DNS
# takes about 5 s to give up on is cut off by the connect deadline.
LEAF6 = "ipv6.pem"
SLOW_NAME = "grounds-nonexistent-q7.local"


def ipv6_leaf(directory):
    """A synthetic leaf for the same synthetic CA and key: DNS:localhost,
    IP:127.0.0.1 and IP:::1. Never a production key."""
    if (directory / LEAF6).exists():
        return
    openssl = os.environ.get("OPENSSL", "openssl")
    ext = directory / "leaf6.cnf"
    ext.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                   "extendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1\n"
                   "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n")
    subprocess.run([openssl, "req", "-new", "-key", str(directory / "ecdsa.key"), "-out", str(directory / "ipv6.csr"),
                    "-subj", "/CN=synthetic IPv6 SAN-only test leaf", "-sha256"], check=True, capture_output=True)
    subprocess.run([openssl, "x509", "-req", "-in", str(directory / "ipv6.csr"), "-CA", str(directory / "ca.pem"),
                    "-CAkey", str(directory / "ca.key"), "-set_serial", "106", "-days", "7", "-sha256",
                    "-extfile", str(ext), "-out", str(directory / LEAF6)], check=True, capture_output=True)


class V6Peer(base.Peer):
    def do_GET(self):
        port = self.server.server_port
        if self.path in ("/v6-redirect", "/v6-cross"):
            self.rfile.read(int(self.headers.get("content-length", "0")))
            self.server.requests.append(dict(path=self.path, headers=dict(self.headers), connection=self.client_address,
                                             sni=self.server.sni.get(self.connection.fileno())))
            target = f"https://[0:0:0:0:0:0:0:1]:{port}/v6-final" if self.path == "/v6-redirect" \
                else f"https://localhost:{port}/v6-final"
            self.send_response(302)
            self.send_header("Location", target)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        super().do_GET()


class Server6(base.Server):
    address_family = socket.AF_INET6


@contextmanager
def peer_on(directory, host, credential):
    server = (Server6 if ":" in host else base.Server)((host, 0), V6Peer)
    server.requests, server.errors, server.sni = [], [], {}
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(directory / credential, directory / "ecdsa.key")
    context.set_alpn_protocols(["http/1.1"])
    context.set_servername_callback(lambda sock, name, _: server.sni.__setitem__(sock.fileno(), name))
    server.context = context
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        yield server
        assert not server.errors, server.errors
    finally:
        server.shutdown()
        server.server_close()
        thread.join(3)
        assert not thread.is_alive()


def free_on(host, port):
    """Whether nothing listens on host:port (so a connect there is refused)."""
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family) as s:
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False


def ipv6(binary, directory, rows):
    ipv6_leaf(directory)
    names = sorted({a[4][0] for a in socket.getaddrinfo("localhost", 443, 0, socket.SOCK_STREAM)})
    assert "::1" in names and "127.0.0.1" in names, ("localhost must be dual-stack for these cases", names)

    def case(name, url, mode, check, server=None):
        start = len(server.requests) if server else 0
        output, elapsed, _ = run(binary, directory, url, mode)
        seen = server.requests[start:] if server else []
        check(output, seen)
        rows.append(dict(name=name, url=url, mode=mode, output=output, requests=len(seen),
                         peers=[r["connection"][0] for r in seen], sni=[r.get("sni") for r in seen],
                         elapsed_seconds=elapsed))
        print(name, "passed", flush=True)

    def host_is(value):
        return lambda r: [hdr(x, "host") for x in r] == [value]

    with peer_on(directory, "::1", LEAF6) as s6:
        port = s6.server_port
        lit = f"https://[::1]:{port}"
        case("literal", lit + "/", "get", lambda o, r: (o == ["ok:200:5"] and host_is(f"[::1]:{port}")(r)
             and r[0]["sni"] is None and r[0]["connection"][0] == "::1") or fail(o, r), s6)
        case("literal-expanded", f"https://[0:0:0:0:0:0:0:1]:{port}/", "get",
             lambda o, r: (o == ["ok:200:5"] and host_is(f"[::1]:{port}")(r) and r[0]["sni"] is None) or fail(o, r), s6)
        case("literal-uppercase-zeros", f"https://[0000:0:0::0001]:{port}/?q=1", "get",
             lambda o, r: (o == ["ok:200:5"] and r[0]["path"] == "/?q=1" and host_is(f"[::1]:{port}")(r)) or fail(o, r), s6)
        case("pool-reuse", lit + "/", "pool2",
             lambda o, r: (o == ["ok:200:5", "ok:200:5"] and len({x["connection"] for x in r}) == 1) or fail(o, r), s6)
        case("redirect-same-origin-canonical", lit + "/v6-redirect", "auth",
             lambda o, r: (o == ["ok:200:5"] and [x["path"] for x in r] == ["/v6-redirect", "/v6-final"]
                           and hdr(r[1], "authorization") == "secret"
                           and hdr(r[1], "host") == f"[::1]:{port}") or fail(o, r), s6)
        case("redirect-to-name-cross-origin", lit + "/v6-cross", "auth",
             lambda o, r: (o == ["ok:200:5"] and [x["path"] for x in r] == ["/v6-cross", "/v6-final"]
                           and hdr(r[1], "authorization") is None and r[1]["sni"] == "localhost"
                           and hdr(r[1], "host") == f"localhost:{port}") or fail(o, r), s6)
        case("dual-stack-name-to-v6-only", f"https://localhost:{port}/", "get",
             lambda o, r: (o == ["ok:200:5"] and r[0]["connection"][0] == "::1" and r[0]["sni"] == "localhost") or fail(o, r), s6)
        assert free_on("127.0.0.1", port), port

    with peer_on(directory, "::1", "ecdsa.pem") as s6:
        case("literal-without-ipv6-san", f"https://[::1]:{s6.server_port}/", "get",
             lambda o, r: (o == ["error:tls:certificate:identity-mismatch"] and r == []) or fail(o, r), s6)

    with peer_on(directory, "127.0.0.1", LEAF6) as s4:
        port = s4.server_port
        assert free_on("::1", port), port
        case("dual-stack-name-to-v4-only-falls-back", f"https://localhost:{port}/", "connect-timeout",
             lambda o, r: (o[0] == "ok:200:5" and r[0]["connection"][0] == "127.0.0.1" and elapsed_ms(o) < 1500) or fail(o, r), s4)
        case("literal-v4-still", f"https://127.0.0.1:{port}/", "get",
             lambda o, r: (o == ["ok:200:5"] and r[0]["sni"] is None) or fail(o, r), s4)

    for name, url in [("zone-id", "https://[fe80::1%25lo0]:443/"), ("zone-id-raw", "https://[::1%lo0]:443/"),
                      ("unbracketed", "https://::1/"), ("unclosed", "https://[::1/"), ("dotted-tail", "https://[::ffff:127.0.0.1]/")]:
        case("malformed-" + name, url, "get",
             lambda o, r: o == ["error:bad url: want http[s]://host[:port][/path]"] or fail(o, r))

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        closed = probe.getsockname()[1]
    if free_on("::1", closed):
        case("dual-stack-name-nothing-listening", f"https://localhost:{closed}/", "get",
             lambda o, r: (len(o) == 1 and o[0].startswith("error:connection failed: errno ")) or fail(o, r))

    if sys.platform == "darwin":
        case("dns-deadline", f"https://{SLOW_NAME}/", "connect-timeout",
             lambda o, r: (o[0] == "error:timeout" and 400 <= elapsed_ms(o) <= 1500) or fail(o, r))
        assert rows[-1]["elapsed_seconds"] < 3.0, rows[-1]
    else:
        rows.append(dict(name="dns-deadline", skipped="needs macOS multicast DNS for a slow lookup"))


def hdr(request, name):
    values = [v for k, v in request["headers"].items() if k.lower() == name]
    assert len(values) <= 1, (name, request)
    return values[0] if values else None


def fail(output, seen):
    raise AssertionError((output, seen))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--fixtures", type=Path, required=True)
    p.add_argument("--report", type=Path, required=True)
    p.add_argument("--mode", choices=["framing", "redirects", "pool", "deadlines", "stream", "ipv6"], required=True)
    args = p.parse_args()
    rows = []
    started = time.monotonic()
    report = dict(target="native", mode=args.mode, results=rows, synthetic_keys_only=True,
                  client_sha256=hashlib.sha256(args.binary.read_bytes()).hexdigest())
    try:
        dict(framing=framing, redirects=redirects, pool=pool, deadlines=deadlines, stream=stream, ipv6=ipv6)[args.mode](
            args.binary, args.fixtures, rows)
        report["passed"] = True
    except BaseException as error:
        report.update(passed=False, error=repr(error))
        raise
    finally:
        report["elapsed_seconds"] = time.monotonic() - started
        args.report.write_text(json.dumps(report, indent=2, default=str) + "\n")
        print(json.dumps(dict(passed=report.get("passed", False), scenarios=len(rows), report=str(args.report))))


if __name__ == "__main__":
    main()
