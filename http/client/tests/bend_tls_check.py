"""Native Bend HTTP client against independent TLS HTTP peers and Bend server."""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import http.server
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "wire"))
sys.path.insert(0, str(ROOT / "http/server/examples"))
from bend_tls_client_check import CIVIL_OFFSET, free_port, record, fixture
from bend_tls_check import server as bend_server, POISON


class Peer(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def do_POST(self):
        self.do_GET()

    def do_GET(self):
        body = self.rfile.read(int(self.headers.get("content-length", "0")))
        self.server.requests.append(dict(path=self.path, body=body.hex(), headers=dict(self.headers),
                                         connection=self.client_address, sni=self.server.sni.get(self.connection.fileno())))
        status, headers, content = 200, {}, b"hello"
        if self.path == "/json":
            assert json.loads(body) == {"name": "cup"}, body
            content = b'{"name":"cup"}'
        elif self.path == "/form":
            assert body == b"q=a+b&n=2", body
            assert self.headers["content-type"] == "application/x-www-form-urlencoded"
            content = b"form ok"
        elif self.path == "/stream":
            content = bytes(range(256)) * 1024
        elif self.path in {"/redirect", "/redirect-bad"}:
            status = 302
            host = "127.0.0.1"
            headers["Location"] = f"https://{host}:{self.server.server_port}/final"
            content = b""
        elif self.path == "/final":
            assert self.headers.get("authorization") is None and self.headers.get("cookie") is None
            content = b"reverified"
        elif self.path == "/slow":
            time.sleep(.5)
        elif self.path == "/events":
            headers["Content-Type"] = "text/event-stream"
            content = b"id: 7\ndata: hello\n\n"
        elif self.path == "/retry":
            headers["Content-Type"] = "text/event-stream"
            last = self.headers.get("last-event-id")
            assert last in (None, "7"), last
            content = b"id: 7\nretry: 1\ndata: hello\n\n" if last is None else b"id: 8\ndata: stop\n\n"
        if self.path == "/bare":
            self.connection.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nhello")
            self.close_connection = True  # deliberate TCP EOF without close_notify
            return
        if self.path == "/notify":
            self.connection.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nhello")
            try:
                self.connection.unwrap().close()
            except (ssl.SSLError, OSError):
                pass
            self.close_connection = True
            return
        try:
            self.send_response(status)
            self.send_header("Content-Length", str(len(content)))
            for key, value in headers.items():
                self.send_header(key, value)
            self.end_headers()
            # Split data across TLS records and arbitrary HTTP body boundaries.
            for start in range(0, len(content), 7919):
                self.wfile.write(content[start:start + 7919])
            if self.path == "/stale":
                self.close_connection = True  # deliberately omit Connection: close
        except (ssl.SSLError, OSError):
            if self.path != "/slow":
                raise


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def get_request(self):
        raw, address = self.socket.accept()
        raw.settimeout(5)
        try:
            return self.context.wrap_socket(raw, server_side=True), address
        except BaseException:
            raw.close()
            raise

    def handle_error(self, request, address):
        self.errors.append(sys.exception())


@contextmanager
def peer(directory, credential="ecdsa"):
    server = Server(("127.0.0.1", 0), Peer)
    server.requests, server.errors, server.sni = [], [], {}
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(directory / (credential + ".pem"), directory / "ecdsa.key")
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


def client(binary, directory, url, mode="get", ca="ca.pem", now=None):
    now = now or int(datetime.now(timezone.utc).timestamp()) + CIVIL_OFFSET
    command = [str(binary), str(ROOT / "crypto/unicode32_nfkc.bin"),
               str(ROOT / "crypto/unicode32_prepare.bin"), str(directory / ca), str(now), url, mode]
    result = subprocess.run(command, env=dict(os.environ, **POISON), capture_output=True, text=True, timeout=12)
    assert result.returncode == 0, (command, result.returncode, result.stdout, result.stderr)
    lines = result.stdout.strip().splitlines()
    if mode in {"stream", "pool-stream"} and lines[-1:] == ["ok:200"]:
        assert all(line.startswith("part:") for line in lines[:-1]), lines
        body = b"".join(bytes.fromhex(line[5:]) for line in lines[:-1])
        return [f"ok:200:{len(body)}:{hashlib.sha256(body).hexdigest()}"]
    return lines


@contextmanager
def altered(upstream_port, truncate=False):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(8)
    sockets, workers, errors, mutations = [], [], [], []

    def pump(source, target, mutate):
        try:
            while data := record(source):
                if mutate and data[0] == 23 and not mutations:
                    mutations.append(True)
                    if truncate:
                        target.sendall(data[:8])
                        target.shutdown(socket.SHUT_WR)
                        return
                    data = data[:-1] + bytes([data[-1] ^ 1])
                target.sendall(data)
        except (OSError, EOFError):
            pass
        except BaseException as error:
            errors.append(repr(error))
        finally:
            try:
                target.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    def accept():
        try:
            downstream, _ = listener.accept()
            sockets.append(downstream)
            upstream = socket.create_connection(("127.0.0.1", upstream_port), timeout=8)
            sockets.append(upstream)
            for source, target, mutate in [(downstream, upstream, False), (upstream, downstream, True)]:
                worker = threading.Thread(target=pump, args=(source, target, mutate))
                workers.append(worker)
                worker.start()
        except BaseException as error:
            errors.append(repr(error))

    thread = threading.Thread(target=accept)
    thread.start()
    try:
        yield listener.getsockname()[1], mutations
    finally:
        listener.close()
        for sock in sockets:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()
        thread.join(9)
        for worker in workers:
            worker.join(3)
        assert not thread.is_alive() and not any(w.is_alive() for w in workers)
        assert not errors, errors


def ordinary(binary, directory, rows):
    with peer(directory) as server:
        url = f"https://localhost:{server.server_port}"
        for path, mode, expected in [
            ("/", "get", ["ok:200:5"]), ("/", "pool", ["ok:200:5"] * 3),
            ("/stale", "pool", ["ok:200:5"] * 3),
            ("/json", "json", ["json:cup"]), ("/form", "form", ["ok:200:7"]),
            ("/stream", "stream", ["ok:200:262144:" + hashlib.sha256(bytes(range(256)) * 1024).hexdigest()]), ("/stream", "pool-stream", ["ok:200:262144:" + hashlib.sha256(bytes(range(256)) * 1024).hexdigest()]),
            ("/redirect", "get", ["ok:200:10"]),
            ("/events", "events", ["event:message:hello:7", "ended:7:0"]),
            ("/retry", "events-retry", ["event:message:hello:7", "event:message:stop:8", "ended:8:1"]),
            ("/retry", "pool-events", ["event:message:hello:7", "event:message:stop:8", "ended:8:1"]),
        ]:
            start = len(server.requests)
            output = client(binary, directory, url + path, mode)
            assert output == expected, (path, mode, output, expected)
            requests = server.requests[start:]
            if mode == "pool":
                assert len(requests) == 3
                assert len({r["connection"] for r in requests}) == (3 if path == "/stale" else 1)
            assert requests[0]["sni"] == "localhost", requests
            if path == "/redirect":
                assert len(requests) == 2 and requests[1]["sni"] is None, requests
            rows.append(dict(name=path + ":" + mode, output=output, requests=requests))
            print(path, mode, "passed", flush=True)


def negative(binary, directory, rows):
    with peer(directory, "dns") as server:
        url = f"https://localhost:{server.server_port}"
        cases = [
            ("wrong-ca", url, "get", "other.pem", None, "error:tls:certificate:wrong-issuer"),
            ("wrong-host", f"https://127.0.0.1:{server.server_port}", "get", "ca.pem", None, "error:tls:certificate:identity-mismatch"),
            ("expired", url, "get", "ca.pem", int(time.time()) + CIVIL_OFFSET + 86400 * 100, "error:tls:certificate:expired"),
            ("redirect-host-reverified", url + "/redirect-bad", "get", "ca.pem", None, "error:tls:certificate:identity-mismatch"),
            ("response-deadline", url + "/slow", "timeout", "ca.pem", None, "error:timeout"),
            ("truncated-close-body", url + "/bare", "get", "ca.pem", None, "error:tls:truncated"),
            ("authenticated-close-body", url + "/notify", "get", "ca.pem", None, "ok:200:5"),
        ]
        for name, target, mode, ca, now, expected in cases:
            output = client(binary, directory, target, mode, ca, now)
            assert output == [expected], (name, output, expected)
            rows.append(dict(name=name, output=output))
            print(name, "passed", flush=True)
        for truncate, expected in [(False, "error:tls:bad-record-mac"), (True, "error:tls:truncated")]:
            with altered(server.server_port, truncate) as (port, mutations):
                output = client(binary, directory, f"https://localhost:{port}/")
                assert output == [expected] and mutations == [True], (output, mutations)
                rows.append(dict(name="truncated-record" if truncate else "tampered-record", output=output, mutations=1))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path)
    p.add_argument("--fixtures", type=Path, required=True)
    p.add_argument("--report", type=Path, required=True)
    p.add_argument("--mode", choices=["prepare", "ordinary", "negative", "bend", "openssl", "go"], required=True)
    p.add_argument("--server", type=Path)
    p.add_argument("--go", type=Path)
    args = p.parse_args()
    rows = []
    started = time.monotonic()
    report = dict(target="native", results=rows, synthetic_keys_only=True,
                  client_sha256=hashlib.sha256(args.binary.read_bytes()).hexdigest() if args.binary else None)
    try:
        if args.mode == "prepare":
            args.fixtures.mkdir(parents=True, exist_ok=True)
            openssl = os.environ.get("OPENSSL", "openssl")
            fixture(args.fixtures, openssl)
            extensions = args.fixtures / "dns.cnf"
            extensions.write_text((args.fixtures / "leaf.cnf").read_text().replace("DNS:localhost,IP:127.0.0.1", "DNS:localhost"))
            subprocess.run([openssl, "x509", "-req", "-in", str(args.fixtures / "ecdsa.csr"),
                "-CA", str(args.fixtures / "ca.pem"), "-CAkey", str(args.fixtures / "ca.key"),
                "-set_serial", "103", "-days", "7", "-sha256", "-extfile", str(extensions),
                "-out", str(args.fixtures / "dns.pem")], check=True, capture_output=True, timeout=15)
            report["fixture_sha256"] = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in args.fixtures.glob("*.pem")}
        elif args.mode == "ordinary":
            ordinary(args.binary, args.fixtures, rows)
        elif args.mode == "negative":
            negative(args.binary, args.fixtures, rows)
        elif args.mode == "bend":
            for suite in ("aes", "chacha"):
                with bend_server([str(args.server)], args.fixtures, "ecdsa", suite) as (port, process):
                    url = f"https://localhost:{port}"
                    for path, mode, expected in [("/", "get", ["ok:200:7"]), ("/", "pool", ["ok:200:7"] * 3),
                                                 ("/echo", "form", [f"ok:200:{len(b'q=a+b&n=2')}"]), ("/stream", "stream", ["ok:200:13:" + hashlib.sha256(b"first\nsecond\n").hexdigest()])]:
                        output = client(args.binary, args.fixtures, url + path, mode)
                        assert output == expected, (suite, path, output, expected)
                        rows.append(dict(name=suite + path + mode, output=output))
        elif args.mode == "go":
            process = subprocess.Popen([str(args.go), "server", str(args.fixtures / "ecdsa.pem"), str(args.fixtures / "ecdsa.key")], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                port = int(process.stdout.readline().strip().split(":")[-1])
                output = client(args.binary, args.fixtures, f"https://localhost:{port}/", "pool")
                assert output == ["ok:200:7"] * 3, output
                rows.append(dict(name="go-https-keepalive", output=output))
            finally:
                process.terminate()
                process.wait(3)
                process.stdout.close()
                process.stderr.close()
        elif args.mode == "openssl":
            port = free_port()
            process = subprocess.Popen([os.environ.get("OPENSSL", "openssl"), "s_server", "-accept", f"127.0.0.1:{port}",
                "-cert", str(args.fixtures / "ecdsa.pem"), "-key", str(args.fixtures / "ecdsa.key"),
                "-tls1_3", "-alpn", "http/1.1", "-www", "-quiet"], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            try:
                time.sleep(.15)
                output = client(args.binary, args.fixtures, f"https://localhost:{port}/")
                assert len(output) == 1 and output[0].startswith("ok:200:") and int(output[0].split(":")[-1]) > 100
                rows.append(dict(name="openssl-s_server", output=output))
            finally:
                process.terminate()
                process.wait(3)
                process.stderr.close()
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
