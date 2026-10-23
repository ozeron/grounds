"""Verified HTTPS against the real Bend HTTP example (synthetic keys only)."""
import argparse
from contextlib import contextmanager
import hashlib
import http.client
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "wire"))
from bend_tls_client_check import fixture, free_port, SUITES

KEY = "m4a-synthetic-runtime-key"
VALUE = "m4a.synthetic.session"
POISON = dict(BEND_LIBSSL="/nonexistent/m4a-libssl", GROUNDS_TLS_CA="/nonexistent/m4a-host-ca")


def run(argv, **kwargs):
    command = list(map(str, argv))
    result = subprocess.run(command, capture_output=True, timeout=25, **kwargs)
    if result.returncode:
        raise AssertionError(dict(command=command, exit=result.returncode,
                                  stdout=result.stdout.decode(errors="replace"),
                                  stderr=result.stderr.decode(errors="replace")))
    return result


def curl_binary():
    # Apple's system curl can lack TLS 1.3. Prefer the installed peer with that
    # feature, while permitting an explicit executable on other platforms.
    candidates = [os.environ.get("GROUNDS_CURL"), "/opt/homebrew/opt/curl/bin/curl",
                  "/usr/local/opt/curl/bin/curl", shutil.which("curl")]
    return next((value for value in candidates if value and Path(value).is_file()), None)


def context(directory, wrong=False):
    ctx = ssl.create_default_context(cafile=str(directory / ("other.pem" if wrong else "ca.pem")))
    ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.set_alpn_protocols(["http/1.1"])
    return ctx


@contextmanager
def server(binary, directory, credential, suite, **settings):
    port = free_port()
    env = dict(os.environ, **POISON, PORT=str(port), HTTP_TLS_ENGINE="bend",
               HTTP_TLS_CERT=str(directory / (credential + ".pem")),
               HTTP_TLS_KEY=str(directory / (credential + ".key")),
               HTTP_COOKIE_KEY=KEY, HTTP_BEND_TLS_SUITE=suite,
               HTTP_IDLE_MS="3000", HTTP_REQUEST_MS="10000", HTTP_DRAIN_MS="3000")
    env.update({key: str(value) for key, value in settings.items()})
    process = subprocess.Popen(binary, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 15
        while True:
            if process.poll() is not None:
                raise AssertionError(("server exited before listening", process.communicate()))
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=.1):
                    break
            except OSError:
                if time.monotonic() >= deadline:
                    raise TimeoutError("server listen")
                time.sleep(.03)
        yield port, process
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(3)
        process.stdout.close()
        process.stderr.close()


def tls_socket(port, directory):
    peer = context(directory).wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=12), server_hostname="localhost")
    peer.settimeout(12)
    return peer


def request(port, directory, path="/", body=None, headers=None, method="GET"):
    conn = http.client.HTTPSConnection("localhost", port, context=context(directory), timeout=12)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        response = conn.getresponse()
        return response.status, response.read(), dict(response.getheaders())
    finally:
        conn.close()


def response(peer, method="GET"):
    res = http.client.HTTPResponse(peer, method=method)
    res.begin()
    body = res.read()
    return res.status, body, dict(res.getheaders())


def assert_response(value, status, body=None):
    assert value[0] == status, value
    if body is not None:
        assert value[1] == body, (value[0], len(value[1]), value[1][:100])


def ordinary(binary, directory, credential, suite, go, legacy, rows):
    expected_suite, suite_name = SUITES[suite]
    with server(binary, directory, credential, suite) as (port, process):
        url = f"https://localhost:{port}"
        curl = curl_binary()
        assert curl
        curl_version = run([curl, "--version"]).stdout.decode().splitlines()[0]
        base = [curl, "--silent", "--show-error", "--fail", "--http1.1", "--tlsv1.3", "--tls-max", "1.3", "--cacert", directory / "ca.pem", "--max-time", "15"]
        assert run(base + [url + "/"]).stdout == b"secure\n"
        payload = bytes(range(256)) * 800
        assert run(base + ["-X", "POST", "--data-binary", "@-", url + "/echo"], input=payload).stdout == payload
        assert run(base + [url + "/stream"]).stdout == b"first\nsecond\n"
        rows.append(dict(name="curl-get-post-stream", client="curl", requests=3, bytes=len(payload), suite=suite_name, version=curl_version))

        conn = http.client.HTTPSConnection("localhost", port, context=context(directory), timeout=15)
        try:
            first = None
            for method, path, body, expected in [("GET", "/", None, b"secure\n"), ("POST", "/echo", payload, payload), ("GET", "/stream", None, b"first\nsecond\n")]:
                conn.request(method, path, body=body)
                res = conn.getresponse()
                assert res.status == 200 and res.read() == expected
                assert conn.sock is not None
                if first is None:
                    first = conn.sock
                assert conn.sock is first
                assert conn.sock.cipher()[0] == suite_name
                assert conn.sock.selected_alpn_protocol() == "http/1.1"
            # Generator body exercises real chunked request framing.
            conn.request("POST", "/echo", body=iter([b"chunk one", b"\x00\xffchunk two"]), encode_chunked=True)
            res = conn.getresponse()
            assert res.status == 200 and res.read() == b"chunk one\x00\xffchunk two"
            assert conn.sock is first
        finally:
            conn.close()
        rows.append(dict(name="python-keepalive-get-post-stream-chunked", client="Python", requests=4, connections=1, suite=suite_name))

        output = json.loads(run([go, directory / "ca.pem", url]).stdout)
        assert output["connections"] == 1
        assert all(r["suite"] == expected_suite and r["version"] == 772 and r["alpn"] == "http/1.1" for r in output["requests"])
        rows.append(dict(name="go-get-post-stream-keepalive", client="Go", **output))

        with tls_socket(port, directory) as peer:
            peer.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\nPOST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\nConnection: close\r\n\r\npipe")
            # One buffered parser across both responses avoids discarding
            # pipelined plaintext when a TLS read coalesces them.
            parser = peer.makefile("rb")
            for expected in [b"secure\n", b"pipe"]:
                line = parser.readline(); assert b" 200 " in line, line
                headers = {}
                while (line := parser.readline()) != b"\r\n":
                    assert line, "truncated pipelined headers"
                    k, v = line.decode().split(":", 1); headers[k.lower()] = v.strip()
                assert parser.read(int(headers["content-length"])) == expected
            parser.close()
        rows.append(dict(name="pipelining", requests=2))

        legacy_signed = run([legacy, KEY, VALUE]).stdout.decode().strip()
        minted = request(port, directory, "/mint")
        assert_response(minted, 200)
        cookie = minted[2]["set-cookie"].split(";", 1)[0]
        assert cookie == "grounds=" + legacy_signed
        assert all(x in minted[2]["set-cookie"] for x in ["Secure", "HttpOnly", "SameSite=Strict"])
        assert_response(request(port, directory, "/cookie", headers={"Cookie": cookie}), 200, b"cookie ok\n")
        assert_response(request(port, directory, "/cookie", headers={"Cookie": "grounds=" + legacy_signed}), 200)
        changed = cookie[:-1] + ("0" if cookie[-1] != "0" else "1")
        assert_response(request(port, directory, "/cookie", headers={"Cookie": changed}), 401)
        assert_response(request(port, directory, "/cookie", headers={"Cookie": cookie.replace(VALUE, "changed")}), 401)
        rows.append(dict(name="cookie-legacy-format-roundtrip-tamper", requests=5, legacy_sha256=hashlib.sha256(legacy_signed.encode()).hexdigest()))
        assert_response(request(port, directory, headers={"X-Forwarded-Proto": "http"}), 200, b"secure\n")
        for path, body in [("/healthz", b"ok\n"), ("/readyz", b"ready\n")]:
            assert_response(request(port, directory, path), 200, body)
        rows.append(dict(name="https-marker-and-health", requests=3))
        assert process.poll() is None


def rejected(binary, directory, credential, suite, rows):
    with server(binary, directory, credential, suite, HTTP_MAX_HEAD_BYTES=1024,
                HTTP_MAX_BODY_BYTES=100000, HTTP_REQUEST_MS=1000, HTTP_IDLE_MS=800) as (port, process):
        try:
            bad = http.client.HTTPSConnection("localhost", port, context=context(directory, True), timeout=8)
            try:
                bad.request("GET", "/")
            finally:
                bad.close()
        except ssl.SSLCertVerificationError:
            pass
        else:
            raise AssertionError("wrong CA accepted")
        rows.append(dict(name="wrong-ca", rejected=True))
        with socket.create_connection(("127.0.0.1", port), timeout=8) as peer:
            peer.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            data = peer.recv(4096)
            assert b"HTTP/1.1 200" not in data
        rows.append(dict(name="plaintext-to-tls", rejected=True))
        with socket.create_connection(("127.0.0.1", port), timeout=8) as peer:
            start = time.monotonic()
            assert peer.recv(4096) == b""
            elapsed = time.monotonic() - start
            assert .5 < elapsed < 3.5, elapsed
        rows.append(dict(name="handshake-timeout", seconds=elapsed, rejected=True))
        with tls_socket(port, directory) as peer:
            peer.sendall(b"POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 999\r\n\r\npartial")
        rows.append(dict(name="disconnect-mid-request", rejected=True))
        assert_response(request(port, directory, "/", headers={"X-Long": "x" * 2048}), 431)
        rows.append(dict(name="oversize-head", status=431))
        assert_response(request(port, directory, "/echo", body=b"x" * 100001, method="POST"), 413)
        rows.append(dict(name="oversize-body", status=413))
        with tls_socket(port, directory) as peer:
            peer.sendall(b"POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 9\r\n\r\nx")
            assert_response(response(peer), 408)
        rows.append(dict(name="request-timeout", status=408))
        with tls_socket(port, directory) as peer:
            start = time.monotonic()
            assert peer.recv(1) == b""
            elapsed = time.monotonic() - start
            assert .4 < elapsed < 3, elapsed
        rows.append(dict(name="idle-timeout", seconds=elapsed))
        assert_response(request(port, directory), 200, b"secure\n")
        rows.append(dict(name="listener-survives-failures", status=200))

    with server(binary, directory, credential, suite, HTTP_MAX_REQUESTS=2) as (port, process):
        conn = http.client.HTTPSConnection("localhost", port, context=context(directory), timeout=12)
        try:
            for n in range(2):
                payload = bytes(range(256)) * 200
                conn.request("POST", "/echo", body=payload)
                res = conn.getresponse(); assert res.status == 200; assert res.read() == payload
                assert (res.getheader("connection") == "close") == (n == 1)
        finally:
            conn.close()
        rows.append(dict(name="max-requests", requests=2))

    with server(binary, directory, credential, suite) as (port, process):
        with tls_socket(port, directory) as peer:
            peer.sendall(b"POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 9\r\n\r\nstart")
            time.sleep(.08)
            process.send_signal(signal.SIGTERM)
            time.sleep(.08)
            peer.sendall(b"done")
            status, body, headers = response(peer)
            assert status == 200 and body == b"startdone" and headers.get("connection") == "close"
        process.wait(5)
        assert process.returncode == 0
        assert b"every connection done" in process.stderr.read()
        rows.append(dict(name="graceful-stop-active-request", status=200, drained=True))

    with server(binary, directory, credential, suite) as (port, process):
        with tls_socket(port, directory) as peer:
            peer.sendall(b"GET /slow HTTP/1.1\r\nHost: localhost\r\n\r\n")
            res = http.client.HTTPResponse(peer); res.begin()
            assert res.read(8) == b"started\n"
            process.send_signal(signal.SIGTERM)
            assert res.read() == b"finished\n"
        process.wait(5)
        assert process.returncode == 0
        assert b"every connection done" in process.stderr.read()
        rows.append(dict(name="graceful-stop-active-stream", drained=True))


def configuration_cases(binary, directory, rows):
    base = dict(os.environ, **POISON, PORT=str(free_port()), HTTP_TLS_ENGINE="bend",
                HTTP_TLS_CERT=str(directory / "ecdsa.pem"),
                HTTP_TLS_KEY=str(directory / "ecdsa.key"), HTTP_COOKIE_KEY=KEY)
    invalid = directory / "invalid.pem"
    invalid.write_text("not a PEM credential\n")
    for name, changes in [
        ("bad-pem-before-listen", dict(HTTP_TLS_CERT=str(invalid))),
        ("mismatched-key-before-listen", dict(HTTP_TLS_KEY=str(directory / "rsa.key"))),
        ("bad-engine-before-listen", dict(HTTP_TLS_ENGINE="unknown")),
        ("hard-bend-rejects-openssl", dict(HTTP_TLS_ENGINE="openssl")),
    ]:
        result = subprocess.run(binary, env=dict(base, **changes), capture_output=True, timeout=15)
        assert result.returncode != 0, (name, result.stdout, result.stderr)
        with socket.socket() as probe:
            assert probe.connect_ex(("127.0.0.1", int(base["PORT"]))) != 0, name
        rows.append(dict(name=name, exit=result.returncode, rejected=True))
    loaded = directory / "loaded-runtime"
    loaded.mkdir(exist_ok=True)
    for name in ("ecdsa.pem", "ecdsa.key", "ca.pem"):
        shutil.copyfile(directory / name, loaded / name)
    with server(binary, loaded, "ecdsa", "aes") as (port, process):
        # PEM disappears after listen. Fresh independent handshakes must use
        # the already validated listener owner, not re-read credentials.
        (loaded / "ecdsa.pem").unlink()
        (loaded / "ecdsa.key").unlink()
        for _ in range(2):
            assert_response(request(port, loaded), 200, b"secure\n")
        rows.append(dict(name="credentials-imported-once-before-listen", requests=2))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--fixtures", type=Path, required=True)
    p.add_argument("--prepare", action="store_true")
    p.add_argument("--credential", choices=["ecdsa", "rsa"])
    p.add_argument("--suite", choices=["aes", "chacha"])
    p.add_argument("--negative", action="store_true")
    p.add_argument("--configuration", action="store_true")
    p.add_argument("--go", type=Path)
    p.add_argument("--legacy", type=Path)
    p.add_argument("--report", type=Path, required=True)
    p.add_argument("binary", nargs=argparse.REMAINDER)
    args = p.parse_args()
    rows = []
    report = dict(credential=args.credential, suite=args.suite, binary=args.binary,
                  synthetic_keys_only=True, certificate_verification=True, results=rows,
                  tested_artifact_sha256={str(Path(arg).resolve()): hashlib.sha256(Path(arg).read_bytes()).hexdigest()
                    for arg in args.binary if Path(arg).is_file()})
    started = time.monotonic()
    try:
        if args.prepare:
            args.fixtures.mkdir(parents=True, exist_ok=True)
            openssl = "/opt/homebrew/opt/openssl@3/bin/openssl" if Path("/opt/homebrew/opt/openssl@3/bin/openssl").exists() else shutil.which("openssl")
            report["fixture_sha256"] = fixture(args.fixtures, openssl)
        else:
            binary = args.binary[1:] if args.binary[:1] == ["--"] else args.binary
            assert binary
            if args.configuration:
                configuration_cases(binary, args.fixtures, rows)
            elif args.negative:
                assert args.credential and args.suite
                rejected(binary, args.fixtures, args.credential, args.suite, rows)
            else:
                assert args.go and args.legacy and args.credential and args.suite
                ordinary(binary, args.fixtures, args.credential, args.suite, args.go, args.legacy, rows)
        report["passed"] = True
    except BaseException as error:
        report.update(passed=False, error=repr(error))
        raise
    finally:
        report["elapsed_seconds"] = time.monotonic() - started
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(dict(passed=report.get("passed", False), scenarios=len(rows), report=str(args.report))))


if __name__ == "__main__":
    main()
