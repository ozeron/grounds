"""End-to-end checks for the TLS and redirect examples."""

import contextlib
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import warnings


def curl(*args):
    return subprocess.run(["curl", "-sS", *args], capture_output=True, text=True)


def ready(url, *args):
    for _ in range(100):
        result = curl(*args, url)
        if result.returncode == 0:
            return result
        time.sleep(0.05)
    raise AssertionError(f"{url} did not start: {result.stderr}")


@contextlib.contextmanager
def running(binary, env):
    proc = subprocess.Popen([binary], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        yield proc
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        proc.stderr.close()


def certificate(directory, name):
    cert = directory / f"{name}.pem"
    key = directory / f"{name}.key"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(cert), "-days", "1",
         "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"],
        check=True, capture_output=True,
    )
    return cert, key


def rejected_alpn(cert):
    ctx = ssl.create_default_context(cafile=str(cert))
    ctx.set_alpn_protocols(["h2"])
    try:
        with socket.create_connection(("127.0.0.1", 8088), timeout=3) as raw:
            with ctx.wrap_socket(raw, server_hostname="localhost"):
                pass
    except ssl.SSLError:
        return
    raise AssertionError("the server accepted an h2-only ALPN offer")


def selected_alpn(cert):
    ctx = ssl.create_default_context(cafile=str(cert))
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    with socket.create_connection(("127.0.0.1", 8088), timeout=3) as raw:
        with ctx.wrap_socket(raw, server_hostname="localhost") as conn:
            assert conn.selected_alpn_protocol() == "http/1.1"
            conn.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            reply = bytearray()
            while part := conn.recv(4096):
                reply.extend(part)
            assert b"secure\n" in reply


def rejected_tls11():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_1
        ctx.maximum_version = ssl.TLSVersion.TLSv1_1
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_ciphers("ALL:@SECLEVEL=0")
    try:
        with socket.create_connection(("127.0.0.1", 8088), timeout=3) as raw:
            with ctx.wrap_socket(raw, server_hostname="localhost"):
                pass
    except ssl.SSLError:
        return
    raise AssertionError("the server accepted TLS 1.1")


def handshake_deadline():
    with socket.create_connection(("127.0.0.1", 8088), timeout=3) as sock:
        sock.settimeout(3)
        start = time.monotonic()
        try:
            data = sock.recv(1)
        except ConnectionResetError:
            data = b""
        elapsed = time.monotonic() - start
        assert data == b"" and elapsed < 2, (data, elapsed)


def main():
    tls_binary, redirect_binary, proxy_binary = sys.argv[1:]
    with tempfile.TemporaryDirectory() as tmp:
        cert, key = certificate(Path(tmp), "localhost")
        _, other_key = certificate(Path(tmp), "other")
        env = dict(os.environ)
        env.pop("HTTP_TLS_CERT", None)
        env.pop("HTTP_TLS_KEY", None)
        env["HTTP_TLS_CERT"] = str(cert)
        env["HTTP_TLS_KEY"] = str(key)
        env["HTTP_REQUEST_MS"] = "1000"

        with running(tls_binary, env):
            url = "https://localhost:8088/path?q=1"
            result = ready(url, "--cacert", str(cert), "-D", "-")
            assert "secure\n" in result.stdout
            assert "strict-transport-security: max-age=31536000" in result.stdout.lower()
            forged = curl("--cacert", str(cert), "-H", "X-Forwarded-Proto: http", url)
            assert forged.returncode == 0 and forged.stdout == "secure\n", forged
            reused = curl("--cacert", str(cert), "-v", url, url)
            assert reused.returncode == 0 and reused.stdout == "secure\nsecure\n", reused
            assert "Re-using existing connection" in reused.stderr, reused.stderr
            assert curl("https://localhost:8088/").returncode != 0
            assert curl("--cacert", str(cert), "https://127.0.0.1:8088/").returncode != 0
            assert curl("http://localhost:8088/").returncode != 0
            selected_alpn(cert)
            rejected_alpn(cert)
            rejected_tls11()
            handshake_deadline()
            with running(redirect_binary, dict(os.environ)):
                response = ready("http://localhost:8089/path?q=1", "-D", "-")
                assert response.stdout.startswith("HTTP/1.1 308 Permanent Redirect"), response.stdout
                assert "location: https://localhost:8088/path?q=1" in response.stdout.lower()
                followed = curl("-L", "--cacert", str(cert), "http://localhost:8089/path?q=1")
                assert followed.returncode == 0 and followed.stdout == "secure\n", followed
        print("https: verified curl, keep-alive, HSTS, forwarded-proto stripping, ALPN, TLS 1.1 rejection, deadline, redirect")

        plain_env = dict(os.environ)
        plain_env.pop("HTTP_TLS_CERT", None)
        plain_env.pop("HTTP_TLS_KEY", None)
        plain_env["PORT"] = "8091"
        with running(tls_binary, plain_env):
            plain = ready("http://localhost:8091/", "-H", "X-Forwarded-Proto: https")
            assert plain.stdout == "insecure\n", plain
        with running(proxy_binary, plain_env):
            assert ready("http://localhost:8090/").stdout == "insecure\n"
            trusted = curl("-H", "X-Forwarded-Proto: https", "http://localhost:8090/")
            assert trusted.returncode == 0 and trusted.stdout == "secure\n", trusted
        print("proxy: forged protocol ignored by default; trusted proxy switch works")

        missing_key = dict(env)
        missing_key.pop("HTTP_TLS_KEY")
        bad = subprocess.run([tls_binary], env=missing_key, capture_output=True, text=True, timeout=5)
        assert bad.returncode != 0 and "HTTP_TLS_CERT and HTTP_TLS_KEY" in bad.stderr, bad
        mismatched = dict(env, HTTP_TLS_KEY=str(other_key))
        bad = subprocess.run([tls_binary], env=mismatched, capture_output=True, text=True, timeout=5)
        assert bad.returncode != 0 and "TLS:" in bad.stderr, bad
        print("config: incomplete and mismatched TLS credentials fail before listen")


if __name__ == "__main__":
    main()
