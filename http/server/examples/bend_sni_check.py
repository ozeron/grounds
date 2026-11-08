"""SNI multi-certificate selection against the native Bend HTTPS/WSS server.

Synthetic keys only. Independent clients: Python ssl, OpenSSL s_client and Go
crypto/tls, all with normal chain and hostname verification against a private
synthetic CA; optional real Chrome with a throwaway-profile trust database.
Every positive row checks the presented leaf by SHA-256 of its DER encoding.
"""
import argparse
import base64
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "wire"))
from bend_tls_client_check import fixture, free_port

POISON = dict(BEND_LIBSSL="/nonexistent/m6-libssl", GROUNDS_TLS_CA="/nonexistent/m6-host-ca")
LEAVES = {  # name: (key algorithm, SAN)
    "a-ecdsa": ("ecdsa", "DNS:a.sni.test"),
    "a-rsa": ("rsa", "DNS:a.sni.test"),
    "b": ("ecdsa", "DNS:b.sni.test"),
    "wild": ("ecdsa", "DNS:*.wild.sni.test"),
    "c": ("ecdsa", "DNS:c.sni.test,DNS:other.sni.test"),
    "default": ("ecdsa", "DNS:default.sni.test,IP:127.0.0.1"),
}


def openssl_binary():
    brew = Path("/opt/homebrew/opt/openssl@3/bin/openssl")
    return str(brew) if brew.exists() else shutil.which("openssl")


def prepare(directory):
    directory.mkdir(parents=True, exist_ok=True)
    openssl = openssl_binary()
    fixture(directory, openssl)
    for serial, (name, (kind, san)) in enumerate(LEAVES.items(), start=201):
        conf = directory / f"{name}.cnf"
        conf.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                        f"extendedKeyUsage=serverAuth\nsubjectAltName={san}\n"
                        "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n")
        algorithm = ["ec", "-pkeyopt", "ec_paramgen_curve:P-256"] if kind == "ecdsa" else ["rsa:2048"]
        subprocess.run([openssl, "req", "-new", "-newkey", *algorithm, "-noenc", "-keyout", directory / f"{name}.key",
                        "-out", directory / f"{name}.csr", "-subj", f"/CN=synthetic SNI {name}", "-sha256"],
                       check=True, capture_output=True)
        subprocess.run([openssl, "x509", "-req", "-in", directory / f"{name}.csr", "-CA", directory / "ca.pem",
                        "-CAkey", directory / "ca.key", "-set_serial", str(serial), "-days", "7", "-sha256",
                        "-extfile", conf, "-out", directory / f"{name}.pem"], check=True, capture_output=True)
    return {name: fingerprint(directory, name) for name in LEAVES}


def fingerprint(directory, name):
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert((directory / f"{name}.pem").read_text())).hexdigest()


@contextmanager
def server(binary, fixtures, mode="full"):
    port = free_port()
    env = dict(os.environ, **POISON, PORT=str(port), HTTP_SNI_FIXTURES=str(fixtures), HTTP_SNI_MODE=mode,
               HTTP_IDLE_MS="3000", HTTP_REQUEST_MS="10000", HTTP_DRAIN_MS="3000")
    for name in ("HTTP_TLS_CERT", "HTTP_TLS_KEY", "HTTP_TLS_ENGINE"):
        env.pop(name, None)
    process = subprocess.Popen([str(binary)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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


def context(fixtures):
    ctx = ssl.create_default_context(cafile=str(fixtures / "ca.pem"))
    ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.set_alpn_protocols(["http/1.1"])
    return ctx


def tls(port, fixtures, name, verify=True):
    ctx = context(fixtures)
    if not verify:
        ctx.check_hostname = False
    peer = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=12), server_hostname=name)
    peer.settimeout(12)
    return peer


def read_all(peer):
    data = bytearray()
    while True:
        try:
            part = peer.recv(65536)
        except ssl.SSLZeroReturnError:
            break
        if not part:
            break
        data.extend(part)
    return bytes(data)


def whoami(peer, host):
    # Forged copies must never reach the handler.
    peer.sendall((f"GET /whoami HTTP/1.1\r\nHost: {host}\r\nx-tls-server-name: forged.example\r\n"
                  "x-tls-credential: forged\r\nConnection: close\r\n\r\n").encode())
    raw = read_all(peer)
    head, _, body = raw.partition(b"\r\n\r\n")
    assert head.startswith(b"HTTP/1.1 200"), raw[:200]
    return dict(line.split("=", 1) for line in body.decode().splitlines())


def python_row(port, fixtures, leaves, name, sni, expected, sni_header, credential, verify=True):
    with tls(port, fixtures, sni, verify) as peer:
        leaf = hashlib.sha256(peer.getpeercert(binary_form=True)).hexdigest()
        version, cipher = peer.version(), peer.cipher()[0]
        who = whoami(peer, sni or "127.0.0.1")
    assert leaf == leaves[expected], (name, leaf, expected)
    assert who == dict(sni=sni_header, credential=credential), (name, who)
    return dict(name=name, client="python-ssl", sni=sni, verified=verify, leaf=expected, leaf_sha256=leaf,
                tls=version, cipher=cipher, headers=who, passed=True)


def python_refused(port, fixtures, name, sni, expected_alert="TLSV1_UNRECOGNIZED_NAME"):
    try:
        with tls(port, fixtures, sni) as peer:
            peer.sendall(b"GET /whoami HTTP/1.1\r\nHost: x\r\n\r\n")
            read_all(peer)
    except ssl.SSLError as error:
        assert expected_alert in str(error), (name, error)
        return dict(name=name, client="python-ssl", sni=sni, refused=True, error=str(error), passed=True)
    raise AssertionError((name, "handshake unexpectedly succeeded"))


def s_client(port, fixtures, sni=None, sigalgs=None, groups=None, messages=False):
    argv = [openssl_binary(), "s_client", "-connect", f"127.0.0.1:{port}", "-tls1_3", "-alpn", "http/1.1",
            "-CAfile", str(fixtures / "ca.pem"), "-verify_return_error"]
    argv += ["-servername", sni, "-verify_hostname", sni] if sni else ["-noservername", "-verify_ip", "127.0.0.1"]
    if sigalgs:
        argv += ["-sigalgs", sigalgs]
    if groups:
        argv += ["-groups", groups]
    if messages:
        argv += ["-msg"]
    result = subprocess.run(argv, input=b"", capture_output=True, timeout=20)
    return argv, result


def openssl_row(port, fixtures, leaves, name, sni, expected, sigalgs=None, groups=None, temp_key=None):
    argv, result = s_client(port, fixtures, sni, sigalgs, groups, messages=bool(temp_key))
    out = result.stdout.decode(errors="replace")
    assert result.returncode == 0, (name, out[-2000:], result.stderr.decode(errors="replace")[-2000:])
    assert "Verify return code: 0 (ok)" in out, (name, out[-2000:])
    begin = out.index("-----BEGIN CERTIFICATE-----")
    end = out.index("-----END CERTIFICATE-----") + len("-----END CERTIFICATE-----")
    leaf = hashlib.sha256(ssl.PEM_cert_to_DER_cert(out[begin:end])).hexdigest()
    assert leaf == leaves[expected], (name, expected)
    if temp_key:
        # The client's only key share is for its first group; the server
        # prefers the second, so a HelloRetryRequest precedes selection reuse.
        assert any(f"{label}: {temp_key}" in out for label in ("Peer Temp Key", "Server Temp Key", "Negotiated TLS1.3 group")), (name, out[-2000:])
        hellos = sum(1 for line in out.splitlines() if line.startswith(">>>") and line.rstrip().endswith("ClientHello"))
        assert hellos == 2, (name, hellos, out[:3000])
    peer_sig = next((line.strip() for line in out.splitlines() if line.startswith("Peer signature type")), None)
    return dict(name=name, client="openssl-s_client", sni=sni, sigalgs=sigalgs, groups=groups, leaf=expected,
                leaf_sha256=leaf, peer_signature_type=peer_sig, verified=True, argv=argv[1:], passed=True)


def openssl_refused(port, fixtures, name, sni):
    argv, result = s_client(port, fixtures, sni)
    err = (result.stdout + result.stderr).decode(errors="replace")
    assert result.returncode != 0 and "unrecognized name" in err, (name, err[-2000:])
    return dict(name=name, client="openssl-s_client", sni=sni, refused=True, alert="unrecognized_name(112)", passed=True)


def go_row(go, port, fixtures, leaves, name, sni, expected, credential):
    result = subprocess.run([str(go), str(fixtures / "ca.pem"), f"127.0.0.1:{port}", sni],
                            capture_output=True, timeout=20, check=True)
    row = json.loads(result.stdout)
    assert row["ok"] and row["leaf_sha256"] == leaves[expected] and row["version"] == 0x0304, (name, row)
    assert f"sni={sni}\ncredential={credential}\n" in row["response"], (name, row["response"][-300:])
    return dict(name=name, client="go-crypto-tls", sni=sni, leaf=expected, leaf_sha256=row["leaf_sha256"],
                alpn=row["alpn"], verified=True, passed=True)


def exact(peer, n):
    data = bytearray()
    while len(data) < n:
        part = peer.recv(n - len(data))
        assert part, "EOF"
        data.extend(part)
    return bytes(data)


def frame(opcode, payload):
    mask = os.urandom(4)
    assert len(payload) < 126
    return bytes([0x80 | opcode, 0x80 | len(payload)]) + mask + bytes(c ^ mask[i % 4] for i, c in enumerate(payload))


def read_frame(peer):
    a, b = exact(peer, 2)
    n = b & 127
    if n == 126:
        n = struct.unpack("!H", exact(peer, 2))[0]
    return a & 15, exact(peer, n)


def wss_row(port, fixtures, leaves, name, sni, expected):
    key = base64.b64encode(os.urandom(16)).decode()
    with tls(port, fixtures, sni) as peer:
        leaf = hashlib.sha256(peer.getpeercert(binary_form=True)).hexdigest()
        peer.sendall((f"GET /ws HTTP/1.1\r\nHost: {sni}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                      f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
        head = b""
        while not head.endswith(b"\r\n\r\n"):
            head += exact(peer, 1)
        accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest())
        assert head.startswith(b"HTTP/1.1 101") and accept in head, head
        message = "sni wss café".encode()
        peer.sendall(frame(1, message))
        assert read_frame(peer) == (1, message)
        peer.sendall(frame(2, bytes([0, 1, 127, 128, 255])))
        assert read_frame(peer) == (2, bytes([0, 1, 127, 128, 255]))
        peer.sendall(frame(8, struct.pack("!H", 1000)))
        opcode, payload = read_frame(peer)
        assert opcode == 8 and payload[:2] == struct.pack("!H", 1000), (opcode, payload)
    assert leaf == leaves[expected], (name, expected)
    return dict(name=name, client="python-ssl-websocket", sni=sni, leaf=expected, leaf_sha256=leaf,
                text_binary_close=True, verified=True, passed=True)


def startup_refused(binary, fixtures, mode, message):
    env = dict(os.environ, **POISON, PORT=str(free_port()), HTTP_SNI_FIXTURES=str(fixtures), HTTP_SNI_MODE=mode)
    result = subprocess.run([str(binary)], env=env, capture_output=True, timeout=30)
    err = (result.stdout + result.stderr).decode(errors="replace")
    assert result.returncode != 0 and message in err, (mode, result.returncode, err[-1000:])
    return dict(name=f"startup-refuses-{mode}", exit=result.returncode, message=message, passed=True)


def full(a, leaves, rows):
    with server(a.binary, a.fixtures) as (port, process):
        f, L = a.fixtures, leaves
        rows += [
            python_row(port, f, L, "exact-a-prefers-p256", "a.sni.test", "a-ecdsa", "a.sni.test", "p256:a.sni.test"),
            python_row(port, f, L, "exact-b", "b.sni.test", "b", "b.sni.test", "p256:b.sni.test"),
            python_row(port, f, L, "wildcard-one-label", "x.wild.sni.test", "wild", "x.wild.sni.test", "p256:*.wild.sni.test"),
            python_row(port, f, L, "explicit-name-c", "c.sni.test", "c", "c.sni.test", "p256:c.sni.test"),
            python_row(port, f, L, "explicit-names-override-san", "other.sni.test", "default", "other.sni.test", "p256:default.sni.test", verify=False),
            python_row(port, f, L, "wildcard-not-two-labels", "a.b.wild.sni.test", "default", "a.b.wild.sni.test", "p256:default.sni.test", verify=False),
            python_row(port, f, L, "wildcard-not-bare-suffix", "wild.sni.test", "default", "wild.sni.test", "p256:default.sni.test", verify=False),
            python_row(port, f, L, "default-own-san-name", "default.sni.test", "default", "default.sni.test", "p256:default.sni.test"),
            python_row(port, f, L, "unknown-name-default", "unknown.example", "default", "unknown.example", "p256:default.sni.test", verify=False),
            python_row(port, f, L, "no-sni-ip-literal-default", "127.0.0.1", "default", "-", "p256:default.sni.test"),
            openssl_row(port, f, L, "openssl-rsa-only-client", "a.sni.test", "a-rsa", sigalgs="rsa_pss_rsae_sha256"),
            openssl_row(port, f, L, "openssl-ecdsa-only-client", "a.sni.test", "a-ecdsa", sigalgs="ecdsa_secp256r1_sha256"),
            openssl_row(port, f, L, "openssl-both-prefers-p256", "a.sni.test", "a-ecdsa", sigalgs="rsa_pss_rsae_sha256:ecdsa_secp256r1_sha256"),
            openssl_row(port, f, L, "openssl-b", "b.sni.test", "b"),
            openssl_row(port, f, L, "openssl-exact-case-folded", "B.SNI.Test", "b"),
            openssl_row(port, f, L, "openssl-wildcard-case-folded", "X.Wild.SNI.test", "wild"),
            openssl_row(port, f, L, "openssl-wildcard-after-hrr", "y.wild.sni.test", "wild", groups="P-256:X25519", temp_key="X25519"),
            openssl_row(port, f, L, "openssl-rsa-after-hrr", "a.sni.test", "a-rsa", sigalgs="rsa_pss_rsae_sha256", groups="P-256:X25519", temp_key="X25519"),
            openssl_row(port, f, L, "openssl-no-sni-default", None, "default"),
            wss_row(port, f, L, "wss-b", "b.sni.test", "b"),
            wss_row(port, f, L, "wss-wildcard", "z.wild.sni.test", "wild"),
        ]
        rows += [go_row(a.go, port, f, L, f"go-{sni}", sni, expected, credential) for sni, expected, credential in [
            ("a.sni.test", "a-ecdsa", "p256:a.sni.test"), ("b.sni.test", "b", "p256:b.sni.test"),
            ("q.wild.sni.test", "wild", "p256:*.wild.sni.test"), ("c.sni.test", "c", "p256:c.sni.test"),
            ("default.sni.test", "default", "p256:default.sni.test")]] if a.go else []
        assert process.poll() is None


def no_default(a, leaves, rows):
    with server(a.binary, a.fixtures, "nodefault") as (port, process):
        f = a.fixtures
        rows += [
            python_refused(port, f, "nodefault-unknown-name-112", "unknown.sni.test"),
            python_refused(port, f, "nodefault-two-label-wildcard-112", "a.b.wild.sni.test"),
            python_refused(port, f, "nodefault-no-sni-112", "127.0.0.1"),
            openssl_refused(port, f, "nodefault-openssl-no-sni-112", None),
            openssl_refused(port, f, "nodefault-openssl-unknown-112", "unknown.sni.test"),
            python_row(port, f, leaves, "nodefault-known-still-served", "b.sni.test", "b", "b.sni.test", "p256:b.sni.test"),
        ]
        assert process.poll() is None


def browser(a, leaves, rows):
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from bend_browser_check import chrome, chrome_binary
    binary = chrome_binary()
    der = (a.fixtures / "anchor.der").read_bytes()
    report = dict(chrome_flags=[], results=[])
    with server(a.binary, a.fixtures) as (port, process):
        with chrome(binary, der, report, rules="MAP *.sni.test 127.0.0.1") as (cdp, session):
            for host, expected, credential in [("b.sni.test", "b", "p256:b.sni.test"),
                                                ("x.wild.sni.test", "wild", "p256:*.wild.sni.test")]:
                url = f"https://{host}:{port}/"
                result = cdp.call("Page.navigate", dict(url=url), session)
                assert not result.get("errorText"), result
                deadline = time.monotonic() + 10
                while not cdp.evaluate('document.readyState === "complete" && document.title === "Grounds SNI"', session):
                    assert time.monotonic() < deadline, ("page", url)
                    time.sleep(.05)
                who = cdp.evaluate("document.querySelector('#who').textContent", session)
                assert who == f"sni={host}\ncredential={credential}\n", who
                echoed = cdp.evaluate('''new Promise((resolve, reject) => {
                  const ws = new WebSocket(location.origin.replace('https:', 'wss:') + '/ws');
                  const timer = setTimeout(() => reject(Error('WSS timeout')), 6000);
                  ws.onopen = () => ws.send('chrome sni');
                  ws.onmessage = e => { clearTimeout(timer); ws.close(1000); resolve(e.data); };
                  ws.onerror = () => { clearTimeout(timer); reject(Error('WSS error')); };
                })''', session)
                assert echoed == "chrome sni", echoed
                cdp.call("Runtime.evaluate", dict(expression="true"), session)
                details = [e["params"]["response"].get("securityDetails") for e in cdp.events
                           if e.get("method") == "Network.responseReceived" and e["params"]["response"]["url"] == url]
                details = [d for d in details if d]
                assert details and details[-1]["protocol"] == "TLS 1.3", details
                san = details[-1]["sanList"]
                assert san == [h for h in LEAVES[expected][1].replace("DNS:", "").split(",")], san
                responses = [e["params"]["response"] for e in cdp.events
                             if e.get("method") == "Network.responseReceived" and e["params"]["response"]["url"] == url]
                assert responses[-1]["securityState"] == "secure", responses[-1]
                rows.append(dict(name=f"chrome-{host}", client="chrome", sni=host, leaf=expected, san=san,
                                 subject=details[-1]["subjectName"], secure=True, wss_echo=True, passed=True))
        assert process.poll() is None
    rows.append(dict(name="chrome-environment", client="chrome", version=report.get("chrome_version"),
                     flags=report["chrome_flags"], trust="throwaway profile ServerCertificate database", passed=True))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--fixtures", type=Path, required=True)
    p.add_argument("--go", type=Path)
    p.add_argument("--chrome", action="store_true")
    p.add_argument("--report", type=Path, required=True)
    a = p.parse_args()
    rows = []
    report = dict(target="native", synthetic_keys_only=True, rows=rows,
                  driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  server_sha256=hashlib.sha256(a.binary.read_bytes()).hexdigest())
    start = time.monotonic()
    try:
        leaves = prepare(a.fixtures)
        report["leaf_sha256"] = leaves
        full(a, leaves, rows)
        no_default(a, leaves, rows)
        rows += [startup_refused(a.binary, a.fixtures, "duplicate", "duplicate TLS server name for the same key type"),
                 startup_refused(a.binary, a.fixtures, "badname", "invalid TLS server name"),
                 startup_refused(a.binary, a.fixtures, "toomany", "between 1 and 64 Bend TLS host credentials")]
        if a.chrome:
            browser(a, leaves, rows)
        report["passed"] = all(row["passed"] for row in rows)
    except BaseException as error:
        report.update(passed=False, error=repr(error))
        raise
    finally:
        report["elapsed_seconds"] = time.monotonic() - start
        a.report.parent.mkdir(parents=True, exist_ok=True)
        a.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(dict(passed=report.get("passed"), rows=len(rows), report=str(a.report))))


if __name__ == "__main__":
    main()
