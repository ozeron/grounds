"""Reproducible native M4 baseline; diagnostic numbers, no performance threshold.

Run --manifest first, then --all inside build_guard using that manifest. Every
frontend, native compile, and workload has its own unchanged 120-second phase.
"""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import platform
import shutil
import socket
import ssl
import statistics
import subprocess
import sys
import tempfile
import time
import traceback

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "wire"))
from bend_tls_client_check import CIVIL_OFFSET, SUITES, fixture, free_port
from bend_tls_no_delegation_build import overlay
from bend_tls_no_openssl_check import c_defined_names, c_effects, native_imports

PROGRAMS = {
    "server-native": "http/server/examples/bend_perf_native.bend",
    "server-legacy": "http/server/examples/bend_perf_legacy.bend",
    "client-native": "http/client/tests/bend_perf_native.bend",
    "client-legacy": "http/client/tests/bend_perf_legacy.bend",
}
PHASES = (["prepare"] + [f"{p}-{s}" for p in PROGRAMS for s in ("frontend", "compile")]
          + [f"measure-{suite}" for suite in SUITES])


def run(command, **kwargs):
    value = subprocess.run(list(map(str, command)), capture_output=True, text=True,
                           timeout=115, **kwargs)
    if value.returncode:
        raise RuntimeError(dict(command=command, exit=value.returncode,
                                stdout=value.stdout, stderr=value.stderr))
    return value


def openssl3():
    candidates = [os.environ.get("OPENSSL"), shutil.which("openssl"),
                  "/opt/homebrew/opt/openssl@3/bin/openssl",
                  "/usr/local/opt/openssl@3/bin/openssl"]
    for value in candidates:
        if value and Path(value).is_file():
            version = run([value, "version"]).stdout.strip()
            if version.startswith("OpenSSL 3."):
                return str(Path(value).resolve()), version
    raise RuntimeError("OpenSSL 3 required: put it first in PATH or set OPENSSL")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


@contextmanager
def phase(name):
    command = [sys.executable, str(ROOT / "tools/check_phase.py")]
    run(command + ["start", "http_perf/" + name.replace("-", "_")])
    try:
        yield
    except BaseException:
        # The guard terminates the process tree immediately on a failed phase.
        # Flush its actual cause before sending the failure announcement.
        traceback.print_exc()
        sys.stderr.flush()
        run(command + ["end", "http_perf/" + name.replace("-", "_"), "1"])
        raise
    else:
        run(command + ["end", "http_perf/" + name.replace("-", "_"), "0"])


def build(program, output, report):
    native = program.endswith("native")
    with tempfile.TemporaryDirectory(prefix="grounds-perf-build-") as td:
        destination = Path(td)
        inputs = overlay(destination) if native else {}
        # Copy exact source bytes; native builds retain the host-TLS abort overlay.
        for directory in ("http/server", "http/client", "http/wire", "json", "decimal"):
            for source in sorted((ROOT / directory).rglob("*")):
                if source.is_file() and source.suffix in {".bend", ".c", ".js"}:
                    relative = source.relative_to(ROOT)
                    target = destination / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(source.read_bytes())
                    inputs[str(relative)] = digest(source)
        source = destination / PROGRAMS[program] if native else ROOT / PROGRAMS[program]
        value = run(["bend", source, "-o", output])
        save(report, dict(program=PROGRAMS[program], native_abort_overlay=native,
                          inputs=inputs, output_sha256=digest(output),
                          stdout=value.stdout, stderr=value.stderr))


def audit(program, c, binary, report):
    source = c.read_text()
    results = dict(c=c_effects(source, set()), native=native_imports(binary, c_defined_names(source)))
    problems = [f"{target}/{key}: {value}" for target, result in results.items()
                for key, value in result.items()
                if (key.startswith(("forbidden_", "missing_")) or key == "unresolved_cid_registrations") and value]
    save(report, dict(program=program, passed=not problems, problems=problems,
                      results=results, c_sha256=digest(c), binary_sha256=digest(binary)))
    assert not problems, problems


@contextmanager
def server(binary, fixtures, suite, openssl_config, native):
    port = free_port()
    env = dict(os.environ, PORT=str(port), HTTP_TLS_CERT=str(fixtures / "ecdsa.pem"),
               HTTP_TLS_KEY=str(fixtures / "ecdsa.key"), HTTP_BEND_TLS_SUITE=suite,
               HTTP_MAX_REQUESTS="10000", HTTP_IDLE_MS="5000", HTTP_DRAIN_MS="1000",
               OPENSSL_CONF=str(openssl_config))
    if native:
        env.update(BEND_LIBSSL="/nonexistent/perf-libssl", GROUNDS_TLS_CA="/nonexistent/perf-ca")
    process = subprocess.Popen([str(binary)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 15
        while True:
            assert process.poll() is None, process.communicate()
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=.1):
                    break
            except OSError:
                if time.monotonic() > deadline:
                    raise TimeoutError("perf listener")
                time.sleep(.03)
        yield port
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(3)
        out, err = process.communicate()
        assert process.returncode == 0, (process.returncode, out, err)


def summary(samples):
    assert len(samples) >= 50
    ordered = sorted(samples)
    return dict(handshakes=len(samples), handshake_ms=samples,
                handshake_p50_ms=statistics.median(samples),
                handshake_p95_ms=ordered[math.ceil(.95 * len(samples)) - 1])


def peer_measure(port, fixtures, suite):
    ctx = ssl.create_default_context(cafile=str(fixtures / "ca.pem"))
    ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.set_alpn_protocols(["http/1.1"])
    expected = SUITES[suite][1]
    assert [c["name"] for c in ctx.get_ciphers() if c["protocol"] == "TLSv1.3"] == [expected]
    samples = []
    for i in range(55):
        before = time.perf_counter_ns()
        peer = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=10), server_hostname="localhost")
        after = time.perf_counter_ns()
        assert peer.version() == "TLSv1.3" and peer.cipher()[0] == expected
        assert peer.selected_alpn_protocol() == "http/1.1"
        peer.close()
        if i >= 5:
            samples.append((after - before) / 1e6)
    connection = http.client.HTTPSConnection("localhost", port, context=ctx, timeout=10)
    owner = None
    before = None
    try:
        for i in range(205):
            if i == 5:
                before = time.perf_counter_ns()
            connection.request("GET", "/")
            response = connection.getresponse()
            assert response.status == 200 and response.read() == b"perf ok\n"
            assert connection.sock is not None
            if owner is None:
                owner = connection.sock
            assert connection.sock is owner, "keep-alive reconnected"
            assert owner.cipher()[0] == expected
        elapsed = (time.perf_counter_ns() - before) / 1e9
    finally:
        connection.close()
    return dict(**summary(samples), requests=200, request_seconds=elapsed,
                requests_per_second=200 / elapsed, keep_alive_connections=1,
                verified_suite=expected, handshake_clock="perf_counter_ns")


def client_measure(binary, fixtures, port, native):
    command = [binary]
    env = dict(os.environ)
    if native:
        command += [ROOT / "crypto/unicode32_nfkc.bin", ROOT / "crypto/unicode32_prepare.bin",
                    fixtures / "ca.pem", str(int(datetime.now(timezone.utc).timestamp()) + CIVIL_OFFSET)]
        env.update(BEND_LIBSSL="/nonexistent/perf-libssl", GROUNDS_TLS_CA="/nonexistent/perf-ca")
    else:
        env["GROUNDS_TLS_CA"] = str(fixtures / "ca.pem")
    command += [str(port), f"https://localhost:{port}/"]
    value = run(command, env=env)
    lines = value.stdout.strip().splitlines()
    samples = [int(line.split(":")[1]) for line in lines if line.startswith("handshake:")]
    request_lines = [line for line in lines if line.startswith("requests:")]
    assert len(lines) == 51 and len(samples) == 50 and len(request_lines) == 1, lines
    _, count, ms = request_lines[0].split(":")
    assert int(count) == 200 and int(ms) > 0, request_lines
    return dict(**summary(samples), requests=int(count), request_seconds=int(ms) / 1000,
                requests_per_second=int(count) * 1000 / int(ms),
                handshake_clock="IO.now monotonic milliseconds", command=list(map(str, command)),
                stdout=value.stdout, keep_alive="one-slot production pool; 5 warmups then 200 requests")


def workload(directory, suite):
    config = directory / f"{suite}.cnf"
    # A fresh interpreter is required: OPENSSL_CONF is read on library startup.
    env = dict(os.environ, OPENSSL_CONF=str(config))
    command = [sys.executable, __file__, "--measure", suite, "--artifacts", str(directory)]
    value = run(command, env=env)
    print(value.stdout, end="")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--manifest", action="store_true")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--measure", choices=list(SUITES))
    args = parser.parse_args()
    directory = args.artifacts.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    if args.manifest:
        save(directory / "phases.json", dict(version=1, phases=[dict(name="http_perf/" + n.replace("-", "_"), optional=False) for n in PHASES]))
        return
    if args.measure:
        suite = args.measure
        rows = []
        for engine in ("native", "legacy"):
            with server(directory / ("server-" + engine), directory / "fixtures", suite,
                        directory / f"{suite}.cnf", engine == "native") as port:
                rows.append(dict(target="server", engine=engine, suite=SUITES[suite][1],
                                 **peer_measure(port, directory / "fixtures", suite)))
        # Both production clients use the very same native server process.
        with server(directory / "server-native", directory / "fixtures", suite,
                    directory / f"{suite}.cnf", True) as port:
            for engine in ("native", "legacy"):
                rows.append(dict(target="client", engine=engine, suite=SUITES[suite][1],
                                 peer="same native Bend server process", **client_measure(directory / ("client-" + engine), directory / "fixtures", port, engine == "native")))
        save(directory / f"results-{suite}.json", dict(rows=rows, openssl_config=str(directory / f"{suite}.cnf")))
        print(json.dumps(rows))
        return
    assert args.all, "choose --manifest, --all or --measure"
    with phase("prepare"):
        openssl, version = openssl3()
        fixtures = directory / "fixtures"
        fixtures.mkdir(exist_ok=True)
        hashes = fixture(fixtures, openssl)
        for suite, (_, name) in SUITES.items():
            (directory / f"{suite}.cnf").write_text("openssl_conf = init\n[init]\nssl_conf = ssl\n[ssl]\nsystem_default = defaults\n[defaults]\nMinProtocol = TLSv1.3\nMaxProtocol = TLSv1.3\nCipherSuites = " + name + "\nGroups = X25519\n")
        metadata = dict(machine=platform.uname()._asdict(), processor=platform.processor(),
                        python=sys.version, python_ssl=ssl.OPENSSL_VERSION, openssl=version,
                        openssl_binary=openssl, bend=run(["bend", "version"]).stdout.strip(),
                        clang=run(["clang", "--version"]).stdout.splitlines()[0],
                        fixture_sha256=hashes, source_sha256={p: digest(ROOT / p) for p in PROGRAMS.values()},
                        measured_at=datetime.now(timezone.utc).isoformat(),
                        command=sys.argv, methodology="5 warmups; 50 full TLS opens (DNS/TCP included), no resumption; 5 warmup GETs then 200 sequential GETs on one production pool / peer socket; 8-byte body; loopback; X25519; ECDSA P-256 leaf and CA; TLS 1.3 single suite; no throughput threshold")
        if sys.platform == "darwin":
            metadata["hardware"] = {name: run(["sysctl", "-n", name]).stdout.strip()
                                    for name in ("hw.model", "machdep.cpu.brand_string", "hw.ncpu", "hw.memsize")}
        save(directory / "metadata.json", metadata)
    for program in PROGRAMS:
        c = directory / (program + ".c")
        with phase(program + "-frontend"):
            build(program, c, directory / (program + "-build.json"))
        with phase(program + "-compile"):
            value = run(["sh", ROOT / "tools/bend_native.sh", c, directory / program])
            save(directory / (program + "-compile.json"), dict(stdout=value.stdout, stderr=value.stderr))
            if program.endswith("native"):
                audit(program, c, directory / program, directory / (program + "-audit.json"))
    for suite in SUITES:
        with phase("measure-" + suite):
            workload(directory, suite)
    rows = [row for suite in SUITES for row in json.loads((directory / f"results-{suite}.json").read_text())["rows"]]
    save(directory / "baseline.json", dict(metadata=metadata, rows=rows, performance_thresholds=False))


if __name__ == "__main__":
    main()
