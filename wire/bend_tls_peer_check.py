"""Both Bend roles against Go crypto/tls, plus Bend-to-Bend application traffic."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

from bend_tls_client_check import fixture, free_port, SUITES, GROUPS, CIVIL_OFFSET
from bend_tls_server_check import server, line, POISON, ROOT


def cases():
    return [dict(name=f"{peer}-{suite}-{group}-{signature}", peer=peer, suite=suite,
                 group=group, signature=signature)
            for peer in ("go-client", "go-server", "bend")
            for suite in SUITES for group in GROUPS for signature in ("ecdsa", "rsa")]


def client_command(binary, port, directory, mode="normal"):
    return binary + ["run", str(ROOT.parent / "crypto/unicode32_nfkc.bin"),
                     str(ROOT.parent / "crypto/unicode32_prepare.bin"), str(directory / "anchor.der"),
                     "localhost", str(port), str(int(time.time()) + CIVIL_OFFSET), mode]


def go_args(go, role, case, port, directory):
    return [go, "-role", role, "-address", f"127.0.0.1:{port}",
            "-group", str(GROUPS[case["group"]][0]), "-suite", str(SUITES[case["suite"]][0]),
            "-cert", str(directory / (case["signature"] + ".pem")),
            "-key", str(directory / (case["signature"] + ".key")),
            "-ca", str(directory / "ca.pem")]


def test(server_binary, client_binary, go, directory, case):
    if case["peer"] == "go-server":
        port = free_port()
        command = go_args(go, "server", case, port, directory)
        # Go's public CipherSuites config deliberately does not control TLS1.3.
        # With AES hardware disabled its standard preference selects ChaCha.
        # Assert the ACTUAL negotiated suite on both peers, never infer it.
        debug = "cpu.all=off" if case["suite"] == "chacha" else ""
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   env=dict(os.environ, GODEBUG=debug), bufsize=0)
        try:
            assert line(process) == "ready"
            client = client_command(client_binary, port, directory)
            result = subprocess.run(client, capture_output=True, text=True, timeout=25,
                                    env=dict(os.environ, **POISON))
            output, errors = process.communicate(timeout=10)
            go_state = json.loads(output)
            expected = f"ok:{SUITES[case['suite']][0]}:{GROUPS[case['group']][0]}:true:706f6e67"
            return dict(command=command, client_command=client, go_debug=debug, go_state=go_state,
                        peer_stderr=errors.decode(), stdout=result.stdout, stderr=result.stderr,
                        passed=result.returncode == 0 and result.stdout.strip() == expected and process.returncode == 0)
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(3)
            process.stdout.close()
            process.stderr.close()
    with server(server_binary, directory, case) as (port, process, command):
        if case["peer"] == "go-client":
            client = go_args(go, "client", case, port, directory)
        else:
            client = client_command(client_binary, port, directory)
        result = subprocess.run(client, capture_output=True, text=True, timeout=25,
                                env=dict(os.environ, **POISON))
        output, errors = process.communicate(timeout=10)
        if case["peer"] == "go-client":
            state = json.loads(result.stdout)
            matched = state["verification"] and state["application"] == "ping"
        else:
            state = None
            expected = f"ok:{SUITES[case['suite']][0]}:{GROUPS[case['group']][0]}:true:70696e67"
            matched = result.stdout.strip() == expected
        accepted = f"accepted:{SUITES[case['suite']][0]}:{GROUPS[case['group']][0]}:true:6c6f63616c686f7374"
        return dict(command=command, client_command=client, go_state=state, stdout=output.decode(),
                    stderr=errors.decode(), client_stdout=result.stdout, client_stderr=result.stderr,
                    passed=result.returncode == 0 and process.returncode == 0 and matched and accepted in output.decode())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", required=True)
    parser.add_argument("--client", required=True)
    parser.add_argument("--runtime")
    parser.add_argument("--go-peer", required=True)
    parser.add_argument("--batch-index", type=int)
    parser.add_argument("--expected-batches", type=int)
    parser.add_argument("--case")
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    server_binary = ([args.runtime] if args.runtime else []) + [args.server]
    client_binary = ([args.runtime] if args.runtime else []) + [args.client]
    rows = cases()
    if args.expected_batches is not None:
        assert args.expected_batches == (len(rows)+1)//2, "phase/corpus batch count drift"
    if args.case:
        rows = [row for row in rows if row["name"] == args.case]
    if args.batch_index is not None:
        rows = rows[args.batch_index*2:args.batch_index*2+2]
    assert rows
    results = []
    with tempfile.TemporaryDirectory(prefix="grounds-tls-go-bend-") as td:
        directory = Path(td)
        openssl = os.environ.get("OPENSSL") or ("/opt/homebrew/opt/openssl@3/bin/openssl"
            if Path("/opt/homebrew/opt/openssl@3/bin/openssl").is_file() else "openssl")
        fixtures = fixture(directory, openssl)
        for case in rows:
            try:
                observed = test(server_binary, client_binary, args.go_peer, directory, case)
            except Exception as error:
                observed = dict(passed=False, error=repr(error))
            observed["case"] = case
            results.append(observed)
            print(case["name"], observed["passed"], flush=True)
    report = dict(passed=all(r["passed"] for r in results), results=results,
                  fixture_sha256=fixtures, environment=POISON)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
