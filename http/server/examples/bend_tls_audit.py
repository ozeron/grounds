"""Permanent emitted HTTP program/import/symbol audit and abort controls."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "wire"))
from bend_tls_no_openssl_check import c_effects, js_effects, native_imports, self_check
from legacy_graph_audit import graph_ids, FORBIDDEN


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--native", type=Path, required=True)
    p.add_argument("--c", type=Path, required=True)
    p.add_argument("--js", type=Path, required=True)
    p.add_argument("--probe-dir", type=Path, required=True)
    p.add_argument("--report", type=Path, required=True)
    args = p.parse_args()
    self_check()
    # Positive controls: the graph classifier must detect the actual Bend graph.
    for path, target in [(args.c, "c"), (args.js, "js")]:
        assert any(FORBIDDEN.search(value) for value in graph_ids(path.read_text(), target)), target
    required = {"wire_random_bytes", "wire_recv_timeout", "wire_send_timeout", "wire_accept_timeout", "TCP.listen", "http_readable", "http_native_target"}
    results = dict(c=c_effects(args.c.read_text(), required),
                   js=js_effects(args.js.read_text(), required), native=native_imports(args.native))
    problems = []
    for target, result in results.items():
        for key, value in result.items():
            if (key.startswith(("forbidden_", "missing_")) or key == "unresolved_cid_registrations") and value:
                problems.append(f"{target} {key}: {value}")
    controls = []
    for name, marker in [("legacy-probe", "wire_tls_listen_ctx"), ("cookie-probe", "sign")]:
        for target, command in [("native", [str(args.probe_dir / name)]), ("bun", ["bun", str(args.probe_dir / (name + ".js"))])]:
            result = subprocess.run(command, capture_output=True, timeout=10)
            expected = ("GROUNDS_FORBIDDEN_HOST_EFFECT:" + marker).encode()
            passed = result.returncode != 0 and expected in result.stderr
            if target == "native":
                passed = passed and result.returncode == 86
            controls.append(dict(probe=name, target=target, exit=result.returncode,
                                 stderr=result.stderr.decode(errors="replace"), passed=passed))
            if not passed:
                problems.append(f"abort control did not trap: {name}/{target}")
    artifacts = {name: dict(path=str(path.resolve()), sha256=hashlib.sha256(path.read_bytes()).hexdigest())
                 for name, path in [("native", args.native), ("c", args.c), ("js", args.js)]}
    report = dict(passed=not problems, problems=problems, artifacts=artifacts,
                  results=results, abort_controls=controls,
                  entrypoint="http/server/bend_server.bend:serve_bend_out_context",
                  server_credentials=dict(native=["ecdsa-p256", "rsa"], bun=["ecdsa-p256"]),
                  bun_rsa="unsupported for latency reasons; rejected before listen",
                  scope="Exact HTTP example emitted effects/imports/calls/symbols/libraries/loader literals; synthetic keys only")
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(dict(passed=not problems, problems=problems, abort_controls=len(controls))))
    if problems:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
