"""Audit exact native M4b programs and prove host-effect abort controls."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "wire"))
from bend_tls_no_openssl_check import c_defined_names, c_effects, native_imports, self_check


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--native", type=Path, required=True)
    p.add_argument("--c", type=Path, required=True)
    p.add_argument("--role", choices=["client", "server"], required=True)
    p.add_argument("--probe-dir", type=Path, required=True)
    p.add_argument("--report", type=Path, required=True)
    a = p.parse_args()
    self_check()
    source = a.c.read_text()
    required = {"wire_random_bytes", "wire_recv_timeout", "wire_send_timeout"}
    required |= {"wire_connect_timeout", "wire_resolve"} if a.role == "client" else {"wire_accept_timeout", "TCP.listen", "http_readable"}
    results = dict(c=c_effects(source, required), native=native_imports(a.native, c_defined_names(source)))
    problems = [f"{target} {key}: {value}" for target, result in results.items()
                for key, value in result.items()
                if (key.startswith(("forbidden_", "missing_")) or key == "unresolved_cid_registrations") and value]
    controls = []
    for name, marker in [("legacy-probe", "wire_tls_listen_ctx"), ("cookie-probe", "sign")]:
        result = subprocess.run([str(a.probe_dir / name)], capture_output=True, timeout=10)
        passed = result.returncode == 86 and ("GROUNDS_FORBIDDEN_HOST_EFFECT:" + marker).encode() in result.stderr
        controls.append(dict(name=name, passed=passed, exit=result.returncode, stderr=result.stderr.decode(errors="replace")))
        if not passed:
            problems.append(f"abort control: {name}")
    artifacts = {str(path.resolve()): hashlib.sha256(path.read_bytes()).hexdigest() for path in [a.c, a.native]}
    a.report.write_text(json.dumps(dict(passed=not problems, problems=problems, results=results,
        abort_controls=controls, artifact_sha256=artifacts, target="native", synthetic_keys_only=True), indent=2) + "\n")
    assert not problems, problems
    print("native no-delegation: emitted C, symbols, libraries, loader literals; two abort controls passed")


if __name__ == "__main__":
    main()
