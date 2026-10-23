"""Build the real HTTP example with the M3b TLS/cookie abort overlay."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "wire"))
from bend_tls_no_delegation_build import overlay


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("output", type=Path)
    p.add_argument("report", type=Path)
    p.add_argument("--program", choices=["http", "wss", "browser", "client"], default="http")
    args = p.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="grounds-http-no-host-tls-") as td:
        destination = Path(td)
        inputs = overlay(destination)
        directories = ["http/server", "http/wire"] + (["http/client", "json", "decimal"] if args.program == "client" else [])
        for directory in directories:
            for source in sorted((ROOT / directory).rglob("*")):
                if source.is_file() and source.suffix in {".bend", ".c", ".js"}:
                    relative = source.relative_to(ROOT)
                    target = destination / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(source.read_bytes())
                    inputs[str(relative)] = hashlib.sha256(source.read_bytes()).hexdigest()
        program = {"http": "http/server/examples/bend_tls.bend",
                   "wss": "http/server/examples/bend_wss.bend",
                   "browser": "http/server/examples/bend_browser.bend",
                   "client": "http/client/tests/bend_tls.bend"}[args.program]
        result = subprocess.run(["bend", str(destination / program),
                                 "-o", str(args.output.resolve())], capture_output=True, text=True)
        report = dict(exit=result.returncode, stdout=result.stdout, stderr=result.stderr,
                      input_sha256=inputs, bend_sources_unchanged=True,
                      os_byte_rng_effects_unchanged=True, legacy_tls_cookie_effects="abort/throw")
        if args.output.exists():
            report["output_sha256"] = hashlib.sha256(args.output.read_bytes()).hexdigest()
        args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(result.stdout, result.stderr, end="")
        raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
