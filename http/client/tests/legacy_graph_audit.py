"""Native legacy HTTP client graphs must remain free of Bend TLS/crypto."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "http/server/examples"))
from legacy_graph_audit import graph_ids

FORBIDDEN = re.compile(r"(?:crypto_|wire_bend_tls|wire_tls_(?:record|handshake|server)|bend_client_|bend_transport_)")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--artifacts", type=Path, required=True)
    args = p.parse_args()
    args.artifacts.mkdir(parents=True, exist_ok=True)
    rows = []
    for name in ["tests/live", "tests/more", "tests/events", "examples/get", "examples/json", "examples/stream", "examples/events"]:
        output = args.artifacts / (name.replace("/", "-") + ".c")
        result = subprocess.run(["bend", str(ROOT / ("http/client/" + name + ".bend")), "-o", str(output)], capture_output=True, text=True)
        assert result.returncode == 0, (name, result.stdout, result.stderr)
        identifiers = graph_ids(output.read_text(), "c")
        assert identifiers and not [value for value in identifiers if FORBIDDEN.search(value)], name
        rows.append(dict(program=name, sha256=hashlib.sha256(output.read_bytes()).hexdigest(), reachable_definitions=len(identifiers)))
    (args.artifacts / "report.json").write_text(json.dumps(dict(passed=True, target="native", graphs=rows), indent=2) + "\n")
    print(f"legacy client graphs: {len(rows)} clean; existing cold checks run unchanged")


if __name__ == "__main__":
    main()
