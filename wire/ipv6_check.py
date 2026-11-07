"""Runs the native ipv6 wire program and checks what it prints.

Strict where the host allows it: localhost must resolve to both ::1 and
127.0.0.1 for the dual-stack cases (it does on macOS), and on macOS a lookup of
an unknown .local name (multicast DNS, about 5 s) must be cut off at its 300 ms
deadline, with the process exiting at once rather than waiting for the lookup.
Elsewhere a fast failure of that lookup is accepted and recorded."""
import json
import platform
import subprocess
import sys
import time


def main():
    binary = sys.argv[1]
    start = time.monotonic()
    out = subprocess.run([binary], capture_output=True, text=True, timeout=30)
    elapsed = time.monotonic() - start
    assert out.returncode == 0, (out.returncode, out.stdout, out.stderr)
    lines = dict(line.split(": ", 1) for line in out.stdout.splitlines())
    names = lines["lookup localhost"].split(",")
    dual = "::1" in names and "127.0.0.1" in names
    expect = {
        "v6 bytes": "1,2,255",
        "v4 same port": "refused",
        "dial literal 0:0::1": "accepted",
        "dial closed port": "unreached refused",
        "listen zone": "invalid",
        "listen name": "invalid",
        "connect zone": "invalid",
    }
    if dual:
        expect["dial localhost to ::1 only"] = "accepted"
        expect["dial localhost to 127.0.0.1 only"] = "accepted"
    for key, value in expect.items():
        assert lines.get(key) == value, (key, lines.get(key), value, out.stdout)
    assert lines["lookup invalid"].startswith("errno "), lines["lookup invalid"]
    slow, ms = lines["slow lookup"].rsplit(" ", 1)
    darwin = platform.system() == "Darwin"
    if darwin:
        assert dual, names
        assert slow == "timeout" and 250 <= int(ms) <= 1000, lines["slow lookup"]
        # the abandoned lookup must not hold the process open
        assert elapsed < 3.0, elapsed
    print(json.dumps(dict(passed=True, dual_stack_localhost=dual, localhost=names, slow_lookup=lines["slow lookup"],
                          dns_deadline_checked=darwin and slow == "timeout", process_seconds=round(elapsed, 3),
                          cases=len(expect) + 3)))


if __name__ == "__main__":
    main()
