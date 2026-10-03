"""Independent HMAC fixtures and explicit signaling admission expectations."""
import hashlib
import hmac
import json
import random
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import quote


def payload(session, end):
    return f"grounds-signal-v1:{session.encode().hex()}:{end}"


def sign(key, value):
    return value + "." + hmac.new(key.encode(), value.encode(), hashlib.sha256).hexdigest()


def cases():
    records = []
    key, session, end, now = "synthetic-cookie-key", "session", 10000, 9999
    valid = sign(key, payload(session, end))
    fields = [["Host", "fixture"], ["Origin", "local"], ["Cookie", "grounds-fixture=" + valid]]

    def add(name, expected="allowed", *, k=key, sid=session, deadline=end, clock=now,
            method="GET", path="/signal", body=False, hs=None):
        records.append((name, [k, sid, deadline, clock, method, path, body, fields if hs is None else hs], expected))

    def cookie(name, value, expected="allowed"):
        add(name, expected, hs=fields[:2] + [["Cookie", value]])

    add("exact live boundary")
    for clock in [0, 1, end - 1]:
        add(f"live {clock}", clock=clock)
    for clock in [end, end + 1, 0xffffffff]:
        add(f"expired {clock}", "denied-auth", clock=clock)
    add("empty lifetime", "denied-auth", deadline=0, clock=0)
    add("wrong key", "denied-auth", k=key + "x")
    add("wrong session", "denied-auth", sid=session + "x")
    add("different trusted deadline", "denied-auth", deadline=end + 1)
    add("missing Cookie", "denied-auth", hs=fields[:2])
    add("duplicate Cookie", "denied-auth", hs=fields + [fields[-1]])
    add("lowercase headers", hs=[[name.lower(), value] for name, value in fields])
    add("mixed-case headers", hs=[["hOsT", "fixture"], ["oRiGiN", "local"], ["cOoKiE", "grounds-fixture=" + valid]])
    for name, status in [("Host", "bad-request"), ("Origin", "denied-origin")]:
        add(f"missing {name}", status, hs=[row for row in fields if row[0] != name])
        add(f"duplicate {name}", status, hs=fields + [next(row for row in fields if row[0] == name)])
        add(f"wrong {name}", status, hs=[[n, "wrong" if n == name else v] for n, v in fields])
    add("Host precedes Origin and auth", "bad-request", hs=[["Host", "wrong"], ["Origin", "wrong"]])
    add("Origin precedes auth", "denied-origin", hs=[["Host", "fixture"], ["Origin", "wrong"]])
    for method in ["POST", "HEAD", "get", "GETx", ""]:
        add("method " + method, "bad-request", method=method)
    for path in ["/", "/signal/", "/Signal", "/signal?x=1", "/signalx", ""]:
        add("path " + path, "bad-request", path=path)
    add("nonempty request body", "bad-request", body=True)
    for value in [valid, '"' + valid + '"', quote(valid, safe=""),
                  " "+valid+"\t", "a=ignored; grounds-fixture="+valid+"; b=ignored"]:
        line = value if value.startswith("a=") else "grounds-fixture=" + value
        cookie("ordinary representation " + value[:16], line)
    cookie("uppercase MAC", "grounds-fixture=" + valid[:-64] + valid[-64:].upper())
    cookie("multiple delimiters", "; ; grounds-fixture=" + valid + "; ;")
    cookie("1024 character boundary", "x=" + "a" * (1024 - len(valid) - len("x=;grounds-fixture=")) + ";grounds-fixture=" + valid)
    cookie("1025 character rejection", "x=" + "a" * (1025 - len(valid) - len("x=;grounds-fixture=")) + ";grounds-fixture=" + valid, "denied-auth")
    for value in ["", "grounds-fixture", "grounds-fixture=", "Grounds-fixture=" + valid,
                  "grounds-fixture-x=" + valid, "grounds-fixture=local-synthetic-session",
                  "grounds-fixture="+valid+";grounds-fixture="+valid,
                  "grounds-fixture=wrong;grounds-fixture="+valid,
                  "grounds-fixture="+valid+";grounds-fixture=wrong",
                  'grounds-fixture="'+valid, 'grounds-fixture='+valid+'"',
                  "grounds-fixture=%", "grounds-fixture=%GG", "grounds-fixture=%FF",
                  "grounds-fixture=%C0%80", "grounds-fixture=%ED%A0%80"]:
        cookie("invalid representation " + value[:24], value, "denied-auth")
    for value in [payload("wrong", end), "other-purpose:"+payload(session, end),
                  payload(session, end+1), payload(session, end).upper(),
                  payload(session, end) + "\0"]:
        cookie("valid MAC for other claims", "grounds-fixture=" + sign(key, value), "denied-auth")
    for index in range(64):
        offset = len(valid) - 64 + index
        changed = valid[:offset] + ("1" if valid[offset] == "0" else "0") + valid[offset+1:]
        cookie(f"changed MAC byte {index}", "grounds-fixture="+changed, "denied-auth")
    for size in [0, 1, 63, 65, 128]:
        cookie(f"wrong MAC length {size}", "grounds-fixture=" + valid[:-64] + "0"*size, "denied-auth")
    rng = random.Random(20261003)
    for index in range(80):
        k = rng.randbytes(32).hex() if index else ""
        sid = ["", "sess;=.%", "caf\u00e9", "\u4f1a\u8bdd", "\U0001f680", "\0"][index % 6] + str(index)
        deadline = rng.randrange(2, 0xffffffff)
        token = "grounds-fixture=" + sign(k, payload(sid, deadline))
        hs = fields[:2] + [["Cookie", token]]
        add(f"independent session {index}", k=k, sid=sid, deadline=deadline, clock=deadline-1, hs=hs)
        add(f"expiry {index}", "denied-auth", k=k, sid=sid, deadline=deadline, clock=deadline, hs=hs)
        add(f"session mismatch {index}", "denied-auth", k=k, sid=sid+"x", deadline=deadline, clock=deadline-1, hs=hs)
    return records


def main():
    records = cases()
    with tempfile.TemporaryDirectory(prefix="grounds-signed-cookie-") as temporary:
        fixture = Path(temporary) / "cases.json"
        for offset in range(0, len(records), 64):
            group = records[offset:offset+64]
            fixture.write_text(json.dumps([record for _, record, _ in group], ensure_ascii=False))
            result = subprocess.run(sys.argv[1:] + [str(fixture)], capture_output=True, text=True, timeout=20)
            assert result.returncode == 0, (result.returncode, result.stderr[-2000:])
            actual = result.stdout.splitlines()
            assert len(actual) == len(group), (len(actual), len(group), result.stderr)
            for got, (name, record, expected) in zip(actual, group):
                assert got == expected, (name, got, expected, record)
    print(f"Signed signaling cookie: {len(records)} independent admission, parsing, tampering and expiry cases passed")


if __name__ == "__main__":
    main()
