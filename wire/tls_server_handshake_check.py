"""Independent encoded ClientHello negotiation cases for the Bend server."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from tls_hello_check import client
from tls_extensions_check import entry, vector


def hello(overrides=None, *, extra=b"", suites=b"\x13\x01", share=None):
    fields = {43: b"\x02\x03\x04", 10: vector(b"\x00\x1d\x00\x17"),
              13: vector(b"\x04\x03\x08\x04"),
              51: vector(b"\x00\x1d" + vector(bytes([9]) + bytes(31))),
              0: vector(b"\x00" + vector(b"localhost")),
              16: vector(b"\x08http/1.1")}
    if share is not None:
        fields[51] = vector(share)
    for kind, value in (overrides or {}).items():
        if value is None:
            fields.pop(kind, None)
        else:
            fields[kind] = value
    return client(suites=suites, extensions=b"".join(entry(k, v) for k, v in fields.items()) + extra)


def cases():
    ok = "ok:4865:29:" + (bytes([9]) + bytes(31)).hex() + ":6c6f63616c686f7374:true"
    # TLS 1.2 permits omitting the extension vector entirely, as well as an
    # explicitly empty vector. Both must reach protocol_version, not decode_error.
    legacy = client(extensions=b"")[:-2]
    legacy = legacy[:1] + (len(legacy)-4).to_bytes(3,"big") + legacy[4:]
    rows = [("valid", hello(), ok),
            ("no-alpn", hello({16: None}), ok[:-4] + "false"),
            ("no-sni", hello({0: None}), ok.replace("6c6f63616c686f7374", "")),
            ("unknown-offer", hello(extra=entry(65000, b"opaque")), ok),
            ("empty-share-hrr", hello(share=b""), "ok:4865:29::6c6f63616c686f7374:true")]
    bad = [
        ("no-suite", hello(suites=b"\x13\x02"), 40),
        ("no-group", hello({10: vector(b"\x00\x18")}), 40),
        ("no-signature", hello({13: vector(b"\x08\x07")}), 40),
        ("missing-version", hello({43: None}), 70),
        ("legacy-empty-extensions", client(extensions=b""), 70),
        ("legacy-without-extensions", legacy, 70),
        ("legacy-short-extensions", client(extensions=entry(21,b"")), 70),
        ("old-version", hello({43: b"\x02\x03\x03"}), 70),
        ("bad-version-length", hello({43: b"\x04\x03\x04"}), 50),
        ("empty-version", hello({43: b"\x00"}), 50),
        ("odd-version", hello({43: b"\x03\x03\x04\x03"}), 50),
        ("missing-groups", hello({10: None}), 109),
        ("missing-signatures", hello({13: None}), 109),
        ("missing-share", hello({51: None}), 109),
        ("empty-groups", hello({10: vector(b"")}), 50),
        ("odd-signatures", hello({13: vector(b"\x04")}), 50),
        ("bad-share-length", hello({51: b"\x00\x01"}), 50),
        ("duplicate-share", hello(share=(b"\x00\x1d" + vector(bytes(32))) * 2), 47),
        ("unoffered-share", hello(share=b"\x00\x18" + vector(bytes(65))), 47),
        ("empty-key", hello(share=b"\x00\x1d\x00\x00"), 47),
        ("duplicate-extension", hello(extra=entry(43, b"\x02\x03\x04")), 50),
        ("wrong-context", hello(extra=entry(48, b"")), 47),
        ("bad-sni-length", hello({0: b"\x00\x10\x00\x00\x01a"}), 50),
        ("empty-sni", hello({0: vector(b"\x00\x00\x00")}), 47),
        ("nul-sni", hello({0: vector(b"\x00" + vector(b"a\x00b"))}), 47),
        ("ip-sni", hello({0: vector(b"\x00" + vector(b"127.0.0.1"))}), 47),
        ("duplicate-sni", hello({0: vector((b"\x00" + vector(b"localhost")) * 2)}), 50),
        ("unsupported-alpn", hello({16: vector(b"\x02h2")}), 120),
        ("empty-alpn", hello({16: vector(b"")}), 50),
        ("empty-alpn-name", hello({16: vector(b"\x00")}), 50),
        ("bad-alpn-length", hello({16: vector(b"\x08http")}), 50),
        ("bad-cookie", hello(extra=entry(44, b"\x00\x00")), 50),
        ("bad-early-data", hello(extra=entry(42, b"\x00")), 50),
        ("bad-psk", hello(extra=entry(45,b"\x01\x01") + entry(41, b"")), 50),
        ("psk-not-last", hello(extra=entry(41,b"") + entry(45,b"\x01\x01")), 47),
        ("bad-padding", hello(extra=entry(21,b"\x01")), 47),
    ]
    rows += [(n, raw, f"error:{code}") for n, raw, code in bad]
    return rows


def retry_cases():
    cookie=vector(b"synthetic-connection-cookie")
    a=hello()
    changed_share=vector(b"\x00\x17"+vector(b"\x04"+bytes(64)))
    b=hello({51:changed_share},extra=entry(44,cookie))
    rows=[("valid-retry",a,b,True),
          ("padding-change",a,hello({51:changed_share},extra=entry(44,cookie)+entry(21,bytes(30))),True),
          ("missing-cookie",a,hello({51:changed_share}),False),
          ("wrong-cookie",a,hello({51:changed_share},extra=entry(44,vector(b"wrong"))),False),
          ("wrong-share",a,hello(extra=entry(44,cookie)),False),
          ("multiple-shares",a,hello({51:changed_share+b"\x00\x1d\x00\x20"+bytes(32)},extra=entry(44,cookie)),False),
          ("changed-sni",a,hello({51:changed_share,0:vector(b"\x00"+vector(b"other.invalid"))},extra=entry(44,cookie)),False),
          ("changed-alpn",a,hello({51:changed_share,16:None},extra=entry(44,cookie)),False),
          ("changed-suites",a,hello({51:changed_share},suites=b"\x13\x03",extra=entry(44,cookie)),False),
          ("changed-groups",a,hello({51:changed_share,10:vector(b"\x00\x17")},extra=entry(44,cookie)),False),
          ("changed-signatures",a,hello({51:changed_share,13:vector(b"\x04\x03")},extra=entry(44,cookie)),False),
          ("changed-version",a,hello({51:changed_share,43:b"\x04\x03\x04\x03\x03"},extra=entry(44,cookie)),False),
          ("early-data-retained",a,hello({51:changed_share},extra=entry(44,cookie)+entry(42,b"")),False)]
    def psk(identity,age,binder):
        return vector(vector(identity)+age.to_bytes(4,"big"))+vector(b"\x20"+bytes([binder])*32)
    first=hello(extra=entry(42,b"")+entry(45,b"\x01\x01")+entry(41,psk(b"id",1,1)))
    second=hello({51:changed_share},extra=entry(44,cookie)+entry(45,b"\x01\x01")+entry(41,psk(b"id",2,2)))
    rows += [("psk-age-binder-update",first,second,True),
             ("psk-identity-change",first,hello({51:changed_share},extra=entry(44,cookie)+entry(45,b"\x01\x01")+entry(41,psk(b"new",2,2))),False),
             ("psk-removal",first,hello({51:changed_share},extra=entry(44,cookie)+entry(45,b"\x01\x01")),True)]
    return [(name,first,second,cookie,expected) for name,first,second,expected in rows]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    rows = cases()
    with tempfile.TemporaryDirectory(prefix="grounds-server-negotiation-") as td:
        paths = []
        for i, (_, raw, _) in enumerate(rows):
            path = Path(td) / str(i)
            path.write_bytes(raw)
            paths.append(str(path))
        result = subprocess.run(command + paths, text=True, capture_output=True, timeout=40)
        retry_paths=[]
        retries=retry_cases()
        for i,(_,a,b,c,_) in enumerate(retries):
            for part,raw in enumerate((a,b,c)):
                path=Path(td)/f"retry-{i}-{part}"
                path.write_bytes(raw)
                retry_paths.append(str(path))
        retry_result=subprocess.run(command+["retry"]+retry_paths,text=True,capture_output=True,timeout=40)
    observed = result.stdout.splitlines()
    report = {"command": command, "exit": result.returncode, "stderr": result.stderr,
              "cases": [dict(name=n, input_sha256=hashlib.sha256(raw).hexdigest(),
                             expected=expected, observed=observed[i] if i < len(observed) else None)
                        for i, (n, raw, expected) in enumerate(rows)]}
    report["passed"] = result.returncode == 0 and observed == [r[2] for r in rows]
    report["retry_cases"]=[dict(name=n,expected=f"retry:{str(expected).lower()}",observed=got)
                           for (n,_,_,_,expected),got in zip(retries,retry_result.stdout.splitlines())]
    report["passed"] &= retry_result.returncode==0 and retry_result.stdout.splitlines()==[f"retry:{str(row[4]).lower()}" for row in retries]
    if args.report:
        args.report.write_text(json.dumps(report, indent=2) + "\n")
    if not report["passed"]:
        print(json.dumps(report, indent=2))
        raise SystemExit(1)
    print(f"server negotiation: {len(rows)}/{len(rows)}; retry: {len(retries)}/{len(retries)}")


if __name__ == "__main__":
    main()
