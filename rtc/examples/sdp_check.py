"""Independent SDP admission cases for the bounded application profile."""
import json
import pathlib
import subprocess
import sys
import tempfile

FP = ":".join(f"{n:02X}" for n in range(32))
PWD = "SyntheticBrowserPassword123456"
CANDIDATE = "a=candidate:7 1 UDP 2130706431 127.0.0.1 32123 typ host generation 0 network-cost 999"
BASE = "\r\n".join([
    "v=0", "o=- 111 2 IN IP4 127.0.0.1", "s=-", "t=0 0",
    "a=group:BUNDLE 0", "m=application 9 UDP/DTLS/SCTP webrtc-datachannel",
    "c=IN IP4 0.0.0.0", "a=ice-ufrag:abcd", "a=ice-pwd:" + PWD,
    "a=mid:0", "a=fingerprint:sha-256 " + FP, "a=setup:actpass",
    "a=sctp-port:5000", "a=max-message-size:262144", CANDIDATE, "",
])


def main():
    cases = []

    def add(name, sdp, valid=False, uf="abcd", pwd=PWD, ignored=0, candidates=1):
        cases.append((name, sdp, valid, uf, pwd, ignored, candidates))

    add("browser shape", BASE, True)
    add("LF lines", BASE.replace("\r\n", "\n"), True)
    add("lowercase fingerprint and transport", BASE.replace(FP, FP.lower()).replace(" UDP ", " udp "), True)
    add("session defaults", BASE.replace("a=group:BUNDLE 0", "a=ice-ufrag:abcd\r\na=ice-pwd:" + PWD)
        .replace("a=ice-ufrag:abcd\r\na=ice-pwd:" + PWD + "\r\na=mid", "a=mid"), True)
    add("media overrides", BASE.replace("a=group:BUNDLE 0", "a=ice-ufrag:default\r\na=ice-pwd:DefaultPassword123456789"), True)
    add("empty candidate list permits peer reflexive learning", BASE.replace(CANDIDATE + "\r\n", ""), True, candidates=0)
    for label, candidate in [
        ("IPv6", CANDIDATE.replace("127.0.0.1", "::1")),
        ("mDNS", CANDIDATE.replace("127.0.0.1", "fixture.local")),
        ("TCP", CANDIDATE.replace(" UDP ", " TCP ") + " tcptype passive"),
    ]:
        add("ignore " + label, BASE.replace(CANDIDATE, candidate), True, ignored=1, candidates=0)
    add("10 digit priority", BASE.replace("2130706431", "2147483647"), True)
    add("remote ufrag maximum", BASE.replace("abcd", "a" * 256), True, uf="a" * 256)
    add("remote password maximum", BASE.replace(PWD, "p" * 256), True, pwd="p" * 256)
    add("related reflexive", BASE.replace("typ host generation 0 network-cost 999", "typ srflx raddr 0.0.0.0 rport 9 extension opaque"), True)
    add("unknown candidate kind", BASE.replace("typ host", "typ future"), True, ignored=1, candidates=0)
    for field in ["ice-ufrag", "ice-pwd", "mid", "fingerprint", "setup", "sctp-port"]:
        row = next(row for row in BASE.splitlines() if row.startswith("a=" + field + ":"))
        add("missing " + field, BASE.replace(row + "\r\n", ""))
        add("duplicate " + field, BASE.replace(row, row + "\r\n" + row))
    for label, old, new in [
        ("ufrag short", "abcd", "abc"), ("ufrag overlong", "abcd", "a" * 257),
        ("ufrag invalid character", "abcd", "ab:cd"), ("password short", PWD, "p" * 21),
        ("password overlong", PWD, "p" * 257), ("wrong hash", "sha-256", "sha-1"),
        ("fingerprint short", FP, FP[:-3]), ("fingerprint long", FP, FP + ":00"),
        ("fingerprint bad hex", FP, FP.replace("0A", "GG")),
        ("setup passive offer", "actpass", "passive"), ("SCTP zero", "sctp-port:5000", "sctp-port:0"),
        ("SCTP overflow", "sctp-port:5000", "sctp-port:4294967296"),
        ("candidate priority zero", "2130706431", "0"),
        ("candidate priority overflow", "2130706431", "4294967296"),
        ("candidate integer overflow", "2130706431", "18446744073709551616"),
        ("candidate negative", "2130706431", "-1"),
        ("candidate port zero", "32123", "0"), ("candidate port overflow", "32123", "65536"),
        ("candidate component zero", "7 1 UDP", "7 0 UDP"),
        ("candidate component overflow", "7 1 UDP", "7 257 UDP"),
        ("candidate foundation invalid", "candidate:7", "candidate:bad-foundation"),
        ("extension missing value", "network-cost 999", "network-cost"),
        ("related missing", "typ host", "typ srflx"),
        ("wrong media", "m=application", "m=audio"),
        ("disabled media", "m=application 9", "m=application 0"),
        ("host related address forbidden", "typ host generation 0 network-cost 999", "typ host raddr 127.0.0.1 rport 9"),
        ("wrong transport", "UDP/DTLS/SCTP", "TCP/DTLS/SCTP"),
        ("wrong version", "v=0", "v=1"),
    ]:
        add(label, BASE.replace(old, new))
    add("duplicate media", BASE + "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n")
    add("candidate before media", BASE.replace("a=group:BUNDLE 0", CANDIDATE))
    add("embedded CR", BASE.replace("a=mid:0", "a=mid:0\rINJECT"))
    add("NUL", BASE.replace("a=mid:0", "a=mid:0\x00"))
    add("non ASCII", BASE.replace("a=mid:0", "a=mid:é"))
    add("unknown SDP field", BASE + "x=invalid\r\n")
    add("line bound", BASE + "a=extension:" + "x" * 1024 + "\r\n")
    add("document bound", BASE + "x" * 16385)
    add("line count bound", BASE + "a=opaque:value\r\n" * 130)
    add("candidate count bound", BASE.replace(CANDIDATE, "\r\n".join(CANDIDATE.replace("32123", str(32000 + i)) for i in range(65))))
    add("candidate count maximum", BASE.replace(CANDIDATE, "\r\n".join(CANDIDATE.replace("32123", str(32000 + i)) for i in range(64))), True, candidates=64)

    with tempfile.TemporaryDirectory() as temp:
        path = pathlib.Path(temp) / "sdp.json"
        path.write_text(json.dumps([case[1] for case in cases]))
        result = subprocess.run([*sys.argv[1:], str(path)], capture_output=True, text=True, timeout=60, check=True)
    rows = [part.strip().splitlines() for part in result.stdout.split("end\n") if part.strip()]
    assert len(rows) == len(cases), (len(rows), len(cases), result.stdout[-1000:])
    for (name, _, valid, uf, pwd, ignored, count), output in zip(cases, rows):
        if valid:
            assert output[0] == f"valid:{uf}:{pwd}:0:{bytes(range(32)).hex()}:5000:{ignored}", (name, output)
            assert len(output) == count + 1, (name, output)
        else:
            assert len(output) == 1 and output[0].startswith("invalid:"), (name, output)
    print(f"SDP: {len(cases)} admission, override, candidate, malformed and bound cases passed")


if __name__ == "__main__":
    main()
