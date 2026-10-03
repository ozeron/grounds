"""Independent UTF-8 cookie HMAC interoperability and rejection checks."""

import argparse
import hashlib
import hmac
import json
from pathlib import Path
import random
import subprocess
import tempfile


def signature(key, value):
    return value + "." + hmac.new(key.encode(), value.encode(), hashlib.sha256).hexdigest()


def corpus():
    # Literal RFC 4231 full HMAC-SHA256 vectors, independently pinned here.
    assert signature("\x0b" * 20, "Hi There").endswith(
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    )
    assert signature("Jefe", "what do ya want for nothing?").endswith(
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    )
    cases = []

    def add(kind, key, value, result, category):
        expected = "invalid" if result is None else "ok:" + result.encode().hex()
        cases.append(([kind, key, value], expected, category))

    samples = [
        ("\x0b" * 20, "Hi There"),
        ("Jefe", "what do ya want for nothing?"),
        ("", ""), ("key", ""), ("", "value"),
        ("key", "The quick brown fox jumps over the lazy dog"),
        ("clé.🔑", "café.☕"), ("a\x00b", "x\x00y"),
        ("key", "."), ("key", "..."),
        ("key", "é.e\u0301.\U0010ffff.\u2028"),
        ("key", "\r\nSet-Cookie: injected=1;"),
    ]
    samples += [("k" * n, "v" * m) for n in (1, 31, 32, 63, 64, 65, 131)
                for m in (0, 1, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129)]
    rng = random.Random(4231)
    alphabet = "abcXYZ012.;= \x00\n\téΩ中☕🔑\u0301\U0010ffff"
    samples += [("".join(rng.choices(alphabet, k=rng.randrange(0, 140))),
                 "".join(rng.choices(alphabet, k=rng.randrange(0, 256))))
                for _ in range(128)]
    samples += [("k" * 32, "v" * 4096), ("clé", "☕" * 1365)]
    for key, value in samples:
        signed = signature(key, value)
        add("sign", key, value, signed, "sign")
        add("verify", key, signed, value, "valid")
        head, tag = signed.rsplit(".", 1)
        add("verify", key, head + "." + tag.upper(), value, "uppercase")
        add("verify", key + "x", signed, None, "wrong_key")
        add("verify", key, "x" + signed, None, "changed_value")

    key, value = "synthetic-cookie-key", "café.with.dots.☕"
    signed = signature(key, value)
    head, tag = signed.rsplit(".", 1)
    for at in range(64):
        for replacement in "0123456789abcdef":
            if replacement != tag[at]:
                add("verify", key, head + "." + tag[:at] + replacement + tag[at+1:],
                    None, "changed_tag")
        for replacement in ("g", "G", "/", " ", "\x00", "é", "☕", "\n"):
            add("verify", key, head + "." + tag[:at] + replacement + tag[at+1:],
                None, "malformed_tag")
    malformed = ["", ".", value, head + tag, head + ":" + tag, signed + "0",
                 signed + ".", signed + "\n", head + "." + tag + "00"]
    malformed += [head + "." + tag[:n] for n in range(64)]
    for text in malformed:
        add("verify", key, text, None, "malformed_envelope")
    return cases


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path)
    parser.add_argument("binary", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.binary[1:] if args.binary[:1] == ["--"] else args.binary
    if not command:
        parser.error("binary required")
    cases = corpus()
    with tempfile.TemporaryDirectory(prefix="grounds-cookie-bend-") as temporary:
        fixture = Path(temporary) / "cases.bin"
        for start in range(0, len(cases), 32):
            batch = cases[start:start+32]
            records = bytearray()
            for (kind, key, value), _, _ in batch:
                records.append(1 if kind == "sign" else 2)
                for text in (key, value):
                    encoded = text.encode()
                    records.extend(len(encoded).to_bytes(4, "big"))
                    records.extend(encoded)
            fixture.write_bytes(records)
            result = subprocess.run([*command, str(fixture)], capture_output=True,
                                    text=True, timeout=30)
            if result.returncode:
                raise AssertionError(f"cookie batch {start} exited {result.returncode}: "
                                     f"{result.stdout!r} {result.stderr!r}")
            actual = result.stdout.splitlines()
            expected = [case[1] for case in batch]
            if actual != expected:
                raise AssertionError(f"cookie batch {start}: {actual!r} != {expected!r}")
    counts = {category: sum(case[2] == category for case in cases)
              for category in sorted({case[2] for case in cases})}
    result = dict(binary=command, cases=len(cases), categories=counts,
                  corpus_sha256=hashlib.sha256(json.dumps(cases, ensure_ascii=True,
                      separators=(",", ":")).encode()).hexdigest(),
                  RFC4231_full_tag_vectors=2, synthetic_keys_only=True,
                  timing_or_live_secret_approval=False)
    if args.report:
        args.report.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
