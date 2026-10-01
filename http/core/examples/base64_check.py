"""RFC 4648 vectors and independent strict canonical Base64 admission."""
import base64
import binascii
import json
from pathlib import Path
import random
import subprocess
import sys
import tempfile


def canonical(text):
    try:
        raw = base64.b64decode(text.encode("ascii"), validate=True)
    except (UnicodeError, ValueError, binascii.Error):
        return "invalid"
    return "ok:" + raw.hex() if base64.b64encode(raw).decode("ascii") == text else "invalid"


def main():
    # RFC 4648 section 10. The re-encoding check enforces this library's
    # existing rejection of nonzero pad bits, permitted by section 3.5.
    vectors = [(b"", ""), (b"f", "Zg=="), (b"fo", "Zm8="), (b"foo", "Zm9v"),
               (b"foob", "Zm9vYg=="), (b"fooba", "Zm9vYmE="), (b"foobar", "Zm9vYmFy")]
    cases = [text for _, text in vectors]
    assert [canonical(text) for _, text in vectors] == ["ok:" + raw.hex() for raw, _ in vectors]
    rng = random.Random(4648)
    for length in range(129):
        cases.append(base64.b64encode(rng.randbytes(length)).decode("ascii"))
    for byte in range(256):
        cases.append(base64.b64encode(bytes([byte])).decode("ascii"))
        cases.append(base64.b64encode(bytes([byte, 255 - byte])).decode("ascii"))
    cases += [base64.b64encode(bytes(range(256))).decode("ascii")]
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    cases += ["Z" + digit + "==" for digit in alphabet]
    cases += ["Zm" + digit + "=" for digit in alphabet]
    for char in ("=", " ", "\t", "\n", "\r", "\x00", "-", "_", "!", "é", "😀"):
        for index in range(4):
            cases.append("Zm9v"[:index] + char + "Zm9v"[index + 1:])
    cases += ["=", "==", "===", "====", "Z", "Zg", "Zg=", "Zg===", "Zg==AAAA",
              "Zm8=AAAA", "AAAA=", "AAAA====", "Zg==\n", " Zg==", "Zg== ", "Zm9vZg==", "Zm9vZm8="]
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "base64.json"
        path.write_text(json.dumps(cases))
        result = subprocess.run([*sys.argv[1:], str(path)], capture_output=True, text=True, timeout=60, check=True)
    rows = result.stdout.splitlines()
    assert len(rows) == len(cases), (len(rows), len(cases), result.stderr)
    for text, row in zip(cases, rows):
        assert row == canonical(text), (repr(text), row, canonical(text))
    print(f"Base64: {len(cases)} RFC, byte, canonical-padding, alphabet and malformed cases passed")


if __name__ == "__main__":
    main()
