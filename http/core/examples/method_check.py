"""HTTP method classification and exact preservation of unknown spellings."""
import json
from pathlib import Path
import random
import subprocess
import sys
import tempfile


def main():
    known = {"GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"}
    cases = sorted(known)
    alphabet = [chr(value) for value in range(128)] + ["é", "€", "😀"]
    for word in sorted(known):
        cases += [word.lower(), word.swapcase()]
        cases += [word[:length] for length in range(len(word))]
        for position in range(len(word)):
            for char in alphabet:
                cases.append(word[:position] + char + word[position + 1:])
        cases += [word + char for char in alphabet]
        cases += [char + word for char in alphabet]
        cases += [word + word, word + "x" * 4096]
    cases += ["", "P", "PX", "PURGE", "PROPFIND", "MKCOL", "get", "pAtCh", "😀GET"]
    rng = random.Random(9110)
    for _ in range(100):
        cases.append("".join(rng.choices(alphabet, k=rng.randrange(65))))
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "method.json"
        # Keep the complete corpus, but release evaluator fixture allocations
        # between batches. One giant JSON array exceeds the guarded Bun budget.
        for start in range(0, len(cases), 256):
            batch = cases[start:start + 256]
            path.write_text(json.dumps(batch))
            result = subprocess.run([*sys.argv[1:], str(path)], capture_output=True, text=True, timeout=60, check=True)
            rows = result.stdout.splitlines()
            assert len(rows) == len(batch), (start, len(rows), len(batch), result.stderr)
            for text, row in zip(batch, rows):
                expected = text if text in known else "other:" + text.encode("utf-8").hex()
                assert row == expected, (repr(text), row, expected)
    print(f"Methods: {len(cases)} known, case, prefix, suffix, byte/Unicode and unknown-preservation cases passed")


if __name__ == "__main__":
    main()
