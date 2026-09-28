"""Compare Bend cookie signatures with Python's HMAC-SHA256."""

import hashlib
import hmac
import subprocess
import sys

values = ("The quick brown fox jumps over the lazy dog", "café.☕")
expected = [
    value + "." + hmac.new(b"key", value.encode(), hashlib.sha256).hexdigest()
    for value in values
]
expected.append("verified; tampered, wrong-key and malformed signatures rejected")

result = subprocess.run([sys.argv[1]], capture_output=True, text=True, check=True)
assert result.stdout.splitlines() == expected, result.stdout
print("cookie signatures: Python HMAC-SHA256 vectors; valid and invalid verification")
