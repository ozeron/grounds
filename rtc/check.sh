#!/bin/sh
set -eu
cd "$(dirname "$0")"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

bend test.bend
bend integrity_test.bend
bend fingerprint_test.bend
bend sign_test.bend
bend sha256_test.bend
bend examples/auth.bend -o "$tmp/auth" > /dev/null
python3 examples/auth_check.py "$tmp/auth"
bend examples/binding.bend -o "$tmp/binding" > /dev/null
python3 examples/binding_check.py "$tmp/binding"
bend examples/stress.bend -o "$tmp/stress" > /dev/null
"$tmp/stress"
bend examples/integrity.bend -o "$tmp/integrity" > /dev/null
"$tmp/integrity"
bend examples/fingerprint.bend -o "$tmp/fingerprint" > /dev/null
"$tmp/fingerprint"
bend examples/sign.bend -o "$tmp/sign" > /dev/null
"$tmp/sign"

if command -v bun > /dev/null 2>&1; then
  bend examples/auth.bend -o "$tmp/auth.js" > /dev/null
  python3 examples/auth_check.py bun "$tmp/auth.js"
  bend examples/binding.bend -o "$tmp/binding.js" > /dev/null
  python3 examples/binding_check.py bun "$tmp/binding.js"
  bend examples/stress.bend -o "$tmp/stress.js" > /dev/null
  bun "$tmp/stress.js"
  bend examples/integrity.bend -o "$tmp/integrity.js" > /dev/null
  bun "$tmp/integrity.js"
  bend examples/fingerprint.bend -o "$tmp/fingerprint.js" > /dev/null
  bun "$tmp/fingerprint.js"
  bend examples/sign.bend -o "$tmp/sign.js" > /dev/null
  bun "$tmp/sign.js"
else
  echo "RTC JS target: Bun unavailable; skipped"
fi
