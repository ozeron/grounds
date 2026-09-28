#!/bin/sh
set -eu
cd "$(dirname "$0")"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

bend test.bend
bend integrity_test.bend
bend fingerprint_test.bend
bend examples/binding.bend -o "$tmp/binding" > /dev/null
python3 examples/binding_check.py "$tmp/binding"
bend examples/stress.bend -o "$tmp/stress" > /dev/null
"$tmp/stress"
bend examples/integrity.bend -o "$tmp/integrity" > /dev/null
"$tmp/integrity"
bend examples/fingerprint.bend -o "$tmp/fingerprint" > /dev/null
"$tmp/fingerprint"

if command -v bun > /dev/null 2>&1; then
  bend examples/binding.bend -o "$tmp/binding.js" > /dev/null
  python3 examples/binding_check.py bun "$tmp/binding.js"
  bend examples/stress.bend -o "$tmp/stress.js" > /dev/null
  bun "$tmp/stress.js"
  bend examples/integrity.bend -o "$tmp/integrity.js" > /dev/null
  bun "$tmp/integrity.js"
  bend examples/fingerprint.bend -o "$tmp/fingerprint.js" > /dev/null
  bun "$tmp/fingerprint.js"
else
  echo "RTC JS target: Bun unavailable; skipped"
fi
