#!/bin/sh
set -eu
cd "$(dirname "$0")"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
bend test.bend
bend chacha_test.bend
bend PROOF.bend
bend cli.bend -o "$tmp/sha256" > /dev/null
bend hkdf_cli.bend -o "$tmp/hkdf" > /dev/null
bend chacha_cli.bend -o "$tmp/chacha20" > /dev/null
python3 check.py "$tmp/sha256" "$tmp/hkdf"
python3 chacha_check.py "$tmp/chacha20"
if command -v bun > /dev/null 2>&1; then
  bend chacha_cli.bend -o "$tmp/chacha20.js" > /dev/null
  python3 chacha_check.py bun "$tmp/chacha20.js"
else
  echo "ChaCha20 JS target: Bun unavailable; skipped"
fi
