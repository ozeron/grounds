#!/bin/sh
set -eu
cd "$(dirname "$0")"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
bend test.bend
bend chacha_test.bend
bend aead_test.bend
bend PROOF.bend
bend cli.bend -o "$tmp/sha256" > /dev/null
bend hkdf_cli.bend -o "$tmp/hkdf" > /dev/null
bend chacha_cli.bend -o "$tmp/chacha20" > /dev/null
bend poly1305_cli.bend -o "$tmp/poly1305" > /dev/null
bend aead_cli.bend -o "$tmp/aead" > /dev/null
python3 check.py "$tmp/sha256" "$tmp/hkdf"
python3 chacha_check.py "$tmp/chacha20"
python3 poly1305_check.py "$tmp/poly1305"
python3 aead_check.py "$tmp/aead"
if command -v bun > /dev/null 2>&1; then
  bend chacha_cli.bend -o "$tmp/chacha20.js" > /dev/null
  bend poly1305_cli.bend -o "$tmp/poly1305.js" > /dev/null
  bend aead_cli.bend -o "$tmp/aead.js" > /dev/null
  python3 chacha_check.py bun "$tmp/chacha20.js"
  python3 poly1305_check.py bun "$tmp/poly1305.js"
  python3 aead_check.py bun "$tmp/aead.js"
else
  echo "ChaCha20/Poly1305 JS target: Bun unavailable; skipped"
fi
