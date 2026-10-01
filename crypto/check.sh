#!/bin/sh
set -eu
cd "$(dirname "$0")"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
bend test.bend
bend chacha_test.bend
bend aead_test.bend
bend hmac_sha1_test.bend
bend x25519_test.bend
bend traffic_test.bend
python3 traffic_type_check.py
bend PROOF.bend
bend cli.bend -o "$tmp/sha256" > /dev/null
bend sha1_cli.bend -o "$tmp/sha1" > /dev/null
bend hmac_sha1_cli.bend -o "$tmp/hmac_sha1" > /dev/null
bend hkdf_cli.bend -o "$tmp/hkdf" > /dev/null
bend chacha_cli.bend -o "$tmp/chacha20" > /dev/null
bend poly1305_cli.bend -o "$tmp/poly1305" > /dev/null
bend aead_cli.bend -o "$tmp/aead" > /dev/null
bend field_cli.bend -o "$tmp/field25519" > /dev/null
bend x25519_cli.bend -o "$tmp/x25519" > /dev/null
bend traffic_cli.bend -o "$tmp/traffic" > /dev/null
python3 check.py "$tmp/sha256" "$tmp/hkdf"
python3 sha1_check.py --long "$tmp/sha1"
python3 hmac_sha1_check.py "$tmp/hmac_sha1"
python3 chacha_check.py "$tmp/chacha20"
python3 poly1305_check.py "$tmp/poly1305"
python3 aead_check.py "$tmp/aead"
python3 field_check.py "$tmp/field25519"
python3 x25519_check.py --iterated "$tmp/x25519"
python3 traffic_check.py "$tmp/traffic"
if command -v bun > /dev/null 2>&1; then
  bend sha1_cli.bend -o "$tmp/sha1.js" > /dev/null
  bend hmac_sha1_cli.bend -o "$tmp/hmac_sha1.js" > /dev/null
  bend chacha_cli.bend -o "$tmp/chacha20.js" > /dev/null
  bend poly1305_cli.bend -o "$tmp/poly1305.js" > /dev/null
  bend aead_cli.bend -o "$tmp/aead.js" > /dev/null
  bend field_cli.bend -o "$tmp/field25519.js" > /dev/null
  bend x25519_cli.bend -o "$tmp/x25519.js" > /dev/null
  bend traffic_cli.bend -o "$tmp/traffic.js" > /dev/null
  python3 sha1_check.py bun "$tmp/sha1.js"
  python3 hmac_sha1_check.py bun "$tmp/hmac_sha1.js"
  python3 chacha_check.py bun "$tmp/chacha20.js"
  python3 poly1305_check.py bun "$tmp/poly1305.js"
  python3 aead_check.py bun "$tmp/aead.js"
  python3 field_check.py bun "$tmp/field25519.js"
  python3 x25519_check.py bun "$tmp/x25519.js"
  python3 traffic_check.py bun "$tmp/traffic.js"
else
  echo "crypto JS target: Bun unavailable; skipped"
fi
