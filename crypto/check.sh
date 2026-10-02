#!/bin/sh
set -eu
cd "$(dirname "$0")"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
bend test.bend
bend chacha_test.bend
bend aead_test.bend
bend aes128_test.bend
bend gcm_test.bend
bend hmac_sha1_test.bend
bend x25519_test.bend
bend field256_test.bend
bend p256_test.bend
bend ecdsa256_test.bend
bend rsa_encoding_test.bend
bend traffic_test.bend
python3 traffic_type_check.py
bend PROOF.bend
../tools/bend_native.sh cli.bend "$tmp/sha256" > /dev/null
../tools/bend_native.sh sha1_cli.bend "$tmp/sha1" > /dev/null
../tools/bend_native.sh hmac_sha1_cli.bend "$tmp/hmac_sha1" > /dev/null
../tools/bend_native.sh hkdf_cli.bend "$tmp/hkdf" > /dev/null
../tools/bend_native.sh chacha_cli.bend "$tmp/chacha20" > /dev/null
../tools/bend_native.sh poly1305_cli.bend "$tmp/poly1305" > /dev/null
../tools/bend_native.sh aead_cli.bend "$tmp/aead" > /dev/null
../tools/bend_native.sh aes128_cli.bend "$tmp/aes128" > /dev/null
../tools/bend_native.sh gcm_cli.bend "$tmp/gcm" > /dev/null
../tools/bend_native.sh field_cli.bend "$tmp/field25519" > /dev/null
../tools/bend_native.sh field256_cli.bend "$tmp/field256" > /dev/null
../tools/bend_native.sh p256_cli.bend "$tmp/p256" > /dev/null
../tools/bend_native.sh ecdsa_scheme256_cli.bend "$tmp/ecdsa_scheme" > /dev/null
../tools/bend_native.sh ecdsa256_cli.bend "$tmp/ecdsa_verify" > /dev/null
../tools/bend_native.sh ecdsa_sign256_cli.bend "$tmp/ecdsa_sign" > /dev/null
../tools/bend_native.sh ecdsa_reject256_cli.bend "$tmp/ecdsa_reject" > /dev/null
../tools/bend_native.sh ecdsa_der256_cli.bend "$tmp/ecdsa_der" > /dev/null
../tools/bend_native.sh rsa_encoding_cli.bend "$tmp/rsa_encoding" > /dev/null
../tools/bend_native.sh x25519_cli.bend "$tmp/x25519" > /dev/null
../tools/bend_native.sh traffic_write_cli.bend "$tmp/traffic_write" > /dev/null
../tools/bend_native.sh traffic_read_cli.bend "$tmp/traffic_read" > /dev/null
python3 check.py "$tmp/sha256" "$tmp/hkdf"
python3 sha1_check.py --long "$tmp/sha1"
python3 hmac_sha1_check.py "$tmp/hmac_sha1"
python3 chacha_check.py "$tmp/chacha20"
python3 poly1305_check.py "$tmp/poly1305"
python3 aead_check.py "$tmp/aead"
python3 aes128_check.py "$tmp/aes128"
python3 gcm_check.py "$tmp/gcm"
python3 field_check.py "$tmp/field25519"
python3 field256_check.py "$tmp/field256"
python3 p256_check.py "$tmp/p256"
python3 ecdsa_check.py -- python3 ecdsa_fixture.py --scheme "$tmp/ecdsa_scheme" --verify "$tmp/ecdsa_verify" --sign "$tmp/ecdsa_sign" --reject "$tmp/ecdsa_reject" --der "$tmp/ecdsa_der" --
python3 ecdsa_der_check.py "$tmp/ecdsa_der"
python3 rsa_encoding_check.py -- "$tmp/rsa_encoding"
python3 x25519_check.py --iterated "$tmp/x25519"
python3 traffic_check.py python3 traffic_fixture.py --write "$tmp/traffic_write" --read "$tmp/traffic_read" --
python3 traffic_aes_check.py python3 traffic_fixture.py --write "$tmp/traffic_write" --read "$tmp/traffic_read" --
if command -v bun > /dev/null 2>&1; then
  bend cli.bend -o "$tmp/sha256.js" > /dev/null
  bend hkdf_cli.bend -o "$tmp/hkdf.js" > /dev/null
  bend sha1_cli.bend -o "$tmp/sha1.js" > /dev/null
  bend hmac_sha1_cli.bend -o "$tmp/hmac_sha1.js" > /dev/null
  bend chacha_cli.bend -o "$tmp/chacha20.js" > /dev/null
  bend poly1305_cli.bend -o "$tmp/poly1305.js" > /dev/null
  bend aead_cli.bend -o "$tmp/aead.js" > /dev/null
  bend aes128_cli.bend -o "$tmp/aes128.js" > /dev/null
  bend gcm_cli.bend -o "$tmp/gcm.js" > /dev/null
  bend field_cli.bend -o "$tmp/field25519.js" > /dev/null
  bend field256_cli.bend -o "$tmp/field256.js" > /dev/null
  bend p256_cli.bend -o "$tmp/p256.js" > /dev/null
  bend ecdsa_scheme256_cli.bend -o "$tmp/ecdsa_scheme.js" > /dev/null
  bend ecdsa256_cli.bend -o "$tmp/ecdsa_verify.js" > /dev/null
  bend ecdsa_sign256_cli.bend -o "$tmp/ecdsa_sign.js" > /dev/null
  bend ecdsa_reject256_cli.bend -o "$tmp/ecdsa_reject.js" > /dev/null
  bend ecdsa_der256_cli.bend -o "$tmp/ecdsa_der.js" > /dev/null
  bend rsa_encoding_cli.bend -o "$tmp/rsa_encoding.js" > /dev/null
  bend x25519_cli.bend -o "$tmp/x25519.js" > /dev/null
  bend traffic_write_cli.bend -o "$tmp/traffic_write.js" > /dev/null
  bend traffic_read_cli.bend -o "$tmp/traffic_read.js" > /dev/null
  python3 check.py --bun "$tmp/sha256.js" "$tmp/hkdf.js"
  python3 sha1_check.py bun "$tmp/sha1.js"
  python3 hmac_sha1_check.py bun "$tmp/hmac_sha1.js"
  python3 chacha_check.py bun "$tmp/chacha20.js"
  python3 poly1305_check.py bun "$tmp/poly1305.js"
  python3 aead_check.py bun "$tmp/aead.js"
  python3 aes128_check.py bun "$tmp/aes128.js"
  python3 gcm_check.py bun "$tmp/gcm.js"
  python3 field_check.py bun "$tmp/field25519.js"
  python3 field256_check.py bun "$tmp/field256.js"
  python3 p256_check.py bun "$tmp/p256.js"
  python3 ecdsa_check.py -- python3 ecdsa_fixture.py --bun --scheme "$tmp/ecdsa_scheme.js" --verify "$tmp/ecdsa_verify.js" --sign "$tmp/ecdsa_sign.js" --reject "$tmp/ecdsa_reject.js" --der "$tmp/ecdsa_der.js" --
  python3 ecdsa_der_check.py bun "$tmp/ecdsa_der.js"
  python3 rsa_encoding_check.py -- bun "$tmp/rsa_encoding.js"
  python3 x25519_check.py bun "$tmp/x25519.js"
  python3 traffic_check.py python3 traffic_fixture.py --bun --write "$tmp/traffic_write.js" --read "$tmp/traffic_read.js" --
  python3 traffic_aes_check.py python3 traffic_fixture.py --bun --write "$tmp/traffic_write.js" --read "$tmp/traffic_read.js" --
else
  echo "crypto JS target: Bun unavailable; skipped"
fi
