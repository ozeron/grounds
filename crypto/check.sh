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
bend rsa_integer_test.bend
bend rsa_signature256_test.bend
bend der_test.bend
BUN_JSC_useJIT=false bend x509_algorithm_test.bend
BUN_JSC_useJIT=false bend x509_public_key_test.bend
BUN_JSC_useJIT=false bend x509_certificate_test.bend
BUN_JSC_useJIT=false bend x509_validity_test.bend
BUN_JSC_useJIT=false bend x509_extensions_test.bend --check-only
bend x509_constraints_test.bend
bend x509_eku_test.bend
bend x509_identity_test.bend
bend x509_hostname_test.bend --check-only
bend x509_san_test.bend --check-only
bend x509_name_test.bend --check-only
bend x509_extension_policy_test.bend
BUN_JSC_useJIT=false bend x509_verify_cli.bend --check-only
bend traffic_test.bend
python3 traffic_type_check.py
python3 sha256_stream_type_check.py
bend PROOF.bend
../tools/bend_native.sh cli.bend "$tmp/sha256" > /dev/null
../tools/bend_native.sh sha256_stream_cli.bend "$tmp/sha_stream" > /dev/null
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
../tools/bend_native.sh rsa_integer_cli.bend "$tmp/rsa_integer" > /dev/null
../tools/bend_native.sh rsa_signature256_cli.bend "$tmp/rsa_signature" > /dev/null
../tools/bend_native.sh der_cli.bend "$tmp/der" > /dev/null
BUN_JSC_useJIT=false ../tools/bend_native.sh x509_key_cli.bend "$tmp/x509_key" > /dev/null
BUN_JSC_useJIT=false ../tools/bend_native.sh x509_signature_cli.bend "$tmp/x509_signature" > /dev/null
BUN_JSC_useJIT=false ../tools/bend_native.sh x509_binding_cli.bend "$tmp/x509_binding" > /dev/null
BUN_JSC_useJIT=false ../tools/bend_native.sh x509_public_key_cli.bend "$tmp/x509_public_key" > /dev/null
BUN_JSC_useJIT=false ../tools/bend_native.sh x509_certificate_cli.bend "$tmp/x509_certificate" > /dev/null
BUN_JSC_useJIT=false ../tools/bend_native.sh x509_validity_cli.bend "$tmp/x509_validity" > /dev/null
BUN_JSC_useJIT=false ../tools/bend_native.sh x509_extensions_cli.bend "$tmp/x509_extensions" > /dev/null
../tools/bend_native.sh x509_constraints_cli.bend "$tmp/x509_constraints" > /dev/null
../tools/bend_native.sh x509_eku_cli.bend "$tmp/x509_eku" > /dev/null
../tools/bend_native.sh x509_identity_cli.bend "$tmp/x509_identity" > /dev/null
../tools/bend_native.sh x509_hostname_cli.bend "$tmp/x509_hostname" > /dev/null
../tools/bend_native.sh x509_san_cli.bend "$tmp/x509_san" > /dev/null
../tools/bend_native.sh x509_name_cli.bend "$tmp/x509_name" > /dev/null
../tools/bend_native.sh x509_extension_policy_cli.bend "$tmp/x509_extension_policy" > /dev/null
BUN_JSC_useJIT=false ../tools/bend_native.sh x509_verify_cli.bend "$tmp/x509_verify" > /dev/null
../tools/bend_native.sh x25519_cli.bend "$tmp/x25519" > /dev/null
../tools/bend_native.sh traffic_write_cli.bend "$tmp/traffic_write" > /dev/null
../tools/bend_native.sh traffic_read_cli.bend "$tmp/traffic_read" > /dev/null
python3 check.py "$tmp/sha256" "$tmp/hkdf"
python3 sha256_stream_check.py "$tmp/sha_stream" "$tmp/sha256"
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
python3 rsa_integer_check.py -- "$tmp/rsa_integer"
python3 rsa_signature256_check.py -- "$tmp/rsa_signature"
python3 der_check.py -- "$tmp/der"
python3 x509_algorithm_check.py -- python3 x509_algorithm_fixture.py --key "$tmp/x509_key" --signature "$tmp/x509_signature" --binding "$tmp/x509_binding" --der "$tmp/der" --
python3 x509_public_key_check.py -- "$tmp/x509_public_key"
python3 x509_certificate_check.py -- "$tmp/x509_certificate"
python3 x509_validity_check.py -- "$tmp/x509_validity"
python3 x509_extensions_check.py -- "$tmp/x509_extensions"
python3 x509_constraints_check.py -- "$tmp/x509_constraints"
python3 x509_eku_check.py -- "$tmp/x509_eku"
python3 x509_hostname_check.py --scope identity -- "$tmp/x509_identity"
python3 x509_hostname_check.py -- "$tmp/x509_hostname"
python3 x509_san_check.py -- "$tmp/x509_san"
python3 x509_name_check.py -- "$tmp/x509_name"
python3 x509_extension_policy_check.py --signature-binary "$tmp/x509_verify" -- "$tmp/x509_extension_policy"
python3 x509_signature_check.py -- "$tmp/x509_verify"
python3 x25519_check.py --iterated "$tmp/x25519"
python3 traffic_check.py python3 traffic_fixture.py --write "$tmp/traffic_write" --read "$tmp/traffic_read" --
python3 traffic_aes_check.py python3 traffic_fixture.py --write "$tmp/traffic_write" --read "$tmp/traffic_read" --
if command -v bun > /dev/null 2>&1; then
  bend cli.bend -o "$tmp/sha256.js" > /dev/null
  bend sha256_stream_cli.bend -o "$tmp/sha_stream.js" > /dev/null
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
  bend rsa_integer_cli.bend -o "$tmp/rsa_integer.js" > /dev/null
  bend rsa_signature256_cli.bend -o "$tmp/rsa_signature.js" > /dev/null
  bend der_cli.bend -o "$tmp/der.js" > /dev/null
  BUN_JSC_useJIT=false bend x509_key_cli.bend -o "$tmp/x509_key.js" > /dev/null
  BUN_JSC_useJIT=false bend x509_signature_cli.bend -o "$tmp/x509_signature.js" > /dev/null
  BUN_JSC_useJIT=false bend x509_binding_cli.bend -o "$tmp/x509_binding.js" > /dev/null
  BUN_JSC_useJIT=false bend x509_public_key_cli.bend -o "$tmp/x509_public_key.js" > /dev/null
  BUN_JSC_useJIT=false bend x509_certificate_cli.bend -o "$tmp/x509_certificate.js" > /dev/null
  BUN_JSC_useJIT=false bend x509_validity_cli.bend -o "$tmp/x509_validity.js" > /dev/null
  BUN_JSC_useJIT=false bend x509_extensions_cli.bend -o "$tmp/x509_extensions.js" > /dev/null
  bend x509_constraints_cli.bend -o "$tmp/x509_constraints.js" > /dev/null
  bend x509_eku_cli.bend -o "$tmp/x509_eku.js" > /dev/null
  bend x509_identity_cli.bend -o "$tmp/x509_identity.js" > /dev/null
  bend x509_hostname_cli.bend -o "$tmp/x509_hostname.js" > /dev/null
  bend x509_san_cli.bend -o "$tmp/x509_san.js" > /dev/null
  bend x509_name_cli.bend -o "$tmp/x509_name.js" > /dev/null
  bend x509_extension_policy_cli.bend -o "$tmp/x509_extension_policy.js" > /dev/null
  BUN_JSC_useJIT=false bend x509_verify_cli.bend -o "$tmp/x509_verify.js" > /dev/null
  bend x25519_cli.bend -o "$tmp/x25519.js" > /dev/null
  bend traffic_write_cli.bend -o "$tmp/traffic_write.js" > /dev/null
  bend traffic_read_cli.bend -o "$tmp/traffic_read.js" > /dev/null
  python3 check.py --bun "$tmp/sha256.js" "$tmp/hkdf.js"
  python3 sha256_stream_check.py --bun "$tmp/sha_stream.js" "$tmp/sha256.js"
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
  python3 rsa_integer_check.py -- bun "$tmp/rsa_integer.js"
  python3 rsa_signature256_check.py -- bun "$tmp/rsa_signature.js"
  python3 der_check.py -- bun "$tmp/der.js"
  python3 x509_algorithm_check.py -- python3 x509_algorithm_fixture.py --bun --key "$tmp/x509_key.js" --signature "$tmp/x509_signature.js" --binding "$tmp/x509_binding.js" --der "$tmp/der.js" --
  python3 x509_public_key_check.py -- bun "$tmp/x509_public_key.js"
  python3 x509_certificate_check.py -- bun "$tmp/x509_certificate.js"
  python3 x509_validity_check.py -- bun "$tmp/x509_validity.js"
  python3 x509_extensions_check.py -- bun "$tmp/x509_extensions.js"
  python3 x509_constraints_check.py -- bun "$tmp/x509_constraints.js"
  python3 x509_eku_check.py -- bun "$tmp/x509_eku.js"
  python3 x509_hostname_check.py --scope identity -- bun "$tmp/x509_identity.js"
  python3 x509_hostname_check.py -- bun "$tmp/x509_hostname.js"
  python3 x509_san_check.py -- bun "$tmp/x509_san.js"
  python3 x509_name_check.py -- bun "$tmp/x509_name.js"
  python3 x509_extension_policy_check.py --bun --signature-binary "$tmp/x509_verify.js" -- bun "$tmp/x509_extension_policy.js"
  python3 x509_signature_check.py -- bun "$tmp/x509_verify.js"
  python3 x25519_check.py bun "$tmp/x25519.js"
  python3 traffic_check.py python3 traffic_fixture.py --bun --write "$tmp/traffic_write.js" --read "$tmp/traffic_read.js" --
  python3 traffic_aes_check.py python3 traffic_fixture.py --bun --write "$tmp/traffic_write.js" --read "$tmp/traffic_read.js" --
else
  echo "crypto JS target: Bun unavailable; skipped"
fi
