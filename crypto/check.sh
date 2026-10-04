#!/bin/sh
set -eu
cd "$(dirname "$0")"
tmp=$(mktemp -d)
phase=
announce() { python3 ../tools/check_phase.py "$@" >&2; }
check() {
  phase="crypto/$1"
  shift
  announce start "$phase"
  "$@"
  announce end "$phase" 0
  phase=
}
cleanup() {
  result=$?
  trap - EXIT
  set +e
  if [ -n "$phase" ]; then
    announce end "$phase" "$result" || result=125
  fi
  rm -rf "$tmp"
  exit "$result"
}
trap cleanup EXIT
check frontend/test bend test.bend
check frontend/chacha_test bend chacha_test.bend
check frontend/aead_test bend aead_test.bend
check frontend/aes128_test bend aes128_test.bend
check frontend/gcm_test bend gcm_test.bend
check frontend/hmac_sha1_test bend hmac_sha1_test.bend
check frontend/x25519_test bend x25519_test.bend
check frontend/field256_test bend field256_test.bend
check frontend/p256_test bend p256_test.bend
check frontend/ecdsa256_test bend ecdsa256_test.bend
check frontend/rsa_encoding_test bend rsa_encoding_test.bend
check frontend/rsa_integer_test bend rsa_integer_test.bend
check frontend/rsa_signature256_test bend rsa_signature256_test.bend
check frontend/der_test bend der_test.bend
check frontend/x509_algorithm_test env BUN_JSC_useJIT=false bend x509_algorithm_test.bend
check frontend/x509_public_key_test env BUN_JSC_useJIT=false bend x509_public_key_test.bend
check frontend/x509_certificate_test env BUN_JSC_useJIT=false bend x509_certificate_test.bend
check frontend/x509_validity_test env BUN_JSC_useJIT=false bend x509_validity_test.bend
check frontend/x509_extensions_test env BUN_JSC_useJIT=false bend x509_extensions_test.bend --check-only
check frontend/x509_constraints_test bend x509_constraints_test.bend
check frontend/x509_eku_test bend x509_eku_test.bend
check frontend/x509_identity_test bend x509_identity_test.bend
check frontend/x509_hostname_test bend x509_hostname_test.bend --check-only
check frontend/x509_san_test bend x509_san_test.bend --check-only
check frontend/unicode32_profile_test bend unicode32_profile_test.bend --check-only
check frontend/unicode32_fold_test bend unicode32_fold_test.bend --check-only
check frontend/unicode32_nfkc_test bend unicode32_nfkc_test.bend --check-only
check frontend/unicode32_prepare_test bend unicode32_prepare_test.bend --check-only
check frontend/x509_name_test bend x509_name_test.bend --check-only
check frontend/x509_name_text_test bend x509_name_text_test.bend
check frontend/x509_extension_policy_test bend x509_extension_policy_test.bend
check frontend/x509_verify_cli env BUN_JSC_useJIT=false bend x509_verify_cli.bend --check-only
check frontend/traffic_test bend traffic_test.bend
check frontend/traffic_type_check python3 traffic_type_check.py
check frontend/sha256_stream_type_check python3 sha256_stream_type_check.py
check frontend/proof bend PROOF.bend
check native/build/cli ../tools/bend_native.sh cli.bend "$tmp/sha256" > /dev/null
check native/build/sha256_stream_cli ../tools/bend_native.sh sha256_stream_cli.bend "$tmp/sha_stream" > /dev/null
check native/build/sha1_cli ../tools/bend_native.sh sha1_cli.bend "$tmp/sha1" > /dev/null
check native/build/hmac_sha1_cli ../tools/bend_native.sh hmac_sha1_cli.bend "$tmp/hmac_sha1" > /dev/null
check native/build/hkdf_cli ../tools/bend_native.sh hkdf_cli.bend "$tmp/hkdf" > /dev/null
check native/build/chacha_cli ../tools/bend_native.sh chacha_cli.bend "$tmp/chacha20" > /dev/null
check native/build/poly1305_cli ../tools/bend_native.sh poly1305_cli.bend "$tmp/poly1305" > /dev/null
check native/build/aead_cli ../tools/bend_native.sh aead_cli.bend "$tmp/aead" > /dev/null
check native/build/aes128_cli ../tools/bend_native.sh aes128_cli.bend "$tmp/aes128" > /dev/null
check native/build/gcm_cli ../tools/bend_native.sh gcm_cli.bend "$tmp/gcm" > /dev/null
check native/build/field_cli ../tools/bend_native.sh field_cli.bend "$tmp/field25519" > /dev/null
check native/build/field256_cli ../tools/bend_native.sh field256_cli.bend "$tmp/field256" > /dev/null
check native/build/p256_cli ../tools/bend_native.sh p256_cli.bend "$tmp/p256" > /dev/null
check native/build/ecdsa_scheme256_cli ../tools/bend_native.sh ecdsa_scheme256_cli.bend "$tmp/ecdsa_scheme" > /dev/null
check native/build/ecdsa256_cli ../tools/bend_native.sh ecdsa256_cli.bend "$tmp/ecdsa_verify" > /dev/null
check native/build/ecdsa_sign256_cli ../tools/bend_native.sh ecdsa_sign256_cli.bend "$tmp/ecdsa_sign" > /dev/null
check native/build/ecdsa_reject256_cli ../tools/bend_native.sh ecdsa_reject256_cli.bend "$tmp/ecdsa_reject" > /dev/null
check native/build/ecdsa_der256_cli ../tools/bend_native.sh ecdsa_der256_cli.bend "$tmp/ecdsa_der" > /dev/null
check native/build/rsa_encoding_cli ../tools/bend_native.sh rsa_encoding_cli.bend "$tmp/rsa_encoding" > /dev/null
check native/build/rsa_integer_cli ../tools/bend_native.sh rsa_integer_cli.bend "$tmp/rsa_integer" > /dev/null
check native/build/rsa_signature256_cli ../tools/bend_native.sh rsa_signature256_cli.bend "$tmp/rsa_signature" > /dev/null
check native/build/der_cli ../tools/bend_native.sh der_cli.bend "$tmp/der" > /dev/null
check native/build/x509_key_cli env BUN_JSC_useJIT=false ../tools/bend_native.sh x509_key_cli.bend "$tmp/x509_key" > /dev/null
check native/build/x509_signature_cli env BUN_JSC_useJIT=false ../tools/bend_native.sh x509_signature_cli.bend "$tmp/x509_signature" > /dev/null
check native/build/x509_binding_cli env BUN_JSC_useJIT=false ../tools/bend_native.sh x509_binding_cli.bend "$tmp/x509_binding" > /dev/null
check native/build/x509_public_key_cli env BUN_JSC_useJIT=false ../tools/bend_native.sh x509_public_key_cli.bend "$tmp/x509_public_key" > /dev/null
check native/build/x509_certificate_cli env BUN_JSC_useJIT=false ../tools/bend_native.sh x509_certificate_cli.bend "$tmp/x509_certificate" > /dev/null
check native/build/x509_validity_cli env BUN_JSC_useJIT=false ../tools/bend_native.sh x509_validity_cli.bend "$tmp/x509_validity" > /dev/null
check native/build/x509_extensions_cli env BUN_JSC_useJIT=false ../tools/bend_native.sh x509_extensions_cli.bend "$tmp/x509_extensions" > /dev/null
check native/build/x509_constraints_cli ../tools/bend_native.sh x509_constraints_cli.bend "$tmp/x509_constraints" > /dev/null
check native/build/x509_eku_cli ../tools/bend_native.sh x509_eku_cli.bend "$tmp/x509_eku" > /dev/null
check native/build/x509_identity_cli ../tools/bend_native.sh x509_identity_cli.bend "$tmp/x509_identity" > /dev/null
check native/build/x509_hostname_cli ../tools/bend_native.sh x509_hostname_cli.bend "$tmp/x509_hostname" > /dev/null
check native/build/x509_san_cli ../tools/bend_native.sh x509_san_cli.bend "$tmp/x509_san" > /dev/null
check native/build/unicode32_profile_cli ../tools/bend_native.sh unicode32_profile_cli.bend "$tmp/unicode32_profile" > /dev/null
check native/build/unicode32_fold_cli ../tools/bend_native.sh unicode32_fold_cli.bend "$tmp/unicode32_fold" > /dev/null
check native/build/unicode32_fold_stress_cli ../tools/bend_native.sh unicode32_fold_stress_cli.bend "$tmp/unicode32_fold_stress" > /dev/null
check native/build/unicode32_nfkc_stress_cli ../tools/bend_native.sh unicode32_nfkc_stress_cli.bend "$tmp/unicode32_nfkc_stress" > /dev/null
check native/build/unicode32_nfkc_matrix_cli ../tools/bend_native.sh unicode32_nfkc_matrix_cli.bend "$tmp/unicode32_nfkc_matrix" > /dev/null
check native/build/unicode32_nfkc_cli ../tools/bend_native.sh unicode32_nfkc_cli.bend "$tmp/unicode32_nfkc" > /dev/null
check native/build/unicode32_prepare_cli ../tools/bend_native.sh unicode32_prepare_cli.bend "$tmp/unicode32_prepare" > /dev/null
check native/build/unicode32_prepare_stress_cli ../tools/bend_native.sh unicode32_prepare_stress_cli.bend "$tmp/unicode32_prepare_stress" > /dev/null
check native/build/x509_name_cli ../tools/bend_native.sh x509_name_cli.bend "$tmp/x509_name" > /dev/null
check native/build/x509_name_text_cli ../tools/bend_native.sh x509_name_text_cli.bend "$tmp/x509_name_text" > /dev/null
check native/build/x509_extension_policy_cli ../tools/bend_native.sh x509_extension_policy_cli.bend "$tmp/x509_extension_policy" > /dev/null
check native/build/x509_verify_cli env BUN_JSC_useJIT=false ../tools/bend_native.sh x509_verify_cli.bend "$tmp/x509_verify" > /dev/null
check native/build/x25519_cli ../tools/bend_native.sh x25519_cli.bend "$tmp/x25519" > /dev/null
check native/build/traffic_write_cli ../tools/bend_native.sh traffic_write_cli.bend "$tmp/traffic_write" > /dev/null
check native/build/traffic_read_cli ../tools/bend_native.sh traffic_read_cli.bend "$tmp/traffic_read" > /dev/null
check native/check/sha256_hkdf python3 check.py "$tmp/sha256" "$tmp/hkdf"
check native/check/sha256_stream_check python3 sha256_stream_check.py "$tmp/sha_stream" "$tmp/sha256"
check native/check/sha1_check python3 sha1_check.py --long "$tmp/sha1"
check native/check/hmac_sha1_check python3 hmac_sha1_check.py "$tmp/hmac_sha1"
check native/check/chacha_check python3 chacha_check.py "$tmp/chacha20"
check native/check/poly1305_check python3 poly1305_check.py "$tmp/poly1305"
check native/check/aead_check python3 aead_check.py "$tmp/aead"
check native/check/aes128_check python3 aes128_check.py "$tmp/aes128"
check native/check/gcm_check python3 gcm_check.py "$tmp/gcm"
check native/check/field_check python3 field_check.py "$tmp/field25519"
check native/check/field256_check python3 field256_check.py "$tmp/field256"
check native/check/p256_check python3 p256_check.py "$tmp/p256"
check native/check/ecdsa_check python3 ecdsa_check.py -- python3 ecdsa_fixture.py --scheme "$tmp/ecdsa_scheme" --verify "$tmp/ecdsa_verify" --sign "$tmp/ecdsa_sign" --reject "$tmp/ecdsa_reject" --der "$tmp/ecdsa_der" --
check native/check/ecdsa_der_check python3 ecdsa_der_check.py "$tmp/ecdsa_der"
check native/check/rsa_encoding_check python3 rsa_encoding_check.py -- "$tmp/rsa_encoding"
check native/check/rsa_integer_check python3 rsa_integer_check.py -- "$tmp/rsa_integer"
check native/check/rsa_signature256_check python3 rsa_signature256_check.py -- "$tmp/rsa_signature"
check native/check/der_check python3 der_check.py -- "$tmp/der"
check native/check/x509_algorithm_check python3 x509_algorithm_check.py -- python3 x509_algorithm_fixture.py --key "$tmp/x509_key" --signature "$tmp/x509_signature" --binding "$tmp/x509_binding" --der "$tmp/der" --
check native/check/x509_public_key_check python3 x509_public_key_check.py -- "$tmp/x509_public_key"
check native/check/x509_certificate_check python3 x509_certificate_check.py -- "$tmp/x509_certificate"
check native/check/x509_validity_check python3 x509_validity_check.py -- "$tmp/x509_validity"
check native/check/x509_extensions_check python3 x509_extensions_check.py -- "$tmp/x509_extensions"
check native/check/x509_constraints_check python3 x509_constraints_check.py -- "$tmp/x509_constraints"
check native/check/x509_eku_check python3 x509_eku_check.py -- "$tmp/x509_eku"
check native/check/x509_hostname_check_identity python3 x509_hostname_check.py --scope identity -- "$tmp/x509_identity"
check native/check/x509_hostname_check python3 x509_hostname_check.py -- "$tmp/x509_hostname"
check native/check/x509_san_check python3 x509_san_check.py -- "$tmp/x509_san"
check native/check/unicode32_profile_check python3 unicode32_profile_check.py -- "$tmp/unicode32_profile"
check native/check/unicode32_fold_check python3 unicode32_fold_check.py -- "$tmp/unicode32_fold"
check native/check/unicode32_fold_check_stress python3 unicode32_fold_check.py --stress-only -- "$tmp/unicode32_fold_stress"
check native/check/unicode32_nfkc_check python3 unicode32_nfkc_check.py --asset-controls -- "$tmp/unicode32_nfkc"
check native/check/unicode32_nfkc_matrix_check python3 unicode32_nfkc_matrix_check.py -- "$tmp/unicode32_nfkc_matrix"
check native/check/unicode32_nfkc_stress_check python3 unicode32_nfkc_stress_check.py -- "$tmp/unicode32_nfkc_stress"
check native/check/unicode32_prepare_check_fold python3 unicode32_prepare_check.py --mode fold --asset-controls -- "$tmp/unicode32_prepare"
check native/check/unicode32_prepare_check_exact python3 unicode32_prepare_check.py --mode exact --asset-controls -- "$tmp/unicode32_prepare"
check native/check/unicode32_prepare_stress_check python3 unicode32_prepare_stress_check.py -- "$tmp/unicode32_prepare_stress"
check native/check/x509_name_check python3 x509_name_check.py -- "$tmp/x509_name"
check native/check/x509_name_text_check python3 x509_name_text_check.py -- "$tmp/x509_name_text"
check native/check/x509_extension_policy_check python3 x509_extension_policy_check.py --signature-binary "$tmp/x509_verify" -- "$tmp/x509_extension_policy"
check native/check/x509_signature_check python3 x509_signature_check.py -- "$tmp/x509_verify"
check native/check/x25519_check python3 x25519_check.py --iterated "$tmp/x25519"
check native/check/traffic_check python3 traffic_check.py python3 traffic_fixture.py --write "$tmp/traffic_write" --read "$tmp/traffic_read" --
check native/check/traffic_aes_check python3 traffic_aes_check.py python3 traffic_fixture.py --write "$tmp/traffic_write" --read "$tmp/traffic_read" --
if command -v bun > /dev/null 2>&1; then
  check bun/build/cli bend cli.bend -o "$tmp/sha256.js" > /dev/null
  check bun/build/sha256_stream_cli bend sha256_stream_cli.bend -o "$tmp/sha_stream.js" > /dev/null
  check bun/build/hkdf_cli bend hkdf_cli.bend -o "$tmp/hkdf.js" > /dev/null
  check bun/build/sha1_cli bend sha1_cli.bend -o "$tmp/sha1.js" > /dev/null
  check bun/build/hmac_sha1_cli bend hmac_sha1_cli.bend -o "$tmp/hmac_sha1.js" > /dev/null
  check bun/build/chacha_cli bend chacha_cli.bend -o "$tmp/chacha20.js" > /dev/null
  check bun/build/poly1305_cli bend poly1305_cli.bend -o "$tmp/poly1305.js" > /dev/null
  check bun/build/aead_cli bend aead_cli.bend -o "$tmp/aead.js" > /dev/null
  check bun/build/aes128_cli bend aes128_cli.bend -o "$tmp/aes128.js" > /dev/null
  check bun/build/gcm_cli bend gcm_cli.bend -o "$tmp/gcm.js" > /dev/null
  check bun/build/field_cli bend field_cli.bend -o "$tmp/field25519.js" > /dev/null
  check bun/build/field256_cli bend field256_cli.bend -o "$tmp/field256.js" > /dev/null
  check bun/build/p256_cli bend p256_cli.bend -o "$tmp/p256.js" > /dev/null
  check bun/build/ecdsa_scheme256_cli bend ecdsa_scheme256_cli.bend -o "$tmp/ecdsa_scheme.js" > /dev/null
  check bun/build/ecdsa256_cli bend ecdsa256_cli.bend -o "$tmp/ecdsa_verify.js" > /dev/null
  check bun/build/ecdsa_sign256_cli bend ecdsa_sign256_cli.bend -o "$tmp/ecdsa_sign.js" > /dev/null
  check bun/build/ecdsa_reject256_cli bend ecdsa_reject256_cli.bend -o "$tmp/ecdsa_reject.js" > /dev/null
  check bun/build/ecdsa_der256_cli bend ecdsa_der256_cli.bend -o "$tmp/ecdsa_der.js" > /dev/null
  check bun/build/rsa_encoding_cli bend rsa_encoding_cli.bend -o "$tmp/rsa_encoding.js" > /dev/null
  check bun/build/rsa_integer_cli bend rsa_integer_cli.bend -o "$tmp/rsa_integer.js" > /dev/null
  check bun/build/rsa_signature256_cli bend rsa_signature256_cli.bend -o "$tmp/rsa_signature.js" > /dev/null
  check bun/build/der_cli bend der_cli.bend -o "$tmp/der.js" > /dev/null
  check bun/build/x509_key_cli env BUN_JSC_useJIT=false bend x509_key_cli.bend -o "$tmp/x509_key.js" > /dev/null
  check bun/build/x509_signature_cli env BUN_JSC_useJIT=false bend x509_signature_cli.bend -o "$tmp/x509_signature.js" > /dev/null
  check bun/build/x509_binding_cli env BUN_JSC_useJIT=false bend x509_binding_cli.bend -o "$tmp/x509_binding.js" > /dev/null
  check bun/build/x509_public_key_cli env BUN_JSC_useJIT=false bend x509_public_key_cli.bend -o "$tmp/x509_public_key.js" > /dev/null
  check bun/build/x509_certificate_cli env BUN_JSC_useJIT=false bend x509_certificate_cli.bend -o "$tmp/x509_certificate.js" > /dev/null
  check bun/build/x509_validity_cli env BUN_JSC_useJIT=false bend x509_validity_cli.bend -o "$tmp/x509_validity.js" > /dev/null
  check bun/build/x509_extensions_cli env BUN_JSC_useJIT=false bend x509_extensions_cli.bend -o "$tmp/x509_extensions.js" > /dev/null
  check bun/build/x509_constraints_cli bend x509_constraints_cli.bend -o "$tmp/x509_constraints.js" > /dev/null
  check bun/build/x509_eku_cli bend x509_eku_cli.bend -o "$tmp/x509_eku.js" > /dev/null
  check bun/build/x509_identity_cli bend x509_identity_cli.bend -o "$tmp/x509_identity.js" > /dev/null
  check bun/build/x509_hostname_cli bend x509_hostname_cli.bend -o "$tmp/x509_hostname.js" > /dev/null
  check bun/build/x509_san_cli bend x509_san_cli.bend -o "$tmp/x509_san.js" > /dev/null
  check bun/build/unicode32_profile_cli bend unicode32_profile_cli.bend -o "$tmp/unicode32_profile.js" > /dev/null
  check bun/build/unicode32_fold_cli bend unicode32_fold_cli.bend -o "$tmp/unicode32_fold.js" > /dev/null
  check bun/build/unicode32_fold_stress_cli bend unicode32_fold_stress_cli.bend -o "$tmp/unicode32_fold_stress.js" > /dev/null
  check bun/build/unicode32_nfkc_stress_cli bend unicode32_nfkc_stress_cli.bend -o "$tmp/unicode32_nfkc_stress.js" > /dev/null
  check bun/build/unicode32_nfkc_matrix_cli bend unicode32_nfkc_matrix_cli.bend -o "$tmp/unicode32_nfkc_matrix.js" > /dev/null
  check bun/build/unicode32_nfkc_cli bend unicode32_nfkc_cli.bend -o "$tmp/unicode32_nfkc.js" > /dev/null
  check bun/build/unicode32_prepare_cli bend unicode32_prepare_cli.bend -o "$tmp/unicode32_prepare.js" > /dev/null
  check bun/build/unicode32_prepare_stress_cli bend unicode32_prepare_stress_cli.bend -o "$tmp/unicode32_prepare_stress.js" > /dev/null
  check bun/build/x509_name_cli bend x509_name_cli.bend -o "$tmp/x509_name.js" > /dev/null
  check bun/build/x509_name_text_cli bend x509_name_text_cli.bend -o "$tmp/x509_name_text.js" > /dev/null
  check bun/build/x509_extension_policy_cli bend x509_extension_policy_cli.bend -o "$tmp/x509_extension_policy.js" > /dev/null
  check bun/build/x509_verify_cli env BUN_JSC_useJIT=false bend x509_verify_cli.bend -o "$tmp/x509_verify.js" > /dev/null
  check bun/build/x25519_cli bend x25519_cli.bend -o "$tmp/x25519.js" > /dev/null
  check bun/build/traffic_write_cli bend traffic_write_cli.bend -o "$tmp/traffic_write.js" > /dev/null
  check bun/build/traffic_read_cli bend traffic_read_cli.bend -o "$tmp/traffic_read.js" > /dev/null
  check bun/check/sha256_hkdf python3 check.py --bun "$tmp/sha256.js" "$tmp/hkdf.js"
  check bun/check/sha256_stream_check python3 sha256_stream_check.py --bun "$tmp/sha_stream.js" "$tmp/sha256.js"
  check bun/check/sha1_check python3 sha1_check.py bun "$tmp/sha1.js"
  check bun/check/hmac_sha1_check python3 hmac_sha1_check.py bun "$tmp/hmac_sha1.js"
  check bun/check/chacha_check python3 chacha_check.py bun "$tmp/chacha20.js"
  check bun/check/poly1305_check python3 poly1305_check.py bun "$tmp/poly1305.js"
  check bun/check/aead_check python3 aead_check.py bun "$tmp/aead.js"
  check bun/check/aes128_check python3 aes128_check.py bun "$tmp/aes128.js"
  check bun/check/gcm_check python3 gcm_check.py bun "$tmp/gcm.js"
  check bun/check/field_check python3 field_check.py bun "$tmp/field25519.js"
  check bun/check/field256_check python3 field256_check.py bun "$tmp/field256.js"
  python3 p256_check.py --phase-prefix crypto/bun/check/p256_check -- bun "$tmp/p256.js"
  python3 ecdsa_check.py --phase-prefix crypto/bun/check/ecdsa_check -- python3 ecdsa_fixture.py --bun --scheme "$tmp/ecdsa_scheme.js" --verify "$tmp/ecdsa_verify.js" --sign "$tmp/ecdsa_sign.js" --reject "$tmp/ecdsa_reject.js" --der "$tmp/ecdsa_der.js" --
  check bun/check/ecdsa_der_check python3 ecdsa_der_check.py bun "$tmp/ecdsa_der.js"
  check bun/check/rsa_encoding_check python3 rsa_encoding_check.py -- bun "$tmp/rsa_encoding.js"
  check bun/check/rsa_integer_check python3 rsa_integer_check.py -- bun "$tmp/rsa_integer.js"
  check bun/check/rsa_signature256_check python3 rsa_signature256_check.py -- bun "$tmp/rsa_signature.js"
  check bun/check/der_check python3 der_check.py -- bun "$tmp/der.js"
  check bun/check/x509_algorithm_check python3 x509_algorithm_check.py -- python3 x509_algorithm_fixture.py --bun --key "$tmp/x509_key.js" --signature "$tmp/x509_signature.js" --binding "$tmp/x509_binding.js" --der "$tmp/der.js" --
  check bun/check/x509_public_key_check python3 x509_public_key_check.py -- bun "$tmp/x509_public_key.js"
  check bun/check/x509_certificate_check python3 x509_certificate_check.py -- bun "$tmp/x509_certificate.js"
  check bun/check/x509_validity_check python3 x509_validity_check.py -- bun "$tmp/x509_validity.js"
  check bun/check/x509_extensions_check python3 x509_extensions_check.py -- bun "$tmp/x509_extensions.js"
  check bun/check/x509_constraints_check python3 x509_constraints_check.py -- bun "$tmp/x509_constraints.js"
  check bun/check/x509_eku_check python3 x509_eku_check.py -- bun "$tmp/x509_eku.js"
  check bun/check/x509_hostname_check_identity python3 x509_hostname_check.py --scope identity -- bun "$tmp/x509_identity.js"
  check bun/check/x509_hostname_check python3 x509_hostname_check.py -- bun "$tmp/x509_hostname.js"
  check bun/check/x509_san_check python3 x509_san_check.py -- bun "$tmp/x509_san.js"
  check bun/check/unicode32_profile_check python3 unicode32_profile_check.py -- bun "$tmp/unicode32_profile.js"
  check bun/check/unicode32_fold_check python3 unicode32_fold_check.py -- bun "$tmp/unicode32_fold.js"
  check bun/check/unicode32_fold_check_stress python3 unicode32_fold_check.py --stress-only -- bun "$tmp/unicode32_fold_stress.js"
  check bun/check/unicode32_nfkc_check python3 unicode32_nfkc_check.py --asset-controls -- bun "$tmp/unicode32_nfkc.js"
  check bun/check/unicode32_nfkc_matrix_check env BUN_JSC_forceRAMSize=33554432 python3 unicode32_nfkc_matrix_check.py -- bun "$tmp/unicode32_nfkc_matrix.js"
  check bun/check/unicode32_nfkc_stress_check env BUN_JSC_forceRAMSize=33554432 python3 unicode32_nfkc_stress_check.py -- bun "$tmp/unicode32_nfkc_stress.js"
  check bun/check/unicode32_prepare_check_fold env BUN_JSC_forceRAMSize=8388608 python3 unicode32_prepare_check.py --mode fold --asset-controls -- bun "$tmp/unicode32_prepare.js"
  check bun/check/unicode32_prepare_check_exact env BUN_JSC_forceRAMSize=8388608 python3 unicode32_prepare_check.py --mode exact --asset-controls -- bun "$tmp/unicode32_prepare.js"
  check bun/check/unicode32_prepare_stress_check env BUN_JSC_forceRAMSize=4194304 python3 unicode32_prepare_stress_check.py -- bun "$tmp/unicode32_prepare_stress.js"
  check bun/check/x509_name_check python3 x509_name_check.py -- bun "$tmp/x509_name.js"
  check bun/check/x509_name_text_check python3 x509_name_text_check.py -- bun "$tmp/x509_name_text.js"
  check bun/check/x509_extension_policy_check python3 x509_extension_policy_check.py --bun --signature-binary "$tmp/x509_verify.js" -- bun "$tmp/x509_extension_policy.js"
  check bun/check/x509_signature_check python3 x509_signature_check.py -- bun "$tmp/x509_verify.js"
  check bun/check/x25519_check python3 x25519_check.py bun "$tmp/x25519.js"
  check bun/check/traffic_check python3 traffic_check.py python3 traffic_fixture.py --bun --write "$tmp/traffic_write.js" --read "$tmp/traffic_read.js" --
  check bun/check/traffic_aes_check python3 traffic_aes_check.py python3 traffic_fixture.py --bun --write "$tmp/traffic_write.js" --read "$tmp/traffic_read.js" --
else
  echo "crypto JS target: Bun unavailable; skipped"
  python3 - <<'PY'
import json
import sys
sys.path.insert(0, "../tools")
from check_phase import announce
for phase in json.load(open("check_phases.json"))["phases"]:
    if phase["optional"]:
        announce(["skip", phase["name"], "Bun unavailable"])
PY
fi
