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
bend ice_test.bend
bend retry_test.bend
bend ice_incoming.bend --check-only
bend ice_pairs.bend --check-only
bend ice_scheduler.bend --check-only
bend examples/auth.bend -o "$tmp/auth" > /dev/null
python3 examples/auth_check.py "$tmp/auth"
bend examples/ice_build.bend -o "$tmp/ice_build" > /dev/null
python3 examples/ice_build_check.py "$tmp/ice_build"
bend examples/ice_exchange.bend -o "$tmp/ice_exchange" > /dev/null
python3 examples/ice_exchange_check.py "$tmp/ice_exchange"
bend examples/retry_schedule.bend -o "$tmp/retry_schedule" > /dev/null
python3 examples/retry_schedule_check.py "$tmp/retry_schedule"
bend examples/ice_retry.bend -o "$tmp/ice_retry" > /dev/null
python3 examples/ice_retry_check.py "$tmp/ice_retry"
bend examples/ice_model.bend -o "$tmp/ice_model" > /dev/null
python3 examples/ice_model_check.py "$tmp/ice_model"
bend examples/ice_pairs.bend -o "$tmp/ice_pairs" > /dev/null
python3 examples/ice_pairs_check.py "$tmp/ice_pairs"
bend examples/ice_scheduler.bend -o "$tmp/ice_scheduler" > /dev/null
python3 examples/ice_scheduler_check.py "$tmp/ice_scheduler"
bend examples/ice_clock.bend -o "$tmp/ice_clock" > /dev/null
python3 examples/ice_clock_check.py "$tmp/ice_clock"
bend examples/ice_shared.bend -o "$tmp/ice_shared" > /dev/null
python3 examples/ice_shared_check.py "$tmp/ice_shared"
bend examples/ice_accept.bend -o "$tmp/ice_accept" > /dev/null
python3 examples/ice_accept_check.py "$tmp/ice_accept"
bend examples/ice_duplex.bend -o "$tmp/ice_duplex" > /dev/null
python3 examples/ice_duplex_check.py "$tmp/ice_duplex"
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
  bend examples/ice_build.bend -o "$tmp/ice_build.js" > /dev/null
  python3 examples/ice_build_check.py bun "$tmp/ice_build.js"
  bend examples/ice_exchange.bend -o "$tmp/ice_exchange.js" > /dev/null
  python3 examples/ice_exchange_check.py bun "$tmp/ice_exchange.js"
  bend examples/retry_schedule.bend -o "$tmp/retry_schedule.js" > /dev/null
  python3 examples/retry_schedule_check.py bun "$tmp/retry_schedule.js"
  bend examples/ice_retry.bend -o "$tmp/ice_retry.js" > /dev/null
  python3 examples/ice_retry_check.py bun "$tmp/ice_retry.js"
  bend examples/ice_model.bend -o "$tmp/ice_model.js" > /dev/null
  python3 examples/ice_model_check.py bun "$tmp/ice_model.js"
  bend examples/ice_pairs.bend -o "$tmp/ice_pairs.js" > /dev/null
  python3 examples/ice_pairs_check.py bun "$tmp/ice_pairs.js"
  bend examples/ice_scheduler.bend -o "$tmp/ice_scheduler.js" > /dev/null
  python3 examples/ice_scheduler_check.py bun "$tmp/ice_scheduler.js"
  bend examples/ice_clock.bend -o "$tmp/ice_clock.js" > /dev/null
  python3 examples/ice_clock_check.py bun "$tmp/ice_clock.js"
  bend examples/ice_shared.bend -o "$tmp/ice_shared.js" > /dev/null
  python3 examples/ice_shared_check.py bun "$tmp/ice_shared.js"
  bend examples/ice_accept.bend -o "$tmp/ice_accept.js" > /dev/null
  python3 examples/ice_accept_check.py bun "$tmp/ice_accept.js"
  bend examples/ice_duplex.bend -o "$tmp/ice_duplex.js" > /dev/null
  python3 examples/ice_duplex_check.py bun "$tmp/ice_duplex.js"
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
