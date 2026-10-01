#!/bin/sh
# runs strict Base64, unit/law, example, cookie and cold-type checks
set -eu
cd "$(dirname "$0")"
step() { printf '\n== %s\n' "$1"; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

step "strict Base64 decoder (native and Bun)"
sh ../../tools/bend_native.sh examples/base64.bend "$tmp/base64" > /dev/null
python3 examples/base64_check.py "$tmp/base64"
if command -v bun > /dev/null 2>&1; then
  bend examples/base64.bend -o "$tmp/base64.js" > /dev/null
  python3 examples/base64_check.py bun "$tmp/base64.js"
else
  echo "SKIP Bun Base64 decoder: bun not installed"
fi

step "HTTP method classification (native and Bun)"
sh ../../tools/bend_native.sh examples/method.bend "$tmp/method" > /dev/null
python3 examples/method_check.py "$tmp/method"
if command -v bun > /dev/null 2>&1; then
  bend examples/method.bend -o "$tmp/method.js" > /dev/null
  python3 examples/method_check.py bun "$tmp/method.js"
else
  echo "SKIP Bun method parser: bun not installed"
fi

step "unit tests (all test.bend definitions, grouped imports)"
python3 check_units.py
python3 check_proofs.py

step "example (examples/hello.bend)"
bend examples/hello.bend

step "cookie signing (examples/cookie_sign.bend)"
bend examples/cookie_sign.bend -o "$tmp/cookie_sign" > /dev/null
python3 examples/cookie_sign_check.py "$tmp/cookie_sign"

step "no reference-counted types (../../json/scripts/cold.py)"
python3 ../../json/scripts/cold.py "$PWD/examples/hello.bend" "$PWD/examples/cookie_sign.bend" "$PWD/examples/method_cold.bend"
