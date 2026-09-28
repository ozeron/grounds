#!/bin/sh
# runs http's checks: unit tests, the example, and the cold check
set -eu
cd "$(dirname "$0")"
step() { printf '\n== %s\n' "$1"; }

step "unit tests (test.bend)"
bend test.bend
bend PROOF.bend

step "example (examples/hello.bend)"
bend examples/hello.bend

step "cookie signing (examples/cookie_sign.bend)"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
bend examples/cookie_sign.bend -o "$tmp/cookie_sign" > /dev/null
python3 examples/cookie_sign_check.py "$tmp/cookie_sign"

step "no reference-counted types (../../json/scripts/cold.py)"
python3 ../../json/scripts/cold.py "$PWD/examples/hello.bend" "$PWD/examples/cookie_sign.bend"
