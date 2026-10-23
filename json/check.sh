#!/bin/sh
# runs every check: unit tests, laws, conformance, stress, CLI
set -eu
cd "$(dirname "$0")"

step() { printf '\n== %s\n' "$1"; }

# programs run as native binaries: `bend x.bend` interprets, and the suite
# takes 7 GB that way against 40 MB built
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
native() { name=$1; shift; bend "$name.bend" -o "$tmp/$name" > /dev/null && "$tmp/$name" "$@"; }

step "cold-type metadata checker regressions (no Bend compilation)"
python3 scripts/cold_test.py

python3 scripts/gen_fast.py
python3 scripts/gen_fast_proof.py
python3 scripts/gen_layout_proof.py

step "no reference-counted types in grounds-json or the proven path (scripts/cold.py)"
# the two CLIs are compiled here once: the CLI checks and the integration
# tests run binaries clang builds from this same C
bend main.bend -o "$tmp/main.c" > /dev/null
bend spec_cli.bend -o "$tmp/spec_cli.c" > /dev/null
python3 scripts/cold.py "$tmp/main.c" "$tmp/spec_cli.c" examples/access.bend examples/user.bend examples/users.bend examples/user_laws.bend

step "unit tests (test.bend)"
bend test.bend
bend typed_test.bend

step "laws (PROOF.bend)"
bend PROOF.bend
bend examples/user.bend
bend examples/users.bend
bend examples/user_laws.bend --check-only

step "JSONTestSuite, and fast.bend against the proven parser (suite.bend)"
python3 scripts/gen_suite.py
native suite

step "stress (stress.bend)"
native stress

step "reads on numbers too big for test.bend (reads_check.bend)"
native reads_check

step "decimal constructors and old reader parity (number_check.bend)"
native number_check

step "CLI (main.bend)"
rm -f grounds-json spec-grounds-json
../tools/bend_native.sh "$tmp/main.c" grounds-json > /dev/null
../tools/bend_native.sh "$tmp/spec_cli.c" spec-grounds-json > /dev/null
./grounds-json --compact examples/sample.json
if ./grounds-json examples/broken.json 2>/dev/null; then
  echo "broken.json should fail"; exit 1
fi
echo "broken.json rejected"
size=$(wc -c < examples/sample.json | tr -d ' ')
./grounds-json --max-bytes "$size" --compact examples/sample.json > /dev/null
if ./grounds-json --max-bytes "$((size - 1))" examples/sample.json 2>/dev/null; then
  echo "--max-bytes should refuse a bigger file"; exit 1
fi
echo "--max-bytes $((size - 1)) refused a $size-byte file"

step "integration: native CLI vs Python json (scripts/integration.py)"
NOBUILD=1 python3 scripts/integration.py
