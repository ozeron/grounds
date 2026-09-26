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

python3 scripts/gen_fast.py
python3 scripts/gen_fast_proof.py
python3 scripts/gen_layout_proof.py

step "no reference-counted types in grounds-json or the proven path (scripts/cold.py)"
python3 scripts/cold.py main.bend spec_cli.bend

step "unit tests (test.bend)"
bend test.bend

step "laws (PROOF.bend)"
bend PROOF.bend

step "JSONTestSuite, and fast.bend against the proven parser (suite.bend)"
python3 scripts/gen_suite.py
native suite

step "stress (stress.bend)"
native stress

step "CLI (main.bend)"
bend main.bend -o "$tmp/grounds-json" > /dev/null
"$tmp/grounds-json" --compact examples/sample.json
if "$tmp/grounds-json" examples/broken.json 2>/dev/null; then
  echo "broken.json should fail"; exit 1
fi
echo "broken.json rejected"
size=$(wc -c < examples/sample.json | tr -d ' ')
"$tmp/grounds-json" --max-bytes "$size" --compact examples/sample.json > /dev/null
if "$tmp/grounds-json" --max-bytes "$((size - 1))" examples/sample.json 2>/dev/null; then
  echo "--max-bytes should refuse a bigger file"; exit 1
fi
echo "--max-bytes $((size - 1)) refused a $size-byte file"

step "integration: native CLI vs Python json (scripts/integration.py)"
python3 scripts/integration.py
