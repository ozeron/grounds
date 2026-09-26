#!/bin/sh
# runs every check: unit tests, laws, conformance, stress, CLI
set -eu
cd "$(dirname "$0")"

step() { printf '\n== %s\n' "$1"; }

python3 scripts/gen_fast.py
python3 scripts/gen_fast_proof.py

step "no reference-counted types in bjson or the proven path (scripts/cold.py)"
python3 scripts/cold.py main.bend spec_cli.bend

step "unit tests (test.bend)"
bend test.bend

step "laws (PROOF.bend)"
bend PROOF.bend

step "JSONTestSuite, and fast.bend against the proven parser (suite.bend)"
python3 scripts/gen_suite.py
bend suite.bend

step "stress (stress.bend)"
bend stress.bend

step "CLI (main.bend)"
bend main.bend -- --compact examples/sample.json
if bend main.bend -- examples/broken.json 2>/dev/null; then
  echo "broken.json should fail"; exit 1
fi
echo "broken.json rejected"

step "integration: native CLI vs Python json (scripts/integration.py)"
python3 scripts/integration.py
