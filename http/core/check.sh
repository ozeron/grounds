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

step "no reference-counted types (../../json/scripts/cold.py)"
python3 ../../json/scripts/cold.py "$PWD/examples/hello.bend"
