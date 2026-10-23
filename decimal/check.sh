#!/bin/sh
# runs decimal's checks: unit tests, laws, cold check
set -eu
cd "$(dirname "$0")"

bend test.bend
bend PROOF.bend
python3 ../json/scripts/cold.py "$PWD/test.bend"
