#!/bin/sh
# runs http_router's checks: unit tests, the example, and the cold check
set -eu
cd "$(dirname "$0")"
bend test.bend
bend PROOF.bend
bend examples/routes.bend
python3 ../../json/scripts/cold.py "$PWD/examples/routes.bend"
