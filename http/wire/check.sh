#!/bin/sh
# runs http/wire's checks: unit tests, laws, the example, and the cold check
set -eu
cd "$(dirname "$0")"
bend test.bend
bend PROOF.bend
bend examples/echo.bend > /dev/null
python3 ../../json/scripts/cold.py "$PWD/examples/echo.bend"
