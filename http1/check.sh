#!/bin/sh
# runs http1's checks: unit tests, the example, and the cold check
set -eu
cd "$(dirname "$0")"
bend test.bend
bend examples/echo.bend > /dev/null
python3 ../json/scripts/cold.py "$PWD/examples/echo.bend"
