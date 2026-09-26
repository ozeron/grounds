#!/bin/sh
# runs wire's checks: the loopback test, built natively, and the cold check
set -eu
cd "$(dirname "$0")"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
bend loopback.bend -o "$tmp/loopback" > /dev/null
"$tmp/loopback"
python3 ../json/scripts/cold.py "$PWD/loopback.bend"
