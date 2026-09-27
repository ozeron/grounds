#!/bin/sh
# runs wire's checks: the loopback and timeout tests, built natively, and the cold check
set -eu
cd "$(dirname "$0")"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
bend loopback.bend -o "$tmp/loopback" > /dev/null
"$tmp/loopback"
bend timeout.bend -o "$tmp/timeout" > /dev/null
"$tmp/timeout"
python3 ../json/scripts/cold.py "$PWD/loopback.bend"
