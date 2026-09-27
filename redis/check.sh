#!/bin/sh
# runs redis's checks: unit tests, the cold check, and the demo against a
# Redis on 127.0.0.1:6379 when one is running
set -eu
cd "$(dirname "$0")"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
bend test.bend
bend examples/demo.bend -o "$tmp/demo" > /dev/null
python3 ../json/scripts/cold.py "$PWD/examples/demo.bend"
if python3 -c 'import socket; socket.create_connection(("127.0.0.1", 6379), 1)' 2> /dev/null; then
  got=$("$tmp/demo")
  want=$(printf 'OK\n"brewed"\n1\n2\nPONG')
  [ "$got" = "$want" ] || { echo "demo: want"; echo "$want"; echo "got"; echo "$got"; exit 1; }
  echo "demo against 127.0.0.1:6379: SET, GET, INCR, DEL, PING ok"
else
  echo "no Redis on 127.0.0.1:6379: demo not run"
fi
