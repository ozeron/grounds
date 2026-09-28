#!/bin/sh
# runs http/client's checks: unit tests, then the live test against
# tests/fake.py and examples/stream from http/server; then the cold check
set -eu
cd "$(dirname "$0")"
tmp=$(mktemp -d)
fpid=
spid=
trap '[ -n "$fpid" ] && kill "$fpid" 2>/dev/null; [ -n "$spid" ] && kill "$spid" 2>/dev/null; rm -rf "$tmp"' EXIT
bend test.bend
bend PROOF.bend
bend tests/live.bend -o "$tmp/live" > /dev/null
bend tests/more.bend -o "$tmp/more" > /dev/null
bend tests/fuzz.bend -o "$tmp/fuzz" > /dev/null
bend ../server/examples/stream.bend -o "$tmp/stream" > /dev/null
python3 tests/fake.py "$tmp" > "$tmp/fake.out" &
fpid=$!
PORT=8086 "$tmp/stream" 2> /dev/null &
spid=$!
tries=0
until grep -q ready "$tmp/fake.out" && curl -s -o /dev/null localhost:8086/healthz; do
  tries=$((tries + 1))
  [ "$tries" -lt 100 ] || { echo "servers did not start"; exit 1; }
  python3 -c 'import time; time.sleep(0.05)'
done
"$tmp/live" | tr -d '\r' | sed -E 's/errno [0-9]+/errno N/' > "$tmp/got"
diff "$tmp/got" tests/live.out || { echo "live: differs from tests/live.out"; exit 1; }
echo "live: every case as tests/live.out"
GROUNDS_TLS_CA="$tmp/cert.pem" "$tmp/more" | tr -d '\r' > "$tmp/more.got"
diff "$tmp/more.got" tests/more.out || { echo "more: differs from tests/more.out"; exit 1; }
echo "more: retries, redirects, JSON, streams and TLS, as tests/more.out"
python3 tests/fuzz.py "$tmp/fuzz" 2000 "${SEED:-1}"
# one-shot requests stay uncounted; a pool shares its connections
# through a channel, which counts what it carries
python3 ../../json/scripts/cold.py "$PWD/tests/live.bend" "$PWD/examples/get.bend" "$PWD/examples/json.bend" "$PWD/examples/stream.bend"
