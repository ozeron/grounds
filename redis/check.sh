#!/bin/sh
# runs redis's checks:
# - unit tests, laws, cold check (always)
# - fault tests against tests/fake.py, and the fuzzer against tests/fuzz.py (always)
# - demo and live tests against a Redis on 127.0.0.1:6379, and the AUTH tests
#   against one with password s3cret on 6380, when those are running
set -eu
cd "$(dirname "$0")"
tmp=$(mktemp -d)
fake=
trap '[ -n "$fake" ] && kill "$fake" 2>/dev/null; rm -rf "$tmp"' EXIT

up() { python3 -c "import socket; socket.create_connection(('127.0.0.1', $1), 1)" 2> /dev/null; }
wait_up() {
  tries=0
  until up "$1"; do
    tries=$((tries + 1))
    [ "$tries" -lt 100 ] || { echo "port $1 did not open"; exit 1; }
    python3 -c 'import time; time.sleep(0.05)'
  done
}

bend test.bend
bend PROOF.bend
for p in examples/demo tests/faults tests/fuzz tests/live tests/auth; do
  bend "$p.bend" -o "$tmp/$(basename "$p")" > /dev/null
done
python3 ../json/scripts/cold.py "$PWD/examples/demo.bend"

python3 tests/fake.py > "$tmp/fake.log" 2>&1 &
fake=$!
wait_up 7001
"$tmp/faults"
kill "$fake"
wait "$fake" 2> /dev/null || true
fake=

# the fuzz server counts every connection as a case: wait for its log, not
# with a probe
python3 tests/fuzz.py "${FUZZ_N:-2000}" "${SEED:-1}" > "$tmp/fuzz.log" 2>&1 &
tries=0
until grep -q ready "$tmp/fuzz.log" 2> /dev/null; do
  tries=$((tries + 1))
  [ "$tries" -lt 100 ] || { echo "fuzz server did not start"; exit 1; }
  python3 -c 'import time; time.sleep(0.05)'
done
"$tmp/fuzz"
python3 -c 'import time; time.sleep(1)'
cat "$tmp/fuzz.log" | grep -v '^ready'
grep -q " 0 differ" "$tmp/fuzz.log"

if up 6379; then
  "$tmp/demo" > /dev/null
  "$tmp/live"
else
  echo "no Redis on 127.0.0.1:6379: demo and live tests not run"
fi
if up 6380; then
  "$tmp/auth"
else
  echo "no Redis with a password on 127.0.0.1:6380: AUTH tests not run"
fi
