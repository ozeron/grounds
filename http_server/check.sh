#!/bin/sh
# runs http_server's checks: builds examples/hello, serves it on 8080, and
# asks it with curl and raw sockets; then the cold check
set -eu
cd "$(dirname "$0")"
tmp=$(mktemp -d)
pid=
trap '[ -n "$pid" ] && kill "$pid" 2>/dev/null; rm -rf "$tmp"' EXIT
bend examples/hello.bend -o "$tmp/hello" > /dev/null
"$tmp/hello" &
pid=$!
tries=0
until curl -s -o /dev/null "localhost:8080/"; do
  tries=$((tries + 1))
  [ "$tries" -lt 100 ] || { echo "server did not start"; exit 1; }
  python3 -c 'import time; time.sleep(0.05)'
done

got=$(curl -s "localhost:8080/?name=x")
[ "$got" = "hello, x" ] || { echo "curl: want 'hello, x', got '$got'"; exit 1; }
echo "curl localhost:8080/?name=x: $got"

curl -s -v "localhost:8080/?name=a" "localhost:8080/?name=b" > "$tmp/out" 2> "$tmp/err"
[ "$(cat "$tmp/out")" = "$(printf 'hello, a\nhello, b')" ] || { echo "keep-alive: bad output"; exit 1; }
grep -q "Re-using existing connection" "$tmp/err" || { echo "keep-alive: connection not reused"; exit 1; }
echo "keep-alive: two requests on one connection"

python3 examples/probe.py 8080
python3 ../json/scripts/cold.py "$PWD/examples/hello.bend"
