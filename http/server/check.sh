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

# idle, half-sent and trickling connections close (about 11 s, run at once)
python3 examples/timeouts.py 8080

# 2000 requests, 100 at a time, with and without keep-alive: none fail
for k in "" -k; do
  ab -q $k -c 100 -n 2000 "http://127.0.0.1:8080/?name=ab" > "$tmp/ab" 2>&1 || { cat "$tmp/ab"; exit 1; }
  grep -q "^Failed requests: *0$" "$tmp/ab" || { cat "$tmp/ab"; exit 1; }
  echo "ab $k -c 100 -n 2000: $(grep "^Requests per second" "$tmp/ab" | awk '{print $4}') requests/s, none failed"
done

# the middleware stack: request id, recover's 500, body_limit's 413, logs
bend examples/stack.bend -o "$tmp/stack" > /dev/null
"$tmp/stack" > "$tmp/log" 2> "$tmp/errlog" &
spid=$!
trap '[ -n "$pid" ] && kill "$pid" 2>/dev/null; kill "$spid" 2>/dev/null; rm -rf "$tmp"' EXIT
tries=0
until curl -s -o /dev/null "localhost:8082/"; do
  tries=$((tries + 1))
  [ "$tries" -lt 100 ] || { echo "stack did not start"; exit 1; }
  python3 -c 'import time; time.sleep(0.05)'
done
curl -s -D - -o /dev/null "localhost:8082/" | grep -qiE '^x-request-id: [0-9a-f]{16}' || { echo "stack: no x-request-id"; exit 1; }
[ "$(curl -s -o /dev/null -w '%{http_code}' localhost:8082/fail)" = 500 ] || { echo "stack: /fail is not 500"; exit 1; }
[ "$(curl -s -o /dev/null -w '%{http_code}' -d 12345678901234567 localhost:8082/)" = 413 ] || { echo "stack: big body is not 413"; exit 1; }
grep -q "the handler failed on purpose" "$tmp/errlog" || { echo "stack: recover did not log"; exit 1; }
grep -q "^GET /fail 500 " "$tmp/log" || { echo "stack: logger did not log"; exit 1; }
echo "stack: request id, 500 from recover, 413 from body_limit, logged"

python3 ../../json/scripts/cold.py "$PWD/examples/hello.bend" "$PWD/examples/stack.bend"
