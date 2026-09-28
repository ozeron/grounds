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

# streamed bodies, health, env config and a graceful stop (examples/stream)
bend examples/stream.bend -o "$tmp/stream" > /dev/null
PORT=8083 "$tmp/stream" > /dev/null 2>&1 &
tpid=$!
trap '[ -n "$pid" ] && kill "$pid" 2>/dev/null; kill "$spid" "$tpid" 2>/dev/null; rm -rf "$tmp"' EXIT
tries=0
until curl -s -o /dev/null "localhost:8083/healthz"; do
  tries=$((tries + 1))
  [ "$tries" -lt 100 ] || { echo "stream did not start"; exit 1; }
  python3 -c 'import time; time.sleep(0.05)'
done
[ "$(curl -s -N localhost:8083/events | grep -c '^data: tick')" = 3 ] || { echo "stream: want 3 events"; exit 1; }
[ "$(curl -s 'localhost:8083/big?n=160' | wc -c | tr -d ' ')" = 10485760 ] || { echo "stream: want 10 MiB"; exit 1; }
[ "$(curl -s localhost:8083/healthz)" = ok ] || { echo "stream: /healthz"; exit 1; }
[ "$(curl -s localhost:8083/readyz)" = ready ] || { echo "stream: /readyz"; exit 1; }
kill "$tpid"
echo "stream: 3 server-sent events, 10 MiB in chunks, /healthz, /readyz"
out=$(HTTP_MAX_BODY_BYTES=x "$tmp/stream" 2>&1) && { echo "env: a bad number must stop the server"; exit 1; }
echo "env: $out"
out=$(python3 examples/stop.py "$tmp/stream" 8084 5000)
echo "$out"
echo "$out" | grep -q "slow answered: True | connection: close: True" || { echo "stop: the slow request must finish"; exit 1; }
echo "$out" | grep -q "every connection done" || { echo "stop: must drain"; exit 1; }
python3 examples/hb.py "$tmp/stream" 8087 || { echo "hb: heartbeats must flow and end with the client"; exit 1; }
out=$(python3 examples/stop.py "$tmp/stream" 8085 500)
echo "$out" | grep -q "connections cut" || { echo "$out"; echo "stop: must cut at the drain deadline"; exit 1; }
echo "stop: cut at a 500 ms drain deadline"

bend examples/tls.bend -o "$tmp/tls" > /dev/null
bend examples/redirect.bend -o "$tmp/redirect" > /dev/null
bend examples/trusted_proxy.bend -o "$tmp/trusted_proxy" > /dev/null
python3 examples/tls_check.py "$tmp/tls" "$tmp/redirect" "$tmp/trusted_proxy"

bend examples/auth.bend -o "$tmp/auth" > /dev/null
python3 examples/auth_check.py "$tmp/auth"

bend examples/cors.bend -o "$tmp/cors" > /dev/null
python3 examples/cors_check.py "$tmp/cors"

bend websocket_test.bend
bend websocket_frame_test.bend
bend examples/websocket.bend -o "$tmp/websocket" > /dev/null
"$tmp/websocket" > "$tmp/websocket.log" 2>&1 &
wspid=$!
trap '[ -n "$pid" ] && kill "$pid" 2>/dev/null; kill "$spid" "$tpid" "$wspid" 2>/dev/null; rm -rf "$tmp"' EXIT
tries=0
until curl -s -o /dev/null "localhost:8088/"; do
  tries=$((tries + 1))
  [ "$tries" -lt 100 ] || { echo "WebSocket server did not start"; exit 1; }
  python3 -c 'import time; time.sleep(0.05)'
done
python3 examples/websocket_check.py 8088
kill "$wspid"

bend examples/multipart.bend -o "$tmp/multipart" > /dev/null
bend ../client/examples/multipart.bend -o "$tmp/multipart_client" > /dev/null
python3 examples/multipart_fuzz.py "$tmp/multipart" --count 200 --seed "${SEED:-1}" --client "$tmp/multipart_client"

python3 ../../json/scripts/cold.py "$PWD/examples/hello.bend" "$PWD/examples/stack.bend" "$PWD/examples/stream.bend" "$PWD/examples/tls.bend" "$PWD/examples/redirect.bend" "$PWD/examples/trusted_proxy.bend" "$PWD/examples/auth.bend"
