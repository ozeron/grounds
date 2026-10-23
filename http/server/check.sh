#!/bin/sh
# runs http_server's checks: builds examples/hello, serves it on 8080, and
# asks it with curl and raw sockets; then the cold check
set -eu
cd "$(dirname "$0")"
tmp=$(mktemp -d)
pid=
spid=
tpid=
wspid=
phase=
announce() { python3 ../../tools/check_phase.py "$@"; }
begin() { phase="http_server/$1"; announce start "$phase"; }
end() { announce end "$phase" 0; phase=; }
# Release the frontend before bounded native C compilation. Compiler-only
# heap settings do not change any server or peer evaluator environment.
native() {
  BUN_OPTIONS="${BUN_OPTIONS:-} --smol" BUN_JSC_forceRAMSize=134217728 \
    sh ../../tools/bend_native.sh "$@"
}
stop() {
  [ -n "$1" ] || return 0
  kill "$1" 2>/dev/null || true
  wait "$1"
}
cleanup() {
  result=$?
  trap - EXIT
  set +e
  for owned in "$pid" "$spid" "$tpid" "$wspid"; do
    stop "$owned" || { [ "$result" -ne 0 ] || result=1; }
  done
  if [ -n "$phase" ]; then
    announce end "$phase" "$result" || result=125
  fi
  rm -rf "$tmp"
  exit "$result"
}
trap cleanup EXIT
# M4a: every TLS/cookie host effect is unavailable in these exact outputs.
# Override the artifact directory to retain full source-bound evidence.
artifacts=${GROUNDS_M4A_ARTIFACTS:-$tmp/m4a}
mkdir -p "$artifacts/probes" "$artifacts/fixtures" "$tmp/probes"
begin bend_tls_fixtures
python3 examples/bend_tls_check.py --prepare --fixtures "$artifacts/fixtures" --report "$artifacts/fixtures.json"
end
begin bend_tls_frontend_native
bend_bun_options=${BUN_OPTIONS:-}
BUN_OPTIONS="$bend_bun_options --smol" BUN_JSC_forceRAMSize=134217728 python3 examples/bend_tls_build.py "$artifacts/bend_tls.c" "$artifacts/build-native.json"
end
begin bend_tls_compile_native
native "$artifacts/bend_tls.c" "$artifacts/bend_tls" > /dev/null
end
begin bend_tls_frontend_bun
BUN_OPTIONS="$bend_bun_options --smol" BUN_JSC_forceRAMSize=134217728 python3 examples/bend_tls_build.py "$artifacts/bend_tls.js" "$artifacts/build-bun.json"
end
begin bend_tls_go_peer
# Go is only an independent peer; keep its compiled output outside the repo.
mise exec go@1.26.9 -- go build -o "$tmp/bend_tls_go" examples/bend_tls_peer.go
native ../core/examples/cookie_legacy.bend "$tmp/cookie_legacy" > /dev/null
end
begin bend_tls_legacy_probe_native
python3 ../../wire/bend_tls_no_delegation_build.py --program legacy-probe --output "$artifacts/probes/legacy-probe.c" --report "$artifacts/probes/legacy-probe-native.json"
native "$artifacts/probes/legacy-probe.c" "$tmp/probes/legacy-probe" > /dev/null
end
begin bend_tls_legacy_probe_bun
python3 ../../wire/bend_tls_no_delegation_build.py --program legacy-probe --output "$artifacts/probes/legacy-probe.js" --report "$artifacts/probes/legacy-probe-bun.json"
end
begin bend_tls_cookie_probe_native
python3 ../../wire/bend_tls_no_delegation_build.py --program cookie-probe --output "$artifacts/probes/cookie-probe.c" --report "$artifacts/probes/cookie-probe-native.json"
native "$artifacts/probes/cookie-probe.c" "$tmp/probes/cookie-probe" > /dev/null
end
begin bend_tls_cookie_probe_bun
python3 ../../wire/bend_tls_no_delegation_build.py --program cookie-probe --output "$artifacts/probes/cookie-probe.js" --report "$artifacts/probes/cookie-probe-bun.json"
end
begin bend_tls_no_delegation
cp "$artifacts/probes/legacy-probe.js" "$artifacts/probes/cookie-probe.js" "$tmp/probes/"
python3 examples/bend_tls_audit.py --native "$artifacts/bend_tls" --c "$artifacts/bend_tls.c" --js "$artifacts/bend_tls.js" --probe-dir "$tmp/probes" --report "$artifacts/no-delegation.json"
end
begin bend_tls_native_ecdsa_aes
python3 examples/bend_tls_check.py --fixtures "$artifacts/fixtures" --credential ecdsa --suite aes --go "$tmp/bend_tls_go" --legacy "$tmp/cookie_legacy" --report "$artifacts/bend_tls_native_ecdsa_aes.json" -- "$artifacts/bend_tls"
end
begin bend_tls_native_ecdsa_aes_negative
python3 examples/bend_tls_check.py --fixtures "$artifacts/fixtures" --credential ecdsa --suite aes --negative --report "$artifacts/bend_tls_native_ecdsa_aes_negative.json" -- "$artifacts/bend_tls"
end
begin bend_tls_native_ecdsa_chacha
python3 examples/bend_tls_check.py --fixtures "$artifacts/fixtures" --credential ecdsa --suite chacha --go "$tmp/bend_tls_go" --legacy "$tmp/cookie_legacy" --report "$artifacts/bend_tls_native_ecdsa_chacha.json" -- "$artifacts/bend_tls"
end
begin bend_tls_native_ecdsa_chacha_negative
python3 examples/bend_tls_check.py --fixtures "$artifacts/fixtures" --credential ecdsa --suite chacha --negative --report "$artifacts/bend_tls_native_ecdsa_chacha_negative.json" -- "$artifacts/bend_tls"
end
begin bend_tls_native_rsa_aes
python3 examples/bend_tls_check.py --fixtures "$artifacts/fixtures" --credential rsa --suite aes --go "$tmp/bend_tls_go" --legacy "$tmp/cookie_legacy" --report "$artifacts/bend_tls_native_rsa_aes.json" -- "$artifacts/bend_tls"
end
begin bend_tls_native_rsa_aes_negative
python3 examples/bend_tls_check.py --fixtures "$artifacts/fixtures" --credential rsa --suite aes --negative --report "$artifacts/bend_tls_native_rsa_aes_negative.json" -- "$artifacts/bend_tls"
end
begin bend_tls_native_rsa_chacha
python3 examples/bend_tls_check.py --fixtures "$artifacts/fixtures" --credential rsa --suite chacha --go "$tmp/bend_tls_go" --legacy "$tmp/cookie_legacy" --report "$artifacts/bend_tls_native_rsa_chacha.json" -- "$artifacts/bend_tls"
end
begin bend_tls_native_rsa_chacha_negative
python3 examples/bend_tls_check.py --fixtures "$artifacts/fixtures" --credential rsa --suite chacha --negative --report "$artifacts/bend_tls_native_rsa_chacha_negative.json" -- "$artifacts/bend_tls"
end
begin bend_tls_bun_ecdsa_aes
python3 examples/bend_tls_check.py --target bun --fixtures "$artifacts/fixtures" --credential ecdsa --suite aes --go "$tmp/bend_tls_go" --legacy "$tmp/cookie_legacy" --report "$artifacts/bend_tls_bun_ecdsa_aes.json" -- bun "$artifacts/bend_tls.js"
end
begin bend_tls_bun_ecdsa_aes_negative
python3 examples/bend_tls_check.py --target bun --fixtures "$artifacts/fixtures" --credential ecdsa --suite aes --negative --report "$artifacts/bend_tls_bun_ecdsa_aes_negative.json" -- bun "$artifacts/bend_tls.js"
end
begin bend_tls_bun_ecdsa_chacha
python3 examples/bend_tls_check.py --target bun --fixtures "$artifacts/fixtures" --credential ecdsa --suite chacha --go "$tmp/bend_tls_go" --legacy "$tmp/cookie_legacy" --report "$artifacts/bend_tls_bun_ecdsa_chacha.json" -- bun "$artifacts/bend_tls.js"
end
begin bend_tls_bun_ecdsa_chacha_negative
python3 examples/bend_tls_check.py --target bun --fixtures "$artifacts/fixtures" --credential ecdsa --suite chacha --negative --report "$artifacts/bend_tls_bun_ecdsa_chacha_negative.json" -- bun "$artifacts/bend_tls.js"
end

begin bend_tls_configuration_native
python3 examples/bend_tls_check.py --configuration --fixtures "$artifacts/fixtures" --report "$artifacts/configuration-native.json" -- "$artifacts/bend_tls"
end
begin bend_tls_configuration_bun
python3 examples/bend_tls_check.py --target bun --configuration --fixtures "$artifacts/fixtures" --report "$artifacts/configuration-bun.json" -- bun "$artifacts/bend_tls.js"
end

# M4b WSS is native-only; existing Bun M4a checks above remain unchanged.
m4b=${GROUNDS_M4B_SERVER_ARTIFACTS:-$artifacts/m4b}
mkdir -p "$m4b"
begin bend_wss_frontend_native
BUN_OPTIONS="$bend_bun_options --smol" BUN_JSC_forceRAMSize=134217728 python3 examples/bend_tls_build.py --program wss "$m4b/server.c" "$m4b/build.json"
end
begin bend_wss_compile_native
native "$m4b/server.c" "$m4b/server"
end
begin bend_wss_go_peer
mise exec go@1.26.9 -- go build -o "$tmp/wss-go" examples/bend_m4b_peer.go
end
begin bend_wss_no_delegation
python3 examples/bend_native_audit.py --role server --native "$m4b/server" --c "$m4b/server.c" --probe-dir "$tmp/probes" --report "$m4b/audit.json"
end
for suite in aes chacha; do
  begin "bend_wss_native_$suite"
  python3 examples/bend_wss_check.py --binary "$m4b/server" --fixtures "$artifacts/fixtures" --go "$tmp/wss-go" --suite "$suite" --report "$m4b/$suite.json"
  end
done

# Real Chrome is required for native M4 acceptance. Trust stays inside a freshly
# created profile, with untrusted-CA and hostname-mismatch refusal controls.
begin bend_browser_frontend_native
BUN_OPTIONS="$bend_bun_options --smol" BUN_JSC_forceRAMSize=134217728 python3 examples/bend_tls_build.py --program browser "$m4b/browser.c" "$m4b/browser-build.json"
end
begin bend_browser_compile_native
native "$m4b/browser.c" "$m4b/browser"
end
begin bend_browser_no_delegation
python3 examples/bend_native_audit.py --role server --native "$m4b/browser" --c "$m4b/browser.c" --probe-dir "$tmp/probes" --report "$m4b/browser-audit.json"
end
for suite in aes chacha; do
  begin "bend_browser_native_$suite"
  python3 examples/bend_browser_check.py --binary "$m4b/browser" --fixtures "$artifacts/fixtures" --suite "$suite" --report "$m4b/browser-$suite.json"
  end
done

begin context_native
native examples/context.bend "$tmp/context" > /dev/null
python3 examples/context_check.py "$tmp/context"
end
if command -v bun > /dev/null 2>&1; then
  begin context_bun
  BUN_OPTIONS="${BUN_OPTIONS:-} --smol" BUN_JSC_forceRAMSize=134217728 bend examples/context.bend -o "$tmp/context.js" > /dev/null
  python3 examples/context_check.py bun "$tmp/context.js"
  end
else
  announce skip http_server/context_bun 'Bun unavailable'
fi
begin hello
native examples/hello.bend "$tmp/hello" > /dev/null
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

stop "$pid"
pid=
end

# the middleware stack: request id, recover's 500, body_limit's 413, logs
begin middleware
native examples/stack.bend "$tmp/stack" > /dev/null
"$tmp/stack" > "$tmp/log" 2> "$tmp/errlog" &
spid=$!
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
stop "$spid"
spid=
end

# streamed bodies, health, env config and a graceful stop (examples/stream)
begin stream
native examples/stream.bend "$tmp/stream" > /dev/null
PORT=8083 "$tmp/stream" > /dev/null 2>&1 &
tpid=$!
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
stop "$tpid"
tpid=
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
end

begin tls_proxy
native examples/tls.bend "$tmp/tls" > /dev/null
native examples/redirect.bend "$tmp/redirect" > /dev/null
native examples/trusted_proxy.bend "$tmp/trusted_proxy" > /dev/null
python3 examples/tls_check.py "$tmp/tls" "$tmp/redirect" "$tmp/trusted_proxy"
end

begin auth
native examples/auth.bend "$tmp/auth" > /dev/null
python3 examples/auth_check.py "$tmp/auth"
end

begin cors
native examples/cors.bend "$tmp/cors" > /dev/null
python3 examples/cors_check.py "$tmp/cors"
end

begin websocket_units
bend websocket_test.bend
end
begin websocket_frame_units
bend websocket_frame_test.bend
end
begin websocket_live
native examples/websocket.bend "$tmp/websocket" > /dev/null
"$tmp/websocket" > "$tmp/websocket.log" 2>&1 &
wspid=$!
tries=0
until curl -s -o /dev/null "localhost:8088/"; do
  tries=$((tries + 1))
  [ "$tries" -lt 100 ] || { echo "WebSocket server did not start"; exit 1; }
  python3 -c 'import time; time.sleep(0.05)'
done
python3 examples/websocket_check.py 8088
stop "$wspid"
wspid=
end

begin multipart
native examples/multipart.bend "$tmp/multipart" > /dev/null
native ../client/examples/multipart.bend "$tmp/multipart_client" > /dev/null
python3 examples/multipart_fuzz.py "$tmp/multipart" --count 200 --seed "${SEED:-1}" --client "$tmp/multipart_client"
end

begin cold
BUN_OPTIONS="${BUN_OPTIONS:-} --smol" BUN_JSC_forceRAMSize=134217728 python3 ../../json/scripts/cold.py "$PWD/examples/hello.bend" "$PWD/examples/stack.bend" "$PWD/examples/stream.bend" "$PWD/examples/tls.bend" "$PWD/examples/redirect.bend" "$PWD/examples/trusted_proxy.bend" "$PWD/examples/auth.bend"
python3 examples/legacy_graph_audit.py --artifacts "$artifacts/legacy-graphs" --hello "$tmp/hello" --stream "$tmp/stream"
end
