#!/bin/sh
# runs wire's checks: the loopback and timeout tests, built natively, and the cold check
set -eu
cd "$(dirname "$0")"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
bend tls_record_test.bend
bend tls_record_cli.bend -o "$tmp/tls_record" > /dev/null
python3 tls_record_check.py "$tmp/tls_record"
bend random.bend -o "$tmp/random" > /dev/null
python3 random_check.py "$tmp/random"
"${CC:-cc}" -std=c11 -O2 -Wall -Wextra -Werror random_host_check.c -o "$tmp/random_host_check"
"$tmp/random_host_check"
bend bench.bend -o "$tmp/bench" > /dev/null
python3 bench_check.py "$tmp/bench"
if command -v bun > /dev/null 2>&1; then
  bend tls_record_cli.bend -o "$tmp/tls_record.js" > /dev/null
  python3 tls_record_check.py bun "$tmp/tls_record.js"
  bend random.bend -o "$tmp/random.js" > /dev/null
  python3 random_check.py bun "$tmp/random.js"
  bun random_host_check.mjs
  bend bench.bend -o "$tmp/bench.js" > /dev/null
  python3 bench_check.py bun "$tmp/bench.js"
else
  echo "bulk RNG JS target: Bun unavailable; skipped"
fi
bend loopback.bend -o "$tmp/loopback" > /dev/null
"$tmp/loopback"
bend timeout.bend -o "$tmp/timeout" > /dev/null
"$tmp/timeout"
bend udp.bend -o "$tmp/udp" > /dev/null
"$tmp/udp"
bend udp_address.bend -o "$tmp/udp_address" > /dev/null
python3 udp_address_check.py "$tmp/udp_address"
if command -v bun > /dev/null 2>&1; then
  bend udp.bend -o "$tmp/udp.js" > /dev/null
  bun "$tmp/udp.js"
  bend udp_address.bend -o "$tmp/udp_address.js" > /dev/null
  python3 udp_address_check.py bun "$tmp/udp_address.js"
else
  echo "udp JS target: Bun unavailable; skipped"
fi
python3 ../json/scripts/cold.py "$PWD/loopback.bend"
bend stop.bend -o "$tmp/stop" > /dev/null
"$tmp/stop" > "$tmp/stop.out" &
spid=$!
python3 - <<'PY'
import socket, time
for _ in range(100):
    try:
        socket.create_connection(("127.0.0.1", 7201)).close()
        break
    except OSError:
        time.sleep(0.05)
time.sleep(0.2)
PY
kill -TERM "$spid"
wait "$spid"
grep -q "^stopped: 1 accepted, live 1$" "$tmp/stop.out" || { cat "$tmp/stop.out"; echo "stop: want 'stopped: 1 accepted, live 1'"; exit 1; }
echo "SIGTERM caught: $(tail -1 "$tmp/stop.out")"
python3 stop_check.py "$tmp/stop"
if command -v bun > /dev/null 2>&1; then
  bend stop.bend -o "$tmp/stop.js" > /dev/null
  python3 stop_check.py bun "$tmp/stop.js"
else
  echo "JS signal stop: Bun unavailable; skipped"
fi
bend resolve.bend -o "$tmp/resolve" > /dev/null
[ "$("$tmp/resolve")" = "127.0.0.1 10.1.2.3 fails" ] || { echo "resolve: want '127.0.0.1 10.1.2.3 fails'"; exit 1; }
echo "resolve: localhost, an address, and a name that does not exist"
bend tls.bend -o "$tmp/tls" > /dev/null
python3 tls.py "$tmp" > "$tmp/tls.out" &
tpid=$!
trap 'kill "$tpid" 2>/dev/null; rm -rf "$tmp"' EXIT
until grep -q ready "$tmp/tls.out"; do python3 -c 'import time; time.sleep(0.05)'; done
[ "$(GROUNDS_TLS_CA="$tmp/cert.pem" "$tmp/tls")" = "hello over tls" ] || { echo "tls: want 'hello over tls'"; exit 1; }
GROUNDS_TLS_CA="$tmp/cert.pem" "$tmp/tls" wronghost > /dev/null 2>&1 && { echo "tls: a wrong host name must fail"; exit 1; }
"$tmp/tls" > /dev/null 2>&1 && { echo "tls: an untrusted certificate must fail"; exit 1; }
echo "tls: a GET over TLS; a wrong host name and an untrusted certificate fail"
kill "$tpid" 2>/dev/null || :
wait "$tpid" 2>/dev/null || :

bend tls_server.bend -o "$tmp/tls_server" > /dev/null
TLS_CERT="$tmp/cert.pem" TLS_KEY="$tmp/key.pem" "$tmp/tls_server" > "$tmp/tls_server.out" &
spid=$!
trap 'kill "$spid" 2>/dev/null || :; rm -rf "$tmp"' EXIT
tries=0
until grep -q '^ready$' "$tmp/tls_server.out"; do
  tries=$((tries + 1))
  [ "$tries" -lt 100 ] && kill -0 "$spid" 2>/dev/null || { cat "$tmp/tls_server.out"; echo "tls server did not start"; exit 1; }
  python3 -c 'import time; time.sleep(0.05)'
done
python3 tls_server.py "$tmp/cert.pem"
wait "$spid"
grep -q '^got first$' "$tmp/tls_server.out"
grep -q '^got second$' "$tmp/tls_server.out"
echo "tls server: two verified connections over the plain send/recv effects"
