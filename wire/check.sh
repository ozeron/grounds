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
