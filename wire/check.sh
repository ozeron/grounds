#!/bin/sh
# runs wire's checks: the loopback and timeout tests, built natively, and the cold check
set -eu
cd "$(dirname "$0")"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
announce() { python3 ../tools/check_phase.py "$@" >&2; }
# M2 key agreement and CertificateVerify components; no socket handshake.
announce start wire/m2-types/key_share
python3 tls_key_share_type_check.py
announce end wire/m2-types/key_share 0
announce start wire/m2-types/certificate_verify
python3 tls_certificate_verify_type_check.py
announce end wire/m2-types/certificate_verify 0
announce start wire/m2-native/build/key_share
../tools/bend_native.sh tls_key_share_cli.bend "$tmp/tls_key_share" > /dev/null
announce end wire/m2-native/build/key_share 0
announce start wire/m2-native/build/certificate_verify
../tools/bend_native.sh tls_certificate_verify_cli.bend "$tmp/tls_certificate_verify" > /dev/null
announce end wire/m2-native/build/certificate_verify 0
announce start wire/m2-native/build/certificate_verify_rsa
../tools/bend_native.sh tls_certificate_verify_rsa_cli.bend "$tmp/tls_certificate_verify_rsa" > /dev/null
announce end wire/m2-native/build/certificate_verify_rsa 0
announce start wire/m2-native/check/key_share
python3 tls_key_share_check.py -- "$tmp/tls_key_share"
announce end wire/m2-native/check/key_share 0
announce start wire/m2-native/check/certificate_verify
python3 tls_certificate_verify_check.py -- "$tmp/tls_certificate_verify"
announce end wire/m2-native/check/certificate_verify 0
announce start wire/m2-native/check/certificate_verify_rsa
python3 tls_certificate_verify_rsa_check.py -- "$tmp/tls_certificate_verify_rsa"
announce end wire/m2-native/check/certificate_verify_rsa 0
if command -v bun > /dev/null 2>&1; then
announce start wire/m2-bun/build/key_share
bend tls_key_share_cli.bend -o "$tmp/tls_key_share.js" > /dev/null
announce end wire/m2-bun/build/key_share 0
announce start wire/m2-bun/build/certificate_verify
bend tls_certificate_verify_cli.bend -o "$tmp/tls_certificate_verify.js" > /dev/null
announce end wire/m2-bun/build/certificate_verify 0
announce start wire/m2-bun/build/certificate_verify_rsa
bend tls_certificate_verify_rsa_cli.bend -o "$tmp/tls_certificate_verify_rsa.js" > /dev/null
announce end wire/m2-bun/build/certificate_verify_rsa 0
announce start wire/m2-bun/check/key_share
python3 tls_key_share_check.py -- bun "$tmp/tls_key_share.js"
announce end wire/m2-bun/check/key_share 0
announce start wire/m2-bun/check/certificate_verify
python3 tls_certificate_verify_check.py -- bun "$tmp/tls_certificate_verify.js"
announce end wire/m2-bun/check/certificate_verify 0
announce start wire/m2-bun/check/certificate_verify_rsa
python3 tls_certificate_verify_rsa_check.py -- bun "$tmp/tls_certificate_verify_rsa.js"
announce end wire/m2-bun/check/certificate_verify_rsa 0
else
announce skip wire/m2-bun/build/key_share
announce skip wire/m2-bun/build/certificate_verify
announce skip wire/m2-bun/build/certificate_verify_rsa
announce skip wire/m2-bun/check/key_share
announce skip wire/m2-bun/check/certificate_verify
announce skip wire/m2-bun/check/certificate_verify_rsa
fi
announce start wire/native-extensions
bend tls_extensions_test.bend
../tools/bend_native.sh tls_extensions_cli.bend "$tmp/tls_extensions" > /dev/null
python3 tls_extensions_check.py -- "$tmp/tls_extensions"
python3 tls_extensions_check.py --stress -- "$tmp/tls_extensions"
announce end wire/native-extensions 0
announce start wire/native-handshake-stream
bend tls_handshake_stream_test.bend
python3 tls_handshake_stream_type_check.py
../tools/bend_native.sh tls_handshake_stream_cli.bend "$tmp/tls_handshake_stream" > /dev/null
python3 tls_handshake_stream_check.py -- "$tmp/tls_handshake_stream"
python3 tls_handshake_stream_check.py --stress -- "$tmp/tls_handshake_stream"
announce end wire/native-handshake-stream 0
announce start wire/native-schedule
bend tls_schedule_test.bend
python3 tls_schedule_type_check.py
../tools/bend_native.sh tls_schedule_cli.bend "$tmp/tls_schedule" > /dev/null
python3 tls_schedule_check.py -- "$tmp/tls_schedule"
announce end wire/native-schedule 0
announce start wire/native-foundations
python3 tls_handshake_vectors.py --check tls_handshake_vectors.json
bend tls_transcript_test.bend
python3 tls_transcript_type_check.py
../tools/bend_native.sh tls_transcript_cli.bend "$tmp/tls_transcript" > /dev/null
python3 tls_transcript_check.py -- "$tmp/tls_transcript"
python3 tls_transcript_check.py --stress -- "$tmp/tls_transcript"
bend tls_record_test.bend
../tools/bend_native.sh tls_record_write_cli.bend "$tmp/tls_record_write" > /dev/null
../tools/bend_native.sh tls_record_read_cli.bend "$tmp/tls_record_read" > /dev/null
python3 tls_record_check.py python3 tls_record_fixture.py --write "$tmp/tls_record_write" --read "$tmp/tls_record_read" --
python3 tls_record_check.py --aes python3 tls_record_fixture.py --write "$tmp/tls_record_write" --read "$tmp/tls_record_read" --
bend random.bend -o "$tmp/random" > /dev/null
python3 random_check.py "$tmp/random"
# a plain compiler meets CID(name) before Bend rewrites it: as an unset name,
# so the effect's Bend half drops out as in a program that does not use it
mkdir -p "$tmp/host/effs"
cp random_host_check.c "$tmp/host/"
sed -E 's/CID\(([A-Za-z_]+)\)/CID_\1/g' effs/random.c > "$tmp/host/effs/random.c"
"${CC:-cc}" -std=c11 -O2 -Wall -Wextra -Werror "$tmp/host/random_host_check.c" -o "$tmp/random_host_check"
"$tmp/random_host_check"
bend bench.bend -o "$tmp/bench" > /dev/null
python3 bench_check.py "$tmp/bench"
announce end wire/native-foundations 0
if command -v bun > /dev/null 2>&1; then
  announce start wire/bun-foundations
  bend tls_transcript_cli.bend -o "$tmp/tls_transcript.js" > /dev/null
  python3 tls_transcript_check.py -- bun "$tmp/tls_transcript.js"
  python3 tls_transcript_check.py --stress -- bun "$tmp/tls_transcript.js"
  bend tls_record_write_cli.bend -o "$tmp/tls_record_write.js" > /dev/null
  bend tls_record_read_cli.bend -o "$tmp/tls_record_read.js" > /dev/null
  python3 tls_record_check.py python3 tls_record_fixture.py --bun --write "$tmp/tls_record_write.js" --read "$tmp/tls_record_read.js" --
  python3 tls_record_check.py --aes python3 tls_record_fixture.py --bun --write "$tmp/tls_record_write.js" --read "$tmp/tls_record_read.js" --
  bend random.bend -o "$tmp/random.js" > /dev/null
  python3 random_check.py bun "$tmp/random.js"
  bun random_host_check.mjs
  bend bench.bend -o "$tmp/bench.js" > /dev/null
  python3 bench_check.py bun "$tmp/bench.js"
  announce end wire/bun-foundations 0
  announce start wire/bun-schedule
  bend tls_schedule_cli.bend -o "$tmp/tls_schedule.js" > /dev/null
  python3 tls_schedule_check.py -- bun "$tmp/tls_schedule.js"
  announce end wire/bun-schedule 0
  announce start wire/bun-handshake-stream
  bend tls_handshake_stream_cli.bend -o "$tmp/tls_handshake_stream.js" > /dev/null
  python3 tls_handshake_stream_check.py -- bun "$tmp/tls_handshake_stream.js"
  python3 tls_handshake_stream_check.py --stress -- bun "$tmp/tls_handshake_stream.js"
  announce end wire/bun-handshake-stream 0
  announce start wire/bun-extensions
  bend tls_extensions_cli.bend -o "$tmp/tls_extensions.js" > /dev/null
  python3 tls_extensions_check.py -- bun "$tmp/tls_extensions.js"
  python3 tls_extensions_check.py --stress -- bun "$tmp/tls_extensions.js"
  announce end wire/bun-extensions 0
else
  announce skip wire/bun-foundations "Bun unavailable"
  announce skip wire/bun-schedule "Bun unavailable"
  announce skip wire/bun-handshake-stream "Bun unavailable"
  announce skip wire/bun-extensions "Bun unavailable"
  echo "bulk RNG JS target: Bun unavailable; skipped"
fi
announce start wire/native-transport
bend loopback.bend -o "$tmp/loopback" > /dev/null
"$tmp/loopback"
bend timeout.bend -o "$tmp/timeout" > /dev/null
"$tmp/timeout"
bend udp.bend -o "$tmp/udp" > /dev/null
"$tmp/udp"
bend udp_address.bend -o "$tmp/udp_address" > /dev/null
python3 udp_address_check.py "$tmp/udp_address"
announce end wire/native-transport 0
if command -v bun > /dev/null 2>&1; then
  announce start wire/bun-udp
  bend udp.bend -o "$tmp/udp.js" > /dev/null
  bun "$tmp/udp.js"
  bend udp_address.bend -o "$tmp/udp_address.js" > /dev/null
  python3 udp_address_check.py bun "$tmp/udp_address.js"
  announce end wire/bun-udp 0
else
  announce skip wire/bun-udp "Bun unavailable"
  echo "udp JS target: Bun unavailable; skipped"
fi
announce start wire/native-stop
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
announce end wire/native-stop 0
if command -v bun > /dev/null 2>&1; then
  announce start wire/bun-stop
  bend stop.bend -o "$tmp/stop.js" > /dev/null
  python3 stop_check.py bun "$tmp/stop.js"
  announce end wire/bun-stop 0
else
  announce skip wire/bun-stop "Bun unavailable"
  echo "JS signal stop: Bun unavailable; skipped"
fi
announce start wire/native-tls
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
announce end wire/native-tls 0

# M3a synthetic-key TLS client. Byte TCP/RNG effects only.
m3_reports=${GROUNDS_M3_REPORT_DIR:-"$tmp/m3-reports"}
mkdir -p "$m3_reports"
announce start wire/m3-types/client
python3 tls_client_type_check.py
announce end wire/m3-types/client 0
announce start wire/m3-native/emit/tls_hello
bend tls_hello_cli.bend -o "$tmp/tls_hello.c" > /dev/null
announce end wire/m3-native/emit/tls_hello 0
announce start wire/m3-native/build/tls_hello
../tools/bend_native.sh "$tmp/tls_hello.c" "$tmp/tls_hello" > /dev/null
announce end wire/m3-native/build/tls_hello 0
announce start wire/m3-native/emit/tls_handshake_codec
bend tls_handshake_codec_cli.bend -o "$tmp/tls_handshake_codec.c" > /dev/null
announce end wire/m3-native/emit/tls_handshake_codec 0
announce start wire/m3-native/build/tls_handshake_codec
../tools/bend_native.sh "$tmp/tls_handshake_codec.c" "$tmp/tls_handshake_codec" > /dev/null
announce end wire/m3-native/build/tls_handshake_codec 0
announce start wire/m3-native/emit/tls_client_replay
bend tls_client_replay_cli.bend -o "$tmp/tls_client_replay.c" > /dev/null
announce end wire/m3-native/emit/tls_client_replay 0
announce start wire/m3-native/build/tls_client_replay
../tools/bend_native.sh "$tmp/tls_client_replay.c" "$tmp/tls_client_replay" > /dev/null
announce end wire/m3-native/build/tls_client_replay 0
announce start wire/m3-native/emit/bend_tls_client
python3 bend_tls_no_delegation_build.py --program client --output "$tmp/bend_tls_client.c" --report "$m3_reports/client-disabled-c-build.json"
announce end wire/m3-native/emit/bend_tls_client 0
announce start wire/m3-native/build/bend_tls_client
../tools/bend_native.sh "$tmp/bend_tls_client.c" "$tmp/bend_tls_client" > /dev/null
announce end wire/m3-native/build/bend_tls_client 0
announce start wire/m3-native/check/tls_hello
python3 tls_hello_check.py --report "$m3_reports/tls_hello-native.json" -- "$tmp/tls_hello"
announce end wire/m3-native/check/tls_hello 0
announce start wire/m3-native/check/tls_hello-stress
python3 tls_hello_check.py --stress --report "$m3_reports/tls_hello-stress-native.json" -- "$tmp/tls_hello"
announce end wire/m3-native/check/tls_hello-stress 0
announce start wire/m3-native/check/tls_handshake_codec
python3 tls_handshake_codec_check.py --report "$m3_reports/tls_handshake_codec-native.json" -- "$tmp/tls_handshake_codec"
announce end wire/m3-native/check/tls_handshake_codec 0
announce start wire/m3-native/check/tls_handshake_codec-stress
python3 tls_handshake_codec_check.py --stress --report "$m3_reports/tls_handshake_codec-stress-native.json" -- "$tmp/tls_handshake_codec"
announce end wire/m3-native/check/tls_handshake_codec-stress 0
announce start wire/m3-native/check/diagnostics
python3 tls_client_diagnostics_check.py --report "$m3_reports/diagnostics-native.json" -- "$tmp/bend_tls_client"
announce end wire/m3-native/check/diagnostics 0
announce start wire/m3-native/check/replay
python3 tls_client_replay_check.py --report "$m3_reports/replay-native.json" -- "$tmp/tls_client_replay"
announce end wire/m3-native/check/replay 0
announce start wire/m3-native/interop/000
python3 bend_tls_client_check.py --batch-index 0 --report "$m3_reports/interop-native-000.json" -- "$tmp/bend_tls_client"
announce end wire/m3-native/interop/000 0
announce start wire/m3-native/interop/001
python3 bend_tls_client_check.py --batch-index 1 --report "$m3_reports/interop-native-001.json" -- "$tmp/bend_tls_client"
announce end wire/m3-native/interop/001 0
announce start wire/m3-native/interop/002
python3 bend_tls_client_check.py --batch-index 2 --report "$m3_reports/interop-native-002.json" -- "$tmp/bend_tls_client"
announce end wire/m3-native/interop/002 0
announce start wire/m3-native/interop/003
python3 bend_tls_client_check.py --batch-index 3 --report "$m3_reports/interop-native-003.json" -- "$tmp/bend_tls_client"
announce end wire/m3-native/interop/003 0
announce start wire/m3-native/interop/004
python3 bend_tls_client_check.py --batch-index 4 --report "$m3_reports/interop-native-004.json" -- "$tmp/bend_tls_client"
announce end wire/m3-native/interop/004 0
announce start wire/m3-native/interop/005
python3 bend_tls_client_check.py --batch-index 5 --report "$m3_reports/interop-native-005.json" -- "$tmp/bend_tls_client"
announce end wire/m3-native/interop/005 0
announce start wire/m3-native/interop/006
python3 bend_tls_client_check.py --batch-index 6 --report "$m3_reports/interop-native-006.json" -- "$tmp/bend_tls_client"
announce end wire/m3-native/interop/006 0
announce start wire/m3-native/interop/007
python3 bend_tls_client_check.py --batch-index 7 --report "$m3_reports/interop-native-007.json" -- "$tmp/bend_tls_client"
announce end wire/m3-native/interop/007 0
announce start wire/m3-native/interop/008
python3 bend_tls_client_check.py --batch-index 8 --report "$m3_reports/interop-native-008.json" -- "$tmp/bend_tls_client"
announce end wire/m3-native/interop/008 0
announce start wire/m3-native/interop/009
python3 bend_tls_client_check.py --batch-index 9 --report "$m3_reports/interop-native-009.json" -- "$tmp/bend_tls_client"
announce end wire/m3-native/interop/009 0
announce start wire/m3-native/interop/010
python3 bend_tls_client_check.py --batch-index 10 --report "$m3_reports/interop-native-010.json" -- "$tmp/bend_tls_client"
announce end wire/m3-native/interop/010 0
announce start wire/m3-native/interop/011
python3 bend_tls_client_check.py --batch-index 11 --report "$m3_reports/interop-native-011.json" -- "$tmp/bend_tls_client"
announce end wire/m3-native/interop/011 0
announce start wire/m3-native/interop/012
python3 bend_tls_client_check.py --batch-index 12 --report "$m3_reports/interop-native-012.json" -- "$tmp/bend_tls_client"
announce end wire/m3-native/interop/012 0
announce start wire/m3-native/interop/013
python3 bend_tls_client_check.py --batch-index 13 --report "$m3_reports/interop-native-013.json" -- "$tmp/bend_tls_client"
announce end wire/m3-native/interop/013 0
announce start wire/m3-native/interop/014
python3 bend_tls_client_check.py --batch-index 14 --report "$m3_reports/interop-native-014.json" -- "$tmp/bend_tls_client"
announce end wire/m3-native/interop/014 0
announce start wire/m3-native/interop/015
python3 bend_tls_client_check.py --batch-index 15 --report "$m3_reports/interop-native-015.json" -- "$tmp/bend_tls_client"
announce end wire/m3-native/interop/015 0
announce start wire/m3-native/interop/016
python3 bend_tls_client_check.py --batch-index 16 --report "$m3_reports/interop-native-016.json" -- "$tmp/bend_tls_client"
announce end wire/m3-native/interop/016 0
announce start wire/m3-native/interop/017
python3 bend_tls_client_check.py --batch-index 17 --report "$m3_reports/interop-native-017.json" -- "$tmp/bend_tls_client"
announce end wire/m3-native/interop/017 0
announce start wire/m3-native/interop/018
python3 bend_tls_client_check.py --batch-index 18 --report "$m3_reports/interop-native-018.json" -- "$tmp/bend_tls_client"
announce end wire/m3-native/interop/018 0
announce start wire/m3-native/interop/019
python3 bend_tls_client_check.py --batch-index 19 --report "$m3_reports/interop-native-019.json" -- "$tmp/bend_tls_client"
announce end wire/m3-native/interop/019 0
announce start wire/m3-native/interop/020
python3 bend_tls_client_check.py --batch-index 20 --report "$m3_reports/interop-native-020.json" -- "$tmp/bend_tls_client"
announce end wire/m3-native/interop/020 0
announce start wire/m3-native/interop/021
python3 bend_tls_client_check.py --batch-index 21 --report "$m3_reports/interop-native-021.json" -- "$tmp/bend_tls_client"
announce end wire/m3-native/interop/021 0
announce start wire/m3-native/interop/022
python3 bend_tls_client_check.py --batch-index 22 --report "$m3_reports/interop-native-022.json" -- "$tmp/bend_tls_client"
announce end wire/m3-native/interop/022 0
announce start wire/m3-native/interop/023
python3 bend_tls_client_check.py --batch-index 23 --report "$m3_reports/interop-native-023.json" -- "$tmp/bend_tls_client"
announce end wire/m3-native/interop/023 0
announce start wire/m3-native/interop/024
python3 bend_tls_client_check.py --batch-index 24 --report "$m3_reports/interop-native-024.json" -- "$tmp/bend_tls_client"
announce end wire/m3-native/interop/024 0
announce start wire/m3-native/interop/025
python3 bend_tls_client_check.py --batch-index 25 --report "$m3_reports/interop-native-025.json" -- "$tmp/bend_tls_client"
announce end wire/m3-native/interop/025 0
announce start wire/m3-native/interop/026
python3 bend_tls_client_check.py --batch-index 26 --report "$m3_reports/interop-native-026.json" -- "$tmp/bend_tls_client"
announce end wire/m3-native/interop/026 0
announce start wire/m3-native/interop/027
python3 bend_tls_client_check.py --batch-index 27 --report "$m3_reports/interop-native-027.json" -- "$tmp/bend_tls_client"
announce end wire/m3-native/interop/027 0
if command -v bun > /dev/null 2>&1; then
announce start wire/m3-bun/build/tls_hello
bend tls_hello_cli.bend -o "$tmp/tls_hello.js" > /dev/null
announce end wire/m3-bun/build/tls_hello 0
announce start wire/m3-bun/build/tls_handshake_codec
bend tls_handshake_codec_cli.bend -o "$tmp/tls_handshake_codec.js" > /dev/null
announce end wire/m3-bun/build/tls_handshake_codec 0
announce start wire/m3-bun/build/tls_client_replay
bend tls_client_replay_cli.bend -o "$tmp/tls_client_replay.js" > /dev/null
announce end wire/m3-bun/build/tls_client_replay 0
announce start wire/m3-bun/build/bend_tls_client
python3 bend_tls_no_delegation_build.py --program client --output "$tmp/bend_tls_client.js" --report "$m3_reports/client-disabled-js-build.json"
announce end wire/m3-bun/build/bend_tls_client 0
announce start wire/m3-bun/check/tls_hello
python3 tls_hello_check.py --report "$m3_reports/tls_hello-bun.json" -- bun "$tmp/tls_hello.js"
announce end wire/m3-bun/check/tls_hello 0
announce start wire/m3-bun/check/tls_hello-stress
python3 tls_hello_check.py --stress --report "$m3_reports/tls_hello-stress-bun.json" -- bun "$tmp/tls_hello.js"
announce end wire/m3-bun/check/tls_hello-stress 0
announce start wire/m3-bun/check/tls_handshake_codec
python3 tls_handshake_codec_check.py --report "$m3_reports/tls_handshake_codec-bun.json" -- bun "$tmp/tls_handshake_codec.js"
announce end wire/m3-bun/check/tls_handshake_codec 0
announce start wire/m3-bun/check/tls_handshake_codec-stress
python3 tls_handshake_codec_check.py --stress --report "$m3_reports/tls_handshake_codec-stress-bun.json" -- bun "$tmp/tls_handshake_codec.js"
announce end wire/m3-bun/check/tls_handshake_codec-stress 0
announce start wire/m3-bun/check/diagnostics
python3 tls_client_diagnostics_check.py --report "$m3_reports/diagnostics-bun.json" -- bun "$tmp/bend_tls_client.js"
announce end wire/m3-bun/check/diagnostics 0
announce start wire/m3-bun/check/replay
python3 tls_client_replay_check.py --report "$m3_reports/replay-bun.json" -- bun "$tmp/tls_client_replay.js"
announce end wire/m3-bun/check/replay 0
announce start wire/m3-bun/interop/000
python3 bend_tls_client_check.py --batch-index 0 --report "$m3_reports/interop-bun-000.json" -- bun "$tmp/bend_tls_client.js"
announce end wire/m3-bun/interop/000 0
announce start wire/m3-bun/interop/001
python3 bend_tls_client_check.py --batch-index 1 --report "$m3_reports/interop-bun-001.json" -- bun "$tmp/bend_tls_client.js"
announce end wire/m3-bun/interop/001 0
announce start wire/m3-bun/interop/002
python3 bend_tls_client_check.py --batch-index 2 --report "$m3_reports/interop-bun-002.json" -- bun "$tmp/bend_tls_client.js"
announce end wire/m3-bun/interop/002 0
announce start wire/m3-bun/interop/003
python3 bend_tls_client_check.py --batch-index 3 --report "$m3_reports/interop-bun-003.json" -- bun "$tmp/bend_tls_client.js"
announce end wire/m3-bun/interop/003 0
announce start wire/m3-bun/interop/004
python3 bend_tls_client_check.py --batch-index 4 --report "$m3_reports/interop-bun-004.json" -- bun "$tmp/bend_tls_client.js"
announce end wire/m3-bun/interop/004 0
announce start wire/m3-bun/interop/005
python3 bend_tls_client_check.py --batch-index 5 --report "$m3_reports/interop-bun-005.json" -- bun "$tmp/bend_tls_client.js"
announce end wire/m3-bun/interop/005 0
announce start wire/m3-bun/interop/006
python3 bend_tls_client_check.py --batch-index 6 --report "$m3_reports/interop-bun-006.json" -- bun "$tmp/bend_tls_client.js"
announce end wire/m3-bun/interop/006 0
announce start wire/m3-bun/interop/007
python3 bend_tls_client_check.py --batch-index 7 --report "$m3_reports/interop-bun-007.json" -- bun "$tmp/bend_tls_client.js"
announce end wire/m3-bun/interop/007 0
announce start wire/m3-bun/interop/008
python3 bend_tls_client_check.py --batch-index 8 --report "$m3_reports/interop-bun-008.json" -- bun "$tmp/bend_tls_client.js"
announce end wire/m3-bun/interop/008 0
announce start wire/m3-bun/interop/009
python3 bend_tls_client_check.py --batch-index 9 --report "$m3_reports/interop-bun-009.json" -- bun "$tmp/bend_tls_client.js"
announce end wire/m3-bun/interop/009 0
announce start wire/m3-bun/interop/010
python3 bend_tls_client_check.py --batch-index 10 --report "$m3_reports/interop-bun-010.json" -- bun "$tmp/bend_tls_client.js"
announce end wire/m3-bun/interop/010 0
announce start wire/m3-bun/interop/011
python3 bend_tls_client_check.py --batch-index 11 --report "$m3_reports/interop-bun-011.json" -- bun "$tmp/bend_tls_client.js"
announce end wire/m3-bun/interop/011 0
announce start wire/m3-bun/interop/012
python3 bend_tls_client_check.py --batch-index 12 --report "$m3_reports/interop-bun-012.json" -- bun "$tmp/bend_tls_client.js"
announce end wire/m3-bun/interop/012 0
announce start wire/m3-bun/interop/013
python3 bend_tls_client_check.py --batch-index 13 --report "$m3_reports/interop-bun-013.json" -- bun "$tmp/bend_tls_client.js"
announce end wire/m3-bun/interop/013 0
announce start wire/m3-bun/interop/014
python3 bend_tls_client_check.py --batch-index 14 --report "$m3_reports/interop-bun-014.json" -- bun "$tmp/bend_tls_client.js"
announce end wire/m3-bun/interop/014 0
announce start wire/m3-bun/interop/015
python3 bend_tls_client_check.py --batch-index 15 --report "$m3_reports/interop-bun-015.json" -- bun "$tmp/bend_tls_client.js"
announce end wire/m3-bun/interop/015 0
announce start wire/m3-bun/interop/016
python3 bend_tls_client_check.py --batch-index 16 --report "$m3_reports/interop-bun-016.json" -- bun "$tmp/bend_tls_client.js"
announce end wire/m3-bun/interop/016 0
announce start wire/m3-bun/interop/017
python3 bend_tls_client_check.py --batch-index 17 --report "$m3_reports/interop-bun-017.json" -- bun "$tmp/bend_tls_client.js"
announce end wire/m3-bun/interop/017 0
announce start wire/m3-bun/interop/018
python3 bend_tls_client_check.py --batch-index 18 --report "$m3_reports/interop-bun-018.json" -- bun "$tmp/bend_tls_client.js"
announce end wire/m3-bun/interop/018 0
announce start wire/m3-bun/interop/019
python3 bend_tls_client_check.py --batch-index 19 --report "$m3_reports/interop-bun-019.json" -- bun "$tmp/bend_tls_client.js"
announce end wire/m3-bun/interop/019 0
announce start wire/m3-bun/interop/020
python3 bend_tls_client_check.py --batch-index 20 --report "$m3_reports/interop-bun-020.json" -- bun "$tmp/bend_tls_client.js"
announce end wire/m3-bun/interop/020 0
announce start wire/m3-bun/interop/021
python3 bend_tls_client_check.py --batch-index 21 --report "$m3_reports/interop-bun-021.json" -- bun "$tmp/bend_tls_client.js"
announce end wire/m3-bun/interop/021 0
announce start wire/m3-bun/interop/022
python3 bend_tls_client_check.py --batch-index 22 --report "$m3_reports/interop-bun-022.json" -- bun "$tmp/bend_tls_client.js"
announce end wire/m3-bun/interop/022 0
announce start wire/m3-bun/interop/023
python3 bend_tls_client_check.py --batch-index 23 --report "$m3_reports/interop-bun-023.json" -- bun "$tmp/bend_tls_client.js"
announce end wire/m3-bun/interop/023 0
announce start wire/m3-bun/interop/024
python3 bend_tls_client_check.py --batch-index 24 --report "$m3_reports/interop-bun-024.json" -- bun "$tmp/bend_tls_client.js"
announce end wire/m3-bun/interop/024 0
announce start wire/m3-bun/interop/025
python3 bend_tls_client_check.py --batch-index 25 --report "$m3_reports/interop-bun-025.json" -- bun "$tmp/bend_tls_client.js"
announce end wire/m3-bun/interop/025 0
announce start wire/m3-bun/interop/026
python3 bend_tls_client_check.py --batch-index 26 --report "$m3_reports/interop-bun-026.json" -- bun "$tmp/bend_tls_client.js"
announce end wire/m3-bun/interop/026 0
announce start wire/m3-bun/interop/027
python3 bend_tls_client_check.py --batch-index 27 --report "$m3_reports/interop-bun-027.json" -- bun "$tmp/bend_tls_client.js"
announce end wire/m3-bun/interop/027 0
announce start wire/m3-audit/no-openssl
cp "$tmp/bend_tls_client.c" "$tmp/bend_tls_client.js" "$tmp/bend_tls_client" "$m3_reports/"
python3 bend_tls_no_openssl_check.py --native "$tmp/bend_tls_client" --c "$tmp/bend_tls_client.c" --js "$tmp/bend_tls_client.js" --report "$m3_reports/no-openssl.json"
announce end wire/m3-audit/no-openssl 0
else
announce skip wire/m3-bun/build/tls_hello "Bun unavailable"
announce skip wire/m3-bun/build/tls_handshake_codec "Bun unavailable"
announce skip wire/m3-bun/build/tls_client_replay "Bun unavailable"
announce skip wire/m3-bun/build/bend_tls_client "Bun unavailable"
announce skip wire/m3-bun/check/tls_hello "Bun unavailable"
announce skip wire/m3-bun/check/tls_hello-stress "Bun unavailable"
announce skip wire/m3-bun/check/tls_handshake_codec "Bun unavailable"
announce skip wire/m3-bun/check/tls_handshake_codec-stress "Bun unavailable"
announce skip wire/m3-bun/check/diagnostics "Bun unavailable"
announce skip wire/m3-bun/check/replay "Bun unavailable"
announce skip wire/m3-bun/interop/000 "Bun unavailable"
announce skip wire/m3-bun/interop/001 "Bun unavailable"
announce skip wire/m3-bun/interop/002 "Bun unavailable"
announce skip wire/m3-bun/interop/003 "Bun unavailable"
announce skip wire/m3-bun/interop/004 "Bun unavailable"
announce skip wire/m3-bun/interop/005 "Bun unavailable"
announce skip wire/m3-bun/interop/006 "Bun unavailable"
announce skip wire/m3-bun/interop/007 "Bun unavailable"
announce skip wire/m3-bun/interop/008 "Bun unavailable"
announce skip wire/m3-bun/interop/009 "Bun unavailable"
announce skip wire/m3-bun/interop/010 "Bun unavailable"
announce skip wire/m3-bun/interop/011 "Bun unavailable"
announce skip wire/m3-bun/interop/012 "Bun unavailable"
announce skip wire/m3-bun/interop/013 "Bun unavailable"
announce skip wire/m3-bun/interop/014 "Bun unavailable"
announce skip wire/m3-bun/interop/015 "Bun unavailable"
announce skip wire/m3-bun/interop/016 "Bun unavailable"
announce skip wire/m3-bun/interop/017 "Bun unavailable"
announce skip wire/m3-bun/interop/018 "Bun unavailable"
announce skip wire/m3-bun/interop/019 "Bun unavailable"
announce skip wire/m3-bun/interop/020 "Bun unavailable"
announce skip wire/m3-bun/interop/021 "Bun unavailable"
announce skip wire/m3-bun/interop/022 "Bun unavailable"
announce skip wire/m3-bun/interop/023 "Bun unavailable"
announce skip wire/m3-bun/interop/024 "Bun unavailable"
announce skip wire/m3-bun/interop/025 "Bun unavailable"
announce skip wire/m3-bun/interop/026 "Bun unavailable"
announce skip wire/m3-bun/interop/027 "Bun unavailable"
announce skip wire/m3-audit/no-openssl "Bun unavailable"
fi

## M3b: both roles; every evaluator disables legacy TLS/cookie effects.
announce start wire/m3b-types/server
python3 tls_server_type_check.py
announce end wire/m3b-types/server 0
announce start wire/m3b-peer/build/go
python3 tls_go_peer_build.py --output "$tmp/tls_go_peer" --report "$m3_reports/go-peer-build.json"
announce end wire/m3b-peer/build/go 0
announce start wire/m3b-controls/emit/legacy-probe
python3 bend_tls_no_delegation_build.py --program legacy-probe --output "$tmp/legacy-probe.c" --report "$m3_reports/legacy-probe-c-build.json"
announce end wire/m3b-controls/emit/legacy-probe 0
announce start wire/m3b-controls/native/legacy-probe
../tools/bend_native.sh "$tmp/legacy-probe.c" "$tmp/legacy-probe" > /dev/null
announce end wire/m3b-controls/native/legacy-probe 0
announce start wire/m3b-controls/bun/legacy-probe
python3 bend_tls_no_delegation_build.py --program legacy-probe --output "$tmp/legacy-probe.js" --report "$m3_reports/legacy-probe-js-build.json"
announce end wire/m3b-controls/bun/legacy-probe 0
announce start wire/m3b-controls/check/legacy-probe
python3 bend_tls_disabled_effects_check.py --native "$tmp/legacy-probe" --js "$tmp/legacy-probe.js" --effect wire_tls_listen_ctx --report "$m3_reports/legacy-probe-controls.json"
announce end wire/m3b-controls/check/legacy-probe 0
announce start wire/m3b-controls/emit/cookie-probe
python3 bend_tls_no_delegation_build.py --program cookie-probe --output "$tmp/cookie-probe.c" --report "$m3_reports/cookie-probe-c-build.json"
announce end wire/m3b-controls/emit/cookie-probe 0
announce start wire/m3b-controls/native/cookie-probe
../tools/bend_native.sh "$tmp/cookie-probe.c" "$tmp/cookie-probe" > /dev/null
announce end wire/m3b-controls/native/cookie-probe 0
announce start wire/m3b-controls/bun/cookie-probe
python3 bend_tls_no_delegation_build.py --program cookie-probe --output "$tmp/cookie-probe.js" --report "$m3_reports/cookie-probe-js-build.json"
announce end wire/m3b-controls/bun/cookie-probe 0
announce start wire/m3b-controls/check/cookie-probe
python3 bend_tls_disabled_effects_check.py --native "$tmp/cookie-probe" --js "$tmp/cookie-probe.js" --effect sign --report "$m3_reports/cookie-probe-controls.json"
announce end wire/m3b-controls/check/cookie-probe 0
announce start wire/m3b-native/emit/negotiation
bend tls_server_handshake_cli.bend -o "$tmp/server_negotiation.c" > /dev/null
announce end wire/m3b-native/emit/negotiation 0
announce start wire/m3b-native/build/negotiation
../tools/bend_native.sh "$tmp/server_negotiation.c" "$tmp/server_negotiation" > /dev/null
announce end wire/m3b-native/build/negotiation 0
announce start wire/m3b-native/check/negotiation
python3 tls_server_handshake_check.py --report "$m3_reports/server-negotiation-native.json" -- "$tmp/server_negotiation"
announce end wire/m3b-native/check/negotiation 0
announce start wire/m3b-native/emit/server
python3 bend_tls_no_delegation_build.py --program server --output "$tmp/bend_tls_server.c" --report "$m3_reports/server-disabled-c-build.json"
announce end wire/m3b-native/emit/server 0
announce start wire/m3b-native/build/server
../tools/bend_native.sh "$tmp/bend_tls_server.c" "$tmp/bend_tls_server" > /dev/null
announce end wire/m3b-native/build/server 0
announce start wire/m3b-bun/build/negotiation
bend tls_server_handshake_cli.bend -o "$tmp/server_negotiation.js" > /dev/null
announce end wire/m3b-bun/build/negotiation 0
announce start wire/m3b-bun/check/negotiation
python3 tls_server_handshake_check.py --report "$m3_reports/server-negotiation-bun.json" -- bun "$tmp/server_negotiation.js"
announce end wire/m3b-bun/check/negotiation 0
announce start wire/m3b-bun/build/server
python3 bend_tls_no_delegation_build.py --program server --output "$tmp/bend_tls_server.js" --report "$m3_reports/server-disabled-js-build.json"
announce end wire/m3b-bun/build/server 0
announce start wire/m3b-audit/server-no-openssl
cp "$tmp/bend_tls_server.c" "$tmp/bend_tls_server.js" "$tmp/bend_tls_server" "$m3_reports/"
python3 bend_tls_no_openssl_check.py --role server --native "$tmp/bend_tls_server" --c "$tmp/bend_tls_server.c" --js "$tmp/bend_tls_server.js" --report "$m3_reports/server-no-openssl.json"
announce end wire/m3b-audit/server-no-openssl 0
announce start wire/m3b-native/server/000
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 0 --report "$m3_reports/server-native-000.json" -- "$tmp/bend_tls_server"
announce end wire/m3b-native/server/000 0
announce start wire/m3b-native/server/001
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 1 --report "$m3_reports/server-native-001.json" -- "$tmp/bend_tls_server"
announce end wire/m3b-native/server/001 0
announce start wire/m3b-native/server/002
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 2 --report "$m3_reports/server-native-002.json" -- "$tmp/bend_tls_server"
announce end wire/m3b-native/server/002 0
announce start wire/m3b-native/server/003
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 3 --report "$m3_reports/server-native-003.json" -- "$tmp/bend_tls_server"
announce end wire/m3b-native/server/003 0
announce start wire/m3b-native/server/004
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 4 --report "$m3_reports/server-native-004.json" -- "$tmp/bend_tls_server"
announce end wire/m3b-native/server/004 0
announce start wire/m3b-native/server/005
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 5 --report "$m3_reports/server-native-005.json" -- "$tmp/bend_tls_server"
announce end wire/m3b-native/server/005 0
announce start wire/m3b-native/server/006
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 6 --report "$m3_reports/server-native-006.json" -- "$tmp/bend_tls_server"
announce end wire/m3b-native/server/006 0
announce start wire/m3b-native/server/007
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 7 --report "$m3_reports/server-native-007.json" -- "$tmp/bend_tls_server"
announce end wire/m3b-native/server/007 0
announce start wire/m3b-native/server/008
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 8 --report "$m3_reports/server-native-008.json" -- "$tmp/bend_tls_server"
announce end wire/m3b-native/server/008 0
announce start wire/m3b-native/server/009
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 9 --report "$m3_reports/server-native-009.json" -- "$tmp/bend_tls_server"
announce end wire/m3b-native/server/009 0
announce start wire/m3b-native/server/010
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 10 --report "$m3_reports/server-native-010.json" -- "$tmp/bend_tls_server"
announce end wire/m3b-native/server/010 0
announce start wire/m3b-native/server/011
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 11 --report "$m3_reports/server-native-011.json" -- "$tmp/bend_tls_server"
announce end wire/m3b-native/server/011 0
announce start wire/m3b-native/server/012
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 12 --report "$m3_reports/server-native-012.json" -- "$tmp/bend_tls_server"
announce end wire/m3b-native/server/012 0
announce start wire/m3b-native/server/013
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 13 --report "$m3_reports/server-native-013.json" -- "$tmp/bend_tls_server"
announce end wire/m3b-native/server/013 0
announce start wire/m3b-native/server/014
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 14 --report "$m3_reports/server-native-014.json" -- "$tmp/bend_tls_server"
announce end wire/m3b-native/server/014 0
announce start wire/m3b-native/server/015
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 15 --report "$m3_reports/server-native-015.json" -- "$tmp/bend_tls_server"
announce end wire/m3b-native/server/015 0
announce start wire/m3b-native/server/016
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 16 --report "$m3_reports/server-native-016.json" -- "$tmp/bend_tls_server"
announce end wire/m3b-native/server/016 0
announce start wire/m3b-native/server/017
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 17 --report "$m3_reports/server-native-017.json" -- "$tmp/bend_tls_server"
announce end wire/m3b-native/server/017 0
announce start wire/m3b-native/server/018
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 18 --report "$m3_reports/server-native-018.json" -- "$tmp/bend_tls_server"
announce end wire/m3b-native/server/018 0
announce start wire/m3b-native/server/019
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 19 --report "$m3_reports/server-native-019.json" -- "$tmp/bend_tls_server"
announce end wire/m3b-native/server/019 0
announce start wire/m3b-native/server/020
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 20 --report "$m3_reports/server-native-020.json" -- "$tmp/bend_tls_server"
announce end wire/m3b-native/server/020 0
announce start wire/m3b-native/server/021
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 21 --report "$m3_reports/server-native-021.json" -- "$tmp/bend_tls_server"
announce end wire/m3b-native/server/021 0
announce start wire/m3b-native/server/022
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 22 --report "$m3_reports/server-native-022.json" -- "$tmp/bend_tls_server"
announce end wire/m3b-native/server/022 0
announce start wire/m3b-native/server/023
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 23 --report "$m3_reports/server-native-023.json" -- "$tmp/bend_tls_server"
announce end wire/m3b-native/server/023 0
announce start wire/m3b-native/server/024
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 24 --report "$m3_reports/server-native-024.json" -- "$tmp/bend_tls_server"
announce end wire/m3b-native/server/024 0
announce start wire/m3b-native/server/025
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 25 --report "$m3_reports/server-native-025.json" -- "$tmp/bend_tls_server"
announce end wire/m3b-native/server/025 0
announce start wire/m3b-native/server/026
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 26 --report "$m3_reports/server-native-026.json" -- "$tmp/bend_tls_server"
announce end wire/m3b-native/server/026 0
announce start wire/m3b-native/server/027
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 27 --report "$m3_reports/server-native-027.json" -- "$tmp/bend_tls_server"
announce end wire/m3b-native/server/027 0
announce start wire/m3b-native/server/028
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 28 --report "$m3_reports/server-native-028.json" -- "$tmp/bend_tls_server"
announce end wire/m3b-native/server/028 0
announce start wire/m3b-native/server/029
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 29 --report "$m3_reports/server-native-029.json" -- "$tmp/bend_tls_server"
announce end wire/m3b-native/server/029 0
announce start wire/m3b-native/server/030
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 30 --report "$m3_reports/server-native-030.json" -- "$tmp/bend_tls_server"
announce end wire/m3b-native/server/030 0
announce start wire/m3b-native/server/031
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 31 --report "$m3_reports/server-native-031.json" -- "$tmp/bend_tls_server"
announce end wire/m3b-native/server/031 0
announce start wire/m3b-native/server/032
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 32 --report "$m3_reports/server-native-032.json" -- "$tmp/bend_tls_server"
announce end wire/m3b-native/server/032 0
announce start wire/m3b-native/server/033
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 33 --report "$m3_reports/server-native-033.json" -- "$tmp/bend_tls_server"
announce end wire/m3b-native/server/033 0
announce start wire/m3b-native/server/034
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 34 --report "$m3_reports/server-native-034.json" -- "$tmp/bend_tls_server"
announce end wire/m3b-native/server/034 0
announce start wire/m3b-native/server/035
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 35 --report "$m3_reports/server-native-035.json" -- "$tmp/bend_tls_server"
announce end wire/m3b-native/server/035 0
announce start wire/m3b-native/server/036
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 36 --report "$m3_reports/server-native-036.json" -- "$tmp/bend_tls_server"
announce end wire/m3b-native/server/036 0
announce start wire/m3b-native/server/037
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 37 --report "$m3_reports/server-native-037.json" -- "$tmp/bend_tls_server"
announce end wire/m3b-native/server/037 0
announce start wire/m3b-native/peers/000
python3 bend_tls_peer_check.py --expected-batches 12 --batch-index 0 --server "$tmp/bend_tls_server" --client "$tmp/bend_tls_client" --go-peer "$tmp/tls_go_peer" --report "$m3_reports/peers-native-000.json"
announce end wire/m3b-native/peers/000 0
announce start wire/m3b-native/peers/001
python3 bend_tls_peer_check.py --expected-batches 12 --batch-index 1 --server "$tmp/bend_tls_server" --client "$tmp/bend_tls_client" --go-peer "$tmp/tls_go_peer" --report "$m3_reports/peers-native-001.json"
announce end wire/m3b-native/peers/001 0
announce start wire/m3b-native/peers/002
python3 bend_tls_peer_check.py --expected-batches 12 --batch-index 2 --server "$tmp/bend_tls_server" --client "$tmp/bend_tls_client" --go-peer "$tmp/tls_go_peer" --report "$m3_reports/peers-native-002.json"
announce end wire/m3b-native/peers/002 0
announce start wire/m3b-native/peers/003
python3 bend_tls_peer_check.py --expected-batches 12 --batch-index 3 --server "$tmp/bend_tls_server" --client "$tmp/bend_tls_client" --go-peer "$tmp/tls_go_peer" --report "$m3_reports/peers-native-003.json"
announce end wire/m3b-native/peers/003 0
announce start wire/m3b-native/peers/004
python3 bend_tls_peer_check.py --expected-batches 12 --batch-index 4 --server "$tmp/bend_tls_server" --client "$tmp/bend_tls_client" --go-peer "$tmp/tls_go_peer" --report "$m3_reports/peers-native-004.json"
announce end wire/m3b-native/peers/004 0
announce start wire/m3b-native/peers/005
python3 bend_tls_peer_check.py --expected-batches 12 --batch-index 5 --server "$tmp/bend_tls_server" --client "$tmp/bend_tls_client" --go-peer "$tmp/tls_go_peer" --report "$m3_reports/peers-native-005.json"
announce end wire/m3b-native/peers/005 0
announce start wire/m3b-native/peers/006
python3 bend_tls_peer_check.py --expected-batches 12 --batch-index 6 --server "$tmp/bend_tls_server" --client "$tmp/bend_tls_client" --go-peer "$tmp/tls_go_peer" --report "$m3_reports/peers-native-006.json"
announce end wire/m3b-native/peers/006 0
announce start wire/m3b-native/peers/007
python3 bend_tls_peer_check.py --expected-batches 12 --batch-index 7 --server "$tmp/bend_tls_server" --client "$tmp/bend_tls_client" --go-peer "$tmp/tls_go_peer" --report "$m3_reports/peers-native-007.json"
announce end wire/m3b-native/peers/007 0
announce start wire/m3b-native/peers/008
python3 bend_tls_peer_check.py --expected-batches 12 --batch-index 8 --server "$tmp/bend_tls_server" --client "$tmp/bend_tls_client" --go-peer "$tmp/tls_go_peer" --report "$m3_reports/peers-native-008.json"
announce end wire/m3b-native/peers/008 0
announce start wire/m3b-native/peers/009
python3 bend_tls_peer_check.py --expected-batches 12 --batch-index 9 --server "$tmp/bend_tls_server" --client "$tmp/bend_tls_client" --go-peer "$tmp/tls_go_peer" --report "$m3_reports/peers-native-009.json"
announce end wire/m3b-native/peers/009 0
announce start wire/m3b-native/peers/010
python3 bend_tls_peer_check.py --expected-batches 12 --batch-index 10 --server "$tmp/bend_tls_server" --client "$tmp/bend_tls_client" --go-peer "$tmp/tls_go_peer" --report "$m3_reports/peers-native-010.json"
announce end wire/m3b-native/peers/010 0
announce start wire/m3b-native/peers/011
python3 bend_tls_peer_check.py --expected-batches 12 --batch-index 11 --server "$tmp/bend_tls_server" --client "$tmp/bend_tls_client" --go-peer "$tmp/tls_go_peer" --report "$m3_reports/peers-native-011.json"
announce end wire/m3b-native/peers/011 0
announce start wire/m3b-bun/server/000
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 0 --report "$m3_reports/server-bun-000.json" -- bun "$tmp/bend_tls_server.js"
announce end wire/m3b-bun/server/000 0
announce start wire/m3b-bun/server/001
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 1 --report "$m3_reports/server-bun-001.json" -- bun "$tmp/bend_tls_server.js"
announce end wire/m3b-bun/server/001 0
announce start wire/m3b-bun/server/002
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 2 --report "$m3_reports/server-bun-002.json" -- bun "$tmp/bend_tls_server.js"
announce end wire/m3b-bun/server/002 0
announce start wire/m3b-bun/server/003
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 3 --report "$m3_reports/server-bun-003.json" -- bun "$tmp/bend_tls_server.js"
announce end wire/m3b-bun/server/003 0
announce start wire/m3b-bun/server/004
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 4 --report "$m3_reports/server-bun-004.json" -- bun "$tmp/bend_tls_server.js"
announce end wire/m3b-bun/server/004 0
announce start wire/m3b-bun/server/005
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 5 --report "$m3_reports/server-bun-005.json" -- bun "$tmp/bend_tls_server.js"
announce end wire/m3b-bun/server/005 0
announce start wire/m3b-bun/server/006
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 6 --report "$m3_reports/server-bun-006.json" -- bun "$tmp/bend_tls_server.js"
announce end wire/m3b-bun/server/006 0
announce start wire/m3b-bun/server/007
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 7 --report "$m3_reports/server-bun-007.json" -- bun "$tmp/bend_tls_server.js"
announce end wire/m3b-bun/server/007 0
announce start wire/m3b-bun/server/008
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 8 --report "$m3_reports/server-bun-008.json" -- bun "$tmp/bend_tls_server.js"
announce end wire/m3b-bun/server/008 0
announce start wire/m3b-bun/server/009
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 9 --report "$m3_reports/server-bun-009.json" -- bun "$tmp/bend_tls_server.js"
announce end wire/m3b-bun/server/009 0
announce start wire/m3b-bun/server/010
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 10 --report "$m3_reports/server-bun-010.json" -- bun "$tmp/bend_tls_server.js"
announce end wire/m3b-bun/server/010 0
announce start wire/m3b-bun/server/011
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 11 --report "$m3_reports/server-bun-011.json" -- bun "$tmp/bend_tls_server.js"
announce end wire/m3b-bun/server/011 0
announce start wire/m3b-bun/server/012
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 12 --report "$m3_reports/server-bun-012.json" -- bun "$tmp/bend_tls_server.js"
announce end wire/m3b-bun/server/012 0
announce start wire/m3b-bun/server/013
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 13 --report "$m3_reports/server-bun-013.json" -- bun "$tmp/bend_tls_server.js"
announce end wire/m3b-bun/server/013 0
announce start wire/m3b-bun/server/014
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 14 --report "$m3_reports/server-bun-014.json" -- bun "$tmp/bend_tls_server.js"
announce end wire/m3b-bun/server/014 0
announce start wire/m3b-bun/server/015
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 15 --report "$m3_reports/server-bun-015.json" -- bun "$tmp/bend_tls_server.js"
announce end wire/m3b-bun/server/015 0
announce start wire/m3b-bun/server/016
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 16 --report "$m3_reports/server-bun-016.json" -- bun "$tmp/bend_tls_server.js"
announce end wire/m3b-bun/server/016 0
announce start wire/m3b-bun/server/017
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 17 --report "$m3_reports/server-bun-017.json" -- bun "$tmp/bend_tls_server.js"
announce end wire/m3b-bun/server/017 0
announce start wire/m3b-bun/server/018
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 18 --report "$m3_reports/server-bun-018.json" -- bun "$tmp/bend_tls_server.js"
announce end wire/m3b-bun/server/018 0
announce start wire/m3b-bun/server/019
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 19 --report "$m3_reports/server-bun-019.json" -- bun "$tmp/bend_tls_server.js"
announce end wire/m3b-bun/server/019 0
announce start wire/m3b-bun/server/020
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 20 --report "$m3_reports/server-bun-020.json" -- bun "$tmp/bend_tls_server.js"
announce end wire/m3b-bun/server/020 0
announce start wire/m3b-bun/server/021
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 21 --report "$m3_reports/server-bun-021.json" -- bun "$tmp/bend_tls_server.js"
announce end wire/m3b-bun/server/021 0
announce start wire/m3b-bun/server/022
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 22 --report "$m3_reports/server-bun-022.json" -- bun "$tmp/bend_tls_server.js"
announce end wire/m3b-bun/server/022 0
announce start wire/m3b-bun/server/023
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 23 --report "$m3_reports/server-bun-023.json" -- bun "$tmp/bend_tls_server.js"
announce end wire/m3b-bun/server/023 0
announce start wire/m3b-bun/server/024
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 24 --report "$m3_reports/server-bun-024.json" -- bun "$tmp/bend_tls_server.js"
announce end wire/m3b-bun/server/024 0
announce start wire/m3b-bun/server/025
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 25 --report "$m3_reports/server-bun-025.json" -- bun "$tmp/bend_tls_server.js"
announce end wire/m3b-bun/server/025 0
announce start wire/m3b-bun/server/026
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 26 --report "$m3_reports/server-bun-026.json" -- bun "$tmp/bend_tls_server.js"
announce end wire/m3b-bun/server/026 0
announce start wire/m3b-bun/server/027
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 27 --report "$m3_reports/server-bun-027.json" -- bun "$tmp/bend_tls_server.js"
announce end wire/m3b-bun/server/027 0
announce start wire/m3b-bun/server/028
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 28 --report "$m3_reports/server-bun-028.json" -- bun "$tmp/bend_tls_server.js"
announce end wire/m3b-bun/server/028 0
announce start wire/m3b-bun/server/029
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 29 --report "$m3_reports/server-bun-029.json" -- bun "$tmp/bend_tls_server.js"
announce end wire/m3b-bun/server/029 0
announce start wire/m3b-bun/server/030
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 30 --report "$m3_reports/server-bun-030.json" -- bun "$tmp/bend_tls_server.js"
announce end wire/m3b-bun/server/030 0
announce start wire/m3b-bun/server/031
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 31 --report "$m3_reports/server-bun-031.json" -- bun "$tmp/bend_tls_server.js"
announce end wire/m3b-bun/server/031 0
announce start wire/m3b-bun/server/032
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 32 --report "$m3_reports/server-bun-032.json" -- bun "$tmp/bend_tls_server.js"
announce end wire/m3b-bun/server/032 0
announce start wire/m3b-bun/server/033
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 33 --report "$m3_reports/server-bun-033.json" -- bun "$tmp/bend_tls_server.js"
announce end wire/m3b-bun/server/033 0
announce start wire/m3b-bun/server/034
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 34 --report "$m3_reports/server-bun-034.json" -- bun "$tmp/bend_tls_server.js"
announce end wire/m3b-bun/server/034 0
announce start wire/m3b-bun/server/035
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 35 --report "$m3_reports/server-bun-035.json" -- bun "$tmp/bend_tls_server.js"
announce end wire/m3b-bun/server/035 0
announce start wire/m3b-bun/server/036
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 36 --report "$m3_reports/server-bun-036.json" -- bun "$tmp/bend_tls_server.js"
announce end wire/m3b-bun/server/036 0
announce start wire/m3b-bun/server/037
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 37 --report "$m3_reports/server-bun-037.json" -- bun "$tmp/bend_tls_server.js"
announce end wire/m3b-bun/server/037 0
announce start wire/m3b-bun/peers/000
python3 bend_tls_peer_check.py --expected-batches 12 --batch-index 0 --server "$tmp/bend_tls_server.js" --client "$tmp/bend_tls_client.js" --runtime bun --go-peer "$tmp/tls_go_peer" --report "$m3_reports/peers-bun-000.json"
announce end wire/m3b-bun/peers/000 0
announce start wire/m3b-bun/peers/001
python3 bend_tls_peer_check.py --expected-batches 12 --batch-index 1 --server "$tmp/bend_tls_server.js" --client "$tmp/bend_tls_client.js" --runtime bun --go-peer "$tmp/tls_go_peer" --report "$m3_reports/peers-bun-001.json"
announce end wire/m3b-bun/peers/001 0
announce start wire/m3b-bun/peers/002
python3 bend_tls_peer_check.py --expected-batches 12 --batch-index 2 --server "$tmp/bend_tls_server.js" --client "$tmp/bend_tls_client.js" --runtime bun --go-peer "$tmp/tls_go_peer" --report "$m3_reports/peers-bun-002.json"
announce end wire/m3b-bun/peers/002 0
announce start wire/m3b-bun/peers/003
python3 bend_tls_peer_check.py --expected-batches 12 --batch-index 3 --server "$tmp/bend_tls_server.js" --client "$tmp/bend_tls_client.js" --runtime bun --go-peer "$tmp/tls_go_peer" --report "$m3_reports/peers-bun-003.json"
announce end wire/m3b-bun/peers/003 0
announce start wire/m3b-bun/peers/004
python3 bend_tls_peer_check.py --expected-batches 12 --batch-index 4 --server "$tmp/bend_tls_server.js" --client "$tmp/bend_tls_client.js" --runtime bun --go-peer "$tmp/tls_go_peer" --report "$m3_reports/peers-bun-004.json"
announce end wire/m3b-bun/peers/004 0
announce start wire/m3b-bun/peers/005
python3 bend_tls_peer_check.py --expected-batches 12 --batch-index 5 --server "$tmp/bend_tls_server.js" --client "$tmp/bend_tls_client.js" --runtime bun --go-peer "$tmp/tls_go_peer" --report "$m3_reports/peers-bun-005.json"
announce end wire/m3b-bun/peers/005 0
announce start wire/m3b-bun/peers/006
python3 bend_tls_peer_check.py --expected-batches 12 --batch-index 6 --server "$tmp/bend_tls_server.js" --client "$tmp/bend_tls_client.js" --runtime bun --go-peer "$tmp/tls_go_peer" --report "$m3_reports/peers-bun-006.json"
announce end wire/m3b-bun/peers/006 0
announce start wire/m3b-bun/peers/007
python3 bend_tls_peer_check.py --expected-batches 12 --batch-index 7 --server "$tmp/bend_tls_server.js" --client "$tmp/bend_tls_client.js" --runtime bun --go-peer "$tmp/tls_go_peer" --report "$m3_reports/peers-bun-007.json"
announce end wire/m3b-bun/peers/007 0
announce start wire/m3b-bun/peers/008
python3 bend_tls_peer_check.py --expected-batches 12 --batch-index 8 --server "$tmp/bend_tls_server.js" --client "$tmp/bend_tls_client.js" --runtime bun --go-peer "$tmp/tls_go_peer" --report "$m3_reports/peers-bun-008.json"
announce end wire/m3b-bun/peers/008 0
announce start wire/m3b-bun/peers/009
python3 bend_tls_peer_check.py --expected-batches 12 --batch-index 9 --server "$tmp/bend_tls_server.js" --client "$tmp/bend_tls_client.js" --runtime bun --go-peer "$tmp/tls_go_peer" --report "$m3_reports/peers-bun-009.json"
announce end wire/m3b-bun/peers/009 0
announce start wire/m3b-bun/peers/010
python3 bend_tls_peer_check.py --expected-batches 12 --batch-index 10 --server "$tmp/bend_tls_server.js" --client "$tmp/bend_tls_client.js" --runtime bun --go-peer "$tmp/tls_go_peer" --report "$m3_reports/peers-bun-010.json"
announce end wire/m3b-bun/peers/010 0
announce start wire/m3b-bun/peers/011
python3 bend_tls_peer_check.py --expected-batches 12 --batch-index 11 --server "$tmp/bend_tls_server.js" --client "$tmp/bend_tls_client.js" --runtime bun --go-peer "$tmp/tls_go_peer" --report "$m3_reports/peers-bun-011.json"
announce end wire/m3b-bun/peers/011 0
announce start wire/m3b-native/server/038
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 38 --report "$m3_reports/server-native-038.json" -- "$tmp/bend_tls_server"
announce end wire/m3b-native/server/038 0
announce start wire/m3b-bun/server/038
python3 bend_tls_server_check.py --expected-batches 39 --batch-index 38 --report "$m3_reports/server-bun-038.json" -- bun "$tmp/bend_tls_server.js"
announce end wire/m3b-bun/server/038 0
