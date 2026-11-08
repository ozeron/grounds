#!/bin/sh
# New M4b acceptance is native only. The existing check.sh is unchanged.
set -eu
cd "$(dirname "$0")"
tmp=$(mktemp -d)
artifacts=${GROUNDS_M4B_CLIENT_ARTIFACTS:-$tmp/artifacts}
mkdir -p "$artifacts/probes"
phase=
announce() { python3 ../../tools/check_phase.py "$@"; }
begin() { phase="http_client/$1"; announce start "$phase"; }
end() { announce end "$phase" 0; phase=; }
cleanup() {
  result=$?
  trap - EXIT
  if [ -n "$phase" ]; then announce end "$phase" "$result"; fi
  rm -rf "$tmp"
  exit "$result"
}
trap cleanup EXIT
native() {
  BUN_OPTIONS="${BUN_OPTIONS:-} --smol" BUN_JSC_forceRAMSize=134217728 sh ../../tools/bend_native.sh "$@"
}
export BUN_OPTIONS="${BUN_OPTIONS:-} --smol"
export BUN_JSC_forceRAMSize=134217728
begin bend_legacy_graphs
python3 tests/legacy_graph_audit.py --artifacts "$artifacts/legacy-graphs"
end
begin bend_fixtures
python3 tests/bend_tls_check.py --mode prepare --fixtures "$artifacts/fixtures" --report "$artifacts/fixtures.json"
end
begin bend_frontend_native
python3 ../server/examples/bend_tls_build.py --program client "$artifacts/client.c" "$artifacts/client-build.json"
end
begin bend_compile_native
native "$artifacts/client.c" "$artifacts/client"
end
begin bend_server_frontend
python3 ../server/examples/bend_tls_build.py --program http "$artifacts/server.c" "$artifacts/server-build.json"
end
begin bend_server_compile
native "$artifacts/server.c" "$artifacts/server"
end
begin bend_go_peer
mise exec go@1.26.9 -- go build -o "$artifacts/go-peer" ../server/examples/bend_m4b_peer.go
end
begin bend_abort_controls
for probe in legacy-probe cookie-probe; do
  python3 ../../wire/bend_tls_no_delegation_build.py --program "$probe" --output "$artifacts/probes/$probe.c" --report "$artifacts/probes/$probe.json"
  native "$artifacts/probes/$probe.c" "$artifacts/probes/$probe"
done
end
begin bend_no_delegation
python3 ../server/examples/bend_native_audit.py --role client --native "$artifacts/client" --c "$artifacts/client.c" --probe-dir "$artifacts/probes" --report "$artifacts/client-audit.json"
python3 ../server/examples/bend_native_audit.py --role server --native "$artifacts/server" --c "$artifacts/server.c" --probe-dir "$artifacts/probes" --report "$artifacts/server-audit.json"
end
for mode in ordinary negative bend openssl go; do
  begin "bend_live_$mode"
  python3 tests/bend_tls_check.py --mode "$mode" --binary "$artifacts/client" --fixtures "$artifacts/fixtures" --server "$artifacts/server" --go "$artifacts/go-peer" --report "$artifacts/$mode.json"
  end
done
# M6: framing, redirects, keep-alive reuse, deadlines, streamed bodies and
# IPv6 (literals, IP SANs, dual-stack fallback, the DNS deadline), against
# independent Python TLS peers (native only).
for mode in framing redirects pool deadlines stream ipv6; do
  begin "bend_live_$mode"
  python3 tests/bend_m6_check.py --mode "$mode" --binary "$artifacts/client" --fixtures "$artifacts/fixtures" --report "$artifacts/m6-$mode.json"
  end
done

# M5 is native only. All fixture verification stays offline; the internet
# diagnostic is merely checked for its default explicit opt-out below.
begin bend_bundle_build
native tests/bundle.bend "$artifacts/bundle-policy"
end
begin bend_bundle_check
python3 ../../crypto/pem_bundle_check.py --policy "$artifacts/bundle-policy"
end
# M6: opt-in system bundle admission (duplicates dropped, TRUSTED blocks'
# trust settings honoured), reads to end of file (FIFOs) and path
# resolution (SSL_CERT_FILE, fixed candidates).
begin bend_system_bundle_check
python3 tests/system_bundle_check.py "$artifacts/bundle-policy"
end
begin bend_public_chain_build
# Compiler-only baseline JIT avoids the optimizing frontend memory spike.
BUN_JSC_useDFGJIT=false BUN_JSC_useFTLJIT=false native tests/public_chain.bend "$artifacts/public-chain"
end
# M6: the pinned github.com chain against system bundles whose TRUSTED
# blocks withdraw its roots, compared with OpenSSL 3 on the same files.
begin bend_system_bundle_chain
python3 tests/system_bundle_check.py --chain "$artifacts/public-chain"
end
begin bend_public_chain_0
python3 ../../crypto/public_chain_check.py --batch-index 0 "$artifacts/public-chain"
end
begin bend_public_chain_1
python3 ../../crypto/public_chain_check.py --batch-index 1 "$artifacts/public-chain"
end
begin bend_public_chain_2
python3 ../../crypto/public_chain_check.py --batch-index 2 "$artifacts/public-chain"
end
begin bend_public_chain_3
python3 ../../crypto/public_chain_check.py --batch-index 3 "$artifacts/public-chain"
end
begin bend_public_chain_4
python3 ../../crypto/public_chain_check.py --batch-index 4 "$artifacts/public-chain"
end
begin bend_public_chain_5
python3 ../../crypto/public_chain_check.py --batch-index 5 "$artifacts/public-chain"
end
begin bend_public_chain_6
python3 ../../crypto/public_chain_check.py --batch-index 6 "$artifacts/public-chain"
end
begin bend_public_chain_7
python3 ../../crypto/public_chain_check.py --batch-index 7 "$artifacts/public-chain"
end
begin bend_public_chain_8
python3 ../../crypto/public_chain_check.py --batch-index 8 "$artifacts/public-chain"
end
begin bend_public_chain_9
python3 ../../crypto/public_chain_check.py --batch-index 9 "$artifacts/public-chain"
end
begin bend_public_chain_10
python3 ../../crypto/public_chain_check.py --batch-index 10 "$artifacts/public-chain"
end
begin bend_public_chain_11
python3 ../../crypto/public_chain_check.py --batch-index 11 "$artifacts/public-chain"
end
begin bend_public_chain_12
python3 ../../crypto/public_chain_check.py --batch-index 12 "$artifacts/public-chain"
end
# M6: EV/OV subject Names (jurisdiction, businessCategory, street, postalCode).
begin bend_public_chain_13
python3 ../../crypto/public_chain_check.py --batch-index 13 "$artifacts/public-chain"
end
begin bend_public_chain_14
python3 ../../crypto/public_chain_check.py --batch-index 14 "$artifacts/public-chain"
end
begin bend_public_chain_15
python3 ../../crypto/public_chain_check.py --batch-index 15 "$artifacts/public-chain"
end
begin bend_public_chain_16
python3 ../../crypto/public_chain_check.py --batch-index 16 "$artifacts/public-chain"
end
begin bend_public_chain_17
python3 ../../crypto/public_chain_check.py --batch-index 17 "$artifacts/public-chain"
end
begin bend_public_chain_18
python3 ../../crypto/public_chain_check.py --batch-index 18 "$artifacts/public-chain"
end
begin bend_public_chain_19
python3 ../../crypto/public_chain_check.py --batch-index 19 "$artifacts/public-chain"
end
begin bend_public_frontend
BUN_JSC_useDFGJIT=false BUN_JSC_useFTLJIT=false python3 public_https_build.py --trace "$artifacts/public.c" "$artifacts/public-build.json"
end
begin bend_public_compile
native "$artifacts/public.c" "$artifacts/public-http"
end
begin bend_public_no_delegation
python3 ../server/examples/bend_native_audit.py --role client --native "$artifacts/public-http" --c "$artifacts/public.c" --probe-dir "$artifacts/probes" --report "$artifacts/public-audit.json"
end
begin bend_public_live_opt_out
# Even when the caller opts into the diagnostic separately, gates stay offline.
GROUNDS_PUBLIC_HTTPS_LIVE=0 python3 public_https_live.py --report "$artifacts/public-live-skipped.json"
end
