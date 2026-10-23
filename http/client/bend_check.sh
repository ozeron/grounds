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
