#!/bin/sh
# time and peak memory on a 100 MB file: the three bench files, repeated
set -eu
cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
python3 - "$tmp/big.json" <<'PY'
import sys
one = ",".join(open(f"bench/data/{n}.json").read() for n in ["canada", "citm_catalog", "twitter"])
n = 100_000_000 // (len(one.encode()) + 1) + 1
open(sys.argv[1], "w").write("[" + ",".join([one] * n) + "]")
PY
[ -x grounds-json ] || scripts/build.sh
[ -x spec-grounds-json ] || bend spec_cli.bend -o spec-grounds-json
[ -x bench/gort-bin ] || (cd bench/gort && go build -o ../gort-bin .)
run() {
  name=$1; shift
  /usr/bin/time -l "$@" "$tmp/big.json" 2> "$tmp/t" > /dev/null
  awk -v n="$name" '/ real/{r=$1} /maximum resident/{m=$1/1e6} END{printf "%-22s %6.2f s %7.0f MB\n", n, r, m}' "$tmp/t"
}
echo "$(wc -c < "$tmp/big.json" | tr -d ' ') bytes"
run "grounds-json --compact" ./grounds-json --compact
run "grounds-json (pretty)" ./grounds-json
run "spec-grounds-json --compact" ./spec-grounds-json --compact
run "go" bench/gort-bin
run "jq -c" jq -c .
