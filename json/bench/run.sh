#!/bin/sh
# benchmarks bjson against other JSON tools on the nativejson-benchmark corpus
# each run: read the file, parse, print compact JSON to /dev/null; startup included
set -eu
cd "$(dirname "$0")/.."
mkdir -p bench/data bench/results
for f in canada citm_catalog twitter; do
  [ -f bench/data/$f.json ] || curl -fsSL -o bench/data/$f.json \
    https://raw.githubusercontent.com/miloyip/nativejson-benchmark/master/data/$f.json
done
echo '{}' > bench/data/empty.json
scripts/build.sh
(cd bench/gort && go build -o ../gort-bin .)
# QUICK=1 (CI) times only bjson and Go, which is all the gate needs
for f in empty canada citm_catalog twitter; do
  if [ "${QUICK:-}" = 1 ]; then
    hyperfine -N --warmup 2 --min-runs 10 --export-json bench/results/$f.json \
      -n bjson "./bjson --compact bench/data/$f.json" \
      -n go "bench/gort-bin bench/data/$f.json" >/dev/null
  else
    hyperfine -N --warmup 2 --min-runs 10 --export-json bench/results/$f.json \
      -n bjson "./bjson --compact bench/data/$f.json" \
      -n python "python3 bench/rt.py bench/data/$f.json" \
      -n node "node bench/rt.js bench/data/$f.json" \
      -n bun "bun bench/rt.js bench/data/$f.json" \
      -n jq "jq -c . bench/data/$f.json" \
      -n go "bench/gort-bin bench/data/$f.json" >/dev/null
  fi
done
[ "${QUICK:-}" = 1 ] || python3 bench/report.py
python3 bench/gate.py bjson
