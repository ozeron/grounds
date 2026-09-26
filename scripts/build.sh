#!/bin/sh
# builds ./bjson with profile-guided optimization: an instrumented build
# runs --compact over the benchmark files, and clang rebuilds from that
# profile. Training pretty runs too made compact output slower.
# About 4% faster than `bend main.bend -o bjson`, which also works.
set -eu
cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
bend main.bend -o "$tmp/bjson.c" >/dev/null
clang -std=c11 -O3 -fprofile-instr-generate "$tmp/bjson.c" -lpthread -lm -o "$tmp/bjson-gen"
for f in bench/data/*.json; do
  LLVM_PROFILE_FILE="$tmp/%p.profraw" "$tmp/bjson-gen" --compact "$f" >/dev/null 2>&1 || true

done
xcrun llvm-profdata merge -o "$tmp/bjson.profdata" "$tmp"/*.profraw 2>/dev/null \
  || llvm-profdata merge -o "$tmp/bjson.profdata" "$tmp"/*.profraw
clang -std=c11 -O3 -fprofile-instr-use="$tmp/bjson.profdata" -Wno-profile-instr-out-of-date \
  "$tmp/bjson.c" -lpthread -lm -o bjson
