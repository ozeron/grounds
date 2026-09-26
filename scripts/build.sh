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
profdata() {
  xcrun llvm-profdata "$@" 2>/dev/null && return
  for t in llvm-profdata $(ls /usr/bin/llvm-profdata-* 2>/dev/null); do
    command -v "$t" >/dev/null && "$t" "$@" && return
  done
  return 1
}
pgo() {
  clang -std=c11 -O3 -fprofile-instr-generate "$tmp/bjson.c" -lpthread -lm -o "$tmp/bjson-gen" || return 1
  for f in bench/data/*.json; do
    LLVM_PROFILE_FILE="$tmp/%p.profraw" "$tmp/bjson-gen" --compact "$f" >/dev/null 2>&1 || true
  done
  profdata merge -o "$tmp/bjson.profdata" "$tmp"/*.profraw || return 1
  clang -std=c11 -O3 -fprofile-instr-use="$tmp/bjson.profdata" -Wno-profile-instr-out-of-date \
    "$tmp/bjson.c" -lpthread -lm -o bjson
}
# without clang's profile tools (some Linux images), a plain build
pgo || { echo "build.sh: no PGO, plain build" >&2; bend main.bend -o bjson >/dev/null; }
