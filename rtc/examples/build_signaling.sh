#!/bin/sh
# Build this native evaluator from Bend-generated C. Apple Clang 21's Darwin
# stack probe clobbers live preserve_none registers in WL_FID_ENTER. Keep this
# explicit workaround local to the fixture; other checks retain Bend defaults.
set -eu
[ "$#" -eq 1 ] || { echo "usage: build_signaling.sh <native-output>" >&2; exit 2; }
out=$1
src=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
compiler=${CC:-cc}
bend "$src/signaling_server.bend" -o "$out.c"
set -- -std=c11 -O3 "$out.c" -lpthread -lm -o "$out"
if [ "$(uname -s)" = Darwin ] && [ "$(uname -m)" = arm64 ]; then
  case "$("$compiler" --version | head -1)" in
    *"Apple clang version 21."*)
      echo "Native signaling fixture: Apple Clang 21 arm64 workaround uses -O3 -fno-stack-check" >&2
      set -- "$@" -fno-stack-check
      ;;
  esac
fi
"$compiler" "$@"
