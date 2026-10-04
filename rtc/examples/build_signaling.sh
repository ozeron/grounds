#!/bin/sh
# Build this native evaluator from Bend-generated C. Apple Clang 21's Darwin
# stack probe clobbers live preserve_none registers in WL_FID_ENTER. Keep this
# explicit workaround local to the fixture; other checks retain Bend defaults.
set -eu
[ "$#" -eq 1 ] || { echo "usage: build_signaling.sh <native-output>" >&2; exit 2; }
out=$1
src=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
compiler=${CC:-cc}
phase=
announce() { python3 "$src/../../tools/check_phase.py" "$@" >&2; }
begin() { phase="rtc/native/$1/signaling_server"; announce start "$phase"; }
end() { announce end "$phase" 0; phase=; }
cleanup() {
  result=$?
  trap - EXIT
  set +e
  if [ -n "$phase" ]; then announce end "$phase" "$result"; fi
  exit "$result"
}
trap cleanup EXIT
for target in "$out" "$out.c" "$out.parts"; do
  if [ -e "$target" ] || [ -L "$target" ]; then
    echo "signaling build output already exists: $target" >&2
    exit 2
  fi
done
begin emit
bend "$src/signaling_server.bend" -o "$out.c"
end
begin build
set -- --compiler "$compiler" --cflag=-std=c11 --cflag=-O3 \
  --link-flag=-lpthread --link-flag=-lm --output "$out"
if [ "$(uname -s)" = Darwin ] && [ "$(uname -m)" = arm64 ]; then
  case "$("$compiler" --version | head -1)" in
    *"Apple clang version 21."*)
      echo "Native signaling fixture: Apple Clang 21 arm64 workaround uses -O3 -fno-stack-check" >&2
      set -- "$@" --cflag=-fno-stack-check
      ;;
  esac
fi
python3 "$src/../../tools/bend_native_parts.py" "$out.c" "$out.parts" "$@"
end
