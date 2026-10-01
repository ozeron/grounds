#!/bin/sh
# CPU fixtures: release the Bend frontend before running clang on emitted C.
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: bend_native.sh <source.bend> <new-native-output>" >&2
  exit 2
fi

source_file=$1
native_output=$2
if [ -e "$native_output" ] || [ -L "$native_output" ]; then
  echo "native output already exists: $native_output" >&2
  exit 2
fi

native_tmp=$(mktemp -d "$(dirname "$native_output")/.grounds-native.XXXXXX")
trap 'rm -rf "$native_tmp"' EXIT HUP INT TERM
generated_c="$native_tmp/program.c"
echo "Bend CPU frontend: $source_file" >&2
bend "$source_file" -o "$generated_c"

# The current crypto fixtures are CPU-only. Fail explicitly on a GPU program
# so this helper never silently builds a different backend.
if ! rg -q '^#define BANGS[[:space:]]+0$' "$generated_c"; then
  echo "bend_native.sh requires a CPU fixture (BANGS=0)" >&2
  exit 2
fi

compiler=${CC:-clang}
# Match Bend 2.0.27's CPU compile flags and platform libraries.
set -- -std=c11 -O3 "$generated_c" -lpthread -lm
case "$(uname -s)" in
  Darwin)
    if rg -q '^#import ' "$generated_c"; then
      set -- -x objective-c -fobjc-arc -fmodules "$@"
    fi
    ;;
  Linux)
    if rg -q '#include <X11/' "$generated_c"; then
      set -- "$@" -lX11
    fi
    if rg -q '#include <alsa/' "$generated_c"; then
      set -- "$@" -lasound
    fi
    ;;
  *)
    echo "bend_native.sh supports macOS and Linux CPU fixtures" >&2
    exit 2
    ;;
esac
echo "Native CPU compiler: $source_file" >&2
"$compiler" "$@" -o "$native_tmp/program"
# Atomic creation on the same filesystem prevents replacing an output that
# appeared during compilation, including a symlink or directory.
python3 -c 'import os,sys; os.link(sys.argv[1],sys.argv[2])' \
  "$native_tmp/program" "$native_output"
