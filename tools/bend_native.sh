#!/bin/sh
# CPU fixtures: release the Bend frontend before running clang on emitted C.
# Given C the frontend already wrote, only clang runs.
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: bend_native.sh <source.bend | emitted.c> <new-native-output>" >&2
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
case $source_file in
  *.c)
    cp "$source_file" "$generated_c"
    ;;
  *)
    echo "Bend CPU frontend: $source_file" >&2
    bend "$source_file" -o "$generated_c"
    ;;
esac

# The current crypto fixtures are CPU-only. Fail explicitly on a GPU program
# so this helper never silently builds a different backend.
if ! rg -q '^#define BANGS[[:space:]]+0$' "$generated_c"; then
  echo "bend_native.sh requires a CPU fixture (BANGS=0)" >&2
  exit 2
fi

compiler=${CC:-clang}
# Apple Clang 21's Darwin stack probe clobbers live preserve_none registers
# in Bend 2.0.38's segments, and can crash the backend outright.
stack_check=
if [ "$(uname -s)" = Darwin ] && [ "$(uname -m)" = arm64 ]; then
  case "$("$compiler" --version | head -1)" in
    *"Apple clang version 21."*) stack_check=-fno-stack-check ;;
  esac
fi
# Large CPU programs overwhelm a single Clang translation unit. Keep emitted
# bodies intact and compile bounded units after the frontend has exited.
if [ "$(wc -c < "$generated_c")" -ge 4194304 ] && ! rg -q '^#import ' "$generated_c"; then
  helper_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
  set -- --compiler "$compiler" --cflag=-std=c11 --cflag=-O3 \
    --link-flag=-lpthread --link-flag=-lm --output "$native_output"
  if [ -n "$stack_check" ]; then set -- "$@" --cflag=$stack_check; fi
  case "$(uname -s)" in
    Darwin) ;;
    Linux)
      if rg -q '#include <X11/' "$generated_c"; then set -- "$@" --link-flag=-lX11; fi
      if rg -q '#include <alsa/' "$generated_c"; then set -- "$@" --link-flag=-lasound; fi
      ;;
    *) echo "bend_native.sh supports macOS and Linux CPU fixtures" >&2; exit 2 ;;
  esac
  python3 "$helper_dir/bend_native_parts.py" "$generated_c" "$native_tmp/parts" "$@"
  exit
fi
# Match Bend 2.0.27's CPU compile flags and platform libraries.
set -- -std=c11 -O3 $stack_check "$generated_c" -lpthread -lm
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
