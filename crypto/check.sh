#!/bin/sh
set -eu
cd "$(dirname "$0")"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
bend test.bend
bend PROOF.bend
bend cli.bend -o "$tmp/sha256" > /dev/null
bend hkdf_cli.bend -o "$tmp/hkdf" > /dev/null
python3 check.py "$tmp/sha256" "$tmp/hkdf"
