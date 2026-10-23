#!/bin/sh
set -eu
cd "$(dirname "$0")"
python3 ../../tools/check_package.py http_client/check -- ./check.sh
sh ./bend_check.sh
