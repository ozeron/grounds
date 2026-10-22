#!/usr/bin/env python3
"""Account for a short package's complete existing check as one guard phase."""
import subprocess
import sys

from check_phase import announce


def main():
    if len(sys.argv) < 4 or sys.argv[2] != '--':
        raise SystemExit('Usage: check_package.py PHASE -- COMMAND [ARGS...]')
    phase = sys.argv[1]
    announce(['start', phase])
    try:
        result = subprocess.run(sys.argv[3:]).returncode
        result = result if result >= 0 else 128 - result
    except OSError as error:
        print(error, file=sys.stderr)
        result = 127
    announce(['end', phase, str(result)])
    return result


if __name__ == '__main__':
    sys.exit(main())
