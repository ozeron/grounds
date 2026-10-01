"""Run one complete traffic-owner scenario in its Bend direction fixture."""

import argparse
import os


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", required=True)
    parser.add_argument("--read", required=True)
    parser.add_argument("--bun", action="store_true")
    parser.add_argument("args", nargs=argparse.REMAINDER)
    options = parser.parse_args()
    args = options.args[1:] if options.args[:1] == ["--"] else options.args
    if not args or args[0] not in {"write", "write-aes", "read", "read-aes", "label"}:
        parser.error("expected a traffic owner or label evaluator mode")
    target = options.write if args[0] in {"write", "write-aes"} else options.read
    command = (["bun", target] if options.bun else [target]) + args
    # Replace only this test driver. The Bend fixture retains its affine owner
    # and executes the entire scenario; no crypto or lifecycle runs in Python.
    os.execvp(command[0], command)


if __name__ == "__main__":
    main()
