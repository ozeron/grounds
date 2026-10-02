"""Route batched ECDSA checks to complete Bend evaluators; no crypto here."""

import argparse
import subprocess
import sys


# The checker can retain mixed batches. Each contiguous target group runs
# sequentially, and each signature/DER/rejection operation stays inside Bend.
OPERATIONS = {
    "sign": ("scheme", 2, "sign"),
    "verify": ("scheme", 3, "verify"),
    "sign-raw": ("sign", 2, None),
    "verify-raw": ("verify", 3, None),
    "known-nonce": ("reject", 3, "0"),
    "zero-r": ("reject", 3, "1"),
    "reject": ("reject", 2, "2"),
    "candidate-none": ("reject", 2, "3"),
    "signature-none": ("reject", 2, "4"),
    "candidate-range": ("reject", 2, "5"),
    "encode": ("der", 1, "encode"),
    "decode": ("der", 1, "decode"),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("scheme", "sign", "verify", "reject", "der"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--bun", action="store_true")
    parser.add_argument("args", nargs=argparse.REMAINDER)
    options = parser.parse_args()
    remaining = options.args[1:] if options.args[:1] == ["--"] else options.args
    groups = []
    while remaining:
        operation, *remaining = remaining
        if operation not in OPERATIONS:
            parser.error("unknown ECDSA evaluator operation: " + operation)
        target, arity, mode = OPERATIONS[operation]
        if len(remaining) < arity:
            parser.error("missing files for ECDSA operation: " + operation)
        inputs, remaining = remaining[:arity], remaining[arity:]
        arguments = ([mode] if mode else []) + inputs
        if groups and groups[-1][0] == target:
            groups[-1][1].extend(arguments)
        else:
            groups.append((target, arguments))
    for target, arguments in groups:
        path = getattr(options, target)
        command = (["bun", path] if options.bun else [path]) + arguments
        result = subprocess.run(command, timeout=180)
        if result.returncode:
            sys.exit(result.returncode)


if __name__ == "__main__":
    main()
