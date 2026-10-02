"""Route fixture operation codes to precompiled Bend evaluators; no ASN.1 logic."""

import argparse
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--bun', action='store_true')
    for name in ('key', 'signature', 'binding', 'der'):
        parser.add_argument('--'+name, required=True)
    parser.add_argument('args', nargs=argparse.REMAINDER)
    options = parser.parse_args()
    arguments = options.args[1:] if options.args[:1] == ['--'] else options.args
    targets = {'0': options.key, '1': options.signature, '2': options.binding, '3': options.der}
    groups = {}
    count = 0
    while arguments:
        op, arguments = arguments[0], arguments[1:]
        if op not in targets:
            parser.error('unknown operation')
        width = 2 if op == '2' else 1
        if len(arguments) < width:
            parser.error('missing fixture input')
        values, arguments = arguments[:width], arguments[width:]
        groups.setdefault(op, []).append((count, values))
        count += 1
    outputs = [None]*count
    for op, jobs in groups.items():
        values = [value for _, inputs in jobs for value in inputs]
        command = (['bun', targets[op]] if options.bun else [targets[op]]) + values
        result = subprocess.run(command, capture_output=True, text=True, timeout=90)
        if result.returncode:
            sys.stderr.write(result.stderr)
            raise SystemExit(result.returncode)
        lines = result.stdout.splitlines()
        if len(lines) != len(jobs):
            raise SystemExit('evaluator output count mismatch')
        for (index, _), output in zip(jobs, lines):
            outputs[index] = output
    sys.stdout.write('\n'.join(outputs)+'\n' if outputs else '')


if __name__ == '__main__':
    main()
