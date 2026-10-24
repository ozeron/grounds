"""P-384 prime/order arithmetic against independent Python bigint results."""

from pathlib import Path
import random
import subprocess
import sys
import tempfile
import time

P = 2**384 - 2**128 - 2**96 + 2**32 - 1
N = int('ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973', 16)


def main():
    command = sys.argv[1:]
    rng = random.Random(0x256)
    total = 0
    started = time.monotonic()
    with tempfile.TemporaryDirectory() as folder:
        serial = 0
        def put(value, width=48):
            nonlocal serial
            serial += 1
            path = Path(folder)/str(serial)
            path.write_bytes(value.to_bytes(width, 'little'))
            return str(path)

        def batch(args, expected):
            nonlocal total
            result = subprocess.run(command + args, capture_output=True, text=True, timeout=115)
            actual = result.stdout.splitlines()
            assert result.returncode == 0, (result.returncode, result.stderr)
            assert len(actual) == len(expected), (len(actual), len(expected), result.stderr)
            for index, (a, e) in enumerate(zip(actual, expected)):
                assert a == e, (index, a, e)
            total += len(expected)

        for mode, modulus in [('p', P), ('n', N)]:
            edges = [0, 1, 2, modulus-2, modulus-1, modulus, modulus+1, 2**384-1]
            pairs = [(a,b) for a in edges for b in edges]
            # Every binary carry/borrow boundary, including the high sign bit.
            pairs += [(2**i, 2**i-1) for i in range(384)]
            pairs += [(2**i-1, 1) for i in range(1,385)]
            pairs += [(rng.getrandbits(384), rng.getrandbits(384)) for _ in range(64)]
            for start in range(0, len(pairs), 64):
                args, expected = [], []
                for a,b in pairs[start:start+64]:
                    ap,bp = put(a),put(b)
                    for op,value in [('add',a+b),('sub',a-b),('mul',a*b)]:
                        args += [mode,op,ap,bp]
                        expected += [(value % modulus).to_bytes(48,'little').hex()]
                batch(args,expected)
            # 768-bit reductions include every boundary and maximum high carries.
            wide = [0,1,modulus-1,modulus,modulus+1,2*modulus-1,2**384,2**768-1]
            wide += [2**i for i in range(0,768,8)]
            wide += [rng.getrandbits(768) for _ in range(16)]
            args,expected = [],[]
            for value in wide:
                args += [mode,'wide',put(value,96)]
                expected += [(value%modulus).to_bytes(48,'little').hex()]
            batch(args,expected)
            # Retained bit-reduction implementation cross-checks Montgomery too.
            args,expected = [],[]
            for a,b in pairs[:8] + pairs[-8:]:
                args += [mode,'ref',put(a),put(b)]
                expected += [(a*b%modulus).to_bytes(48,'little').hex()]
            batch(args,expected)
            args,expected = [],[]
            inverse_values = edges + [2**i for i in range(0,384,8)] + [rng.getrandbits(384) for _ in range(8)]
            for value in inverse_values:
                args += [mode,'inv',put(value)]
                reduced = value % modulus
                expected += ['invalid' if reduced == 0 else pow(reduced,-1,modulus).to_bytes(48,'little').hex()]
            batch(args,expected)
            args,expected = [],[]
            for value in edges:
                args += [mode,'check',put(value)]
                expected += [value.to_bytes(48,'little').hex() if value < modulus else 'invalid']
            for width in (0,47,49,96):
                invalid = Path(folder)/f'canonical-{mode}-{width}'
                invalid.write_bytes(bytes(width))
                args += [mode,'check',str(invalid)]
                expected += ['invalid']
            batch(args,expected)
            for bad_width in (0,47,49,95,97):
                bad = Path(folder)/f'bad-{bad_width}'
                bad.write_bytes(bytes(bad_width))
                args = [mode,'add',str(bad),put(1)]
                result = subprocess.run(command+args,capture_output=True,text=True,timeout=30)
                assert result.returncode == 2 and not result.stdout,(bad_width,result)
                total += 1
    print(f'P-384 arithmetic: {total} prime/order bigint, carry/borrow, wide-reduction, Montgomery/reference, inversion/canonical and malformed cases passed in {time.monotonic()-started:.3f}s')


if __name__ == '__main__':
    main()
