"""P-256 SEC1/ECDH vectors, independent affine arithmetic and OpenSSL peers."""
from pathlib import Path
import json
import random
import subprocess
import sys
import tempfile
import time

P = 2**256 - 2**224 + 2**192 + 2**96 - 1
N = int('ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551', 16)
B = int('5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b', 16)
G = (int('6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296', 16),
     int('4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5', 16))
PRIVATE_PREFIX = bytes.fromhex('30310201010420')
PRIVATE_SUFFIX = bytes.fromhex('a00a06082a8648ce3d030107')
PUBLIC_PREFIX = bytes.fromhex('3059301306072a8648ce3d020106082a8648ce3d030107034200')


def add(first, second):
    if first is None:
        return second
    if second is None:
        return first
    x1, y1 = first
    x2, y2 = second
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return None
        slope = (3*x1*x1-3)*pow(2*y1, -1, P) % P
    else:
        slope = (y2-y1)*pow(x2-x1, -1, P) % P
    x3 = (slope*slope-x1-x2) % P
    return x3, (slope*(x1-x3)-y1) % P


def mul(scalar, point):
    result = None
    while scalar:
        if scalar & 1:
            result = add(result, point)
        point = add(point, point)
        scalar >>= 1
    return result


def sec1(point):
    return b'\x00' if point is None else b'\x04'+point[0].to_bytes(32, 'big')+point[1].to_bytes(32, 'big')


def expected(point):
    return 'invalid' if point is None else sec1(point).hex()


def projective(point, scale):
    xyz = (0, scale, 0) if point is None else (point[0]*scale % P, point[1]*scale % P, scale)
    return b''.join(v.to_bytes(32, 'big') for v in xyz)


def openssl_public(private, path):
    path.write_bytes(PRIVATE_PREFIX+private+PRIVATE_SUFFIX)
    result = subprocess.run(['openssl', 'pkey', '-inform', 'DER', '-in', str(path),
        '-pubout', '-outform', 'DER'], capture_output=True, check=True).stdout
    assert result.startswith(PUBLIC_PREFIX) and len(result) == len(PUBLIC_PREFIX)+65
    return result[-65:]


def openssl_shared(private, peer, private_path, peer_path):
    private_path.write_bytes(PRIVATE_PREFIX+private+PRIVATE_SUFFIX)
    peer_path.write_bytes(PUBLIC_PREFIX+peer)
    return subprocess.run(['openssl', 'pkeyutl', '-derive', '-inkey', str(private_path),
        '-keyform', 'DER', '-peerkey', str(peer_path), '-peerform', 'DER'],
        capture_output=True, check=True).stdout


def main():
    binary = sys.argv[1:]
    rng = random.Random(0x256EC)
    start = time.monotonic()
    counts = {}
    cases = []

    def case(group, op, inputs, output):
        cases.append((group, op, inputs, output))
        counts[group] = counts.get(group, 0) + 1

    vectors = json.loads(Path(__file__).with_name('p256_vectors.json').read_text())['cases']
    assert len(vectors) == 25
    for v in vectors:
        private = bytes.fromhex(v['dIUT'])
        peer = bytes.fromhex('04'+v['QCAVSx']+v['QCAVSy'])
        public = bytes.fromhex('04'+v['QIUTx']+v['QIUTy'])
        assert sec1(mul(int(v['dIUT'], 16), G)) == public
        shared = mul(int(v['dIUT'], 16), (int(v['QCAVSx'], 16), int(v['QCAVSy'], 16)))
        assert shared[0].to_bytes(32, 'big').hex() == v['ZIUT']
        case('NIST', 'pub', [private], public.hex())
        case('NIST', 'shared', [private, peer], v['ZIUT'])

    # Infinity, inverses, doubling and ordinary addition, with unrelated
    # nonzero projective scales on both operands. The oracle uses affine
    # slopes/inversions, not the implementation's complete RCB formula.
    points = [None, G, (G[0], -G[1] % P)] + [mul(i, G) for i in range(2, 10)]
    for first in points:
        for second in points:
            output = expected(add(first, second))
            case('group', 'add', [sec1(first), sec1(second)], output)
            case('scaled-group', 'projective',
                 [projective(first, rng.randrange(1, P)), projective(second, rng.randrange(1, P))], output)

    # Scalar edges and every byte transition in both directions, with
    # alternating/dense patterns. Raw group tests also exercise 0 and >=n;
    # protocol private-scalar parsing rejects those values separately.
    scalars = sorted({0, 1, 2, 3, N-1, N, N+1, 2**255, 2**256-1,
        int('55'*32, 16), int('aa'*32, 16)} |
        {1 << i for i in range(0, 256, 8)} |
        {(1 << i)-1 for i in range(8, 257, 8)} |
        {rng.randrange(0, 2**256) for _ in range(8)})
    for scalar in scalars:
        case('scalar', 'mul', [scalar.to_bytes(32, 'little'), sec1(G)], expected(mul(scalar, G)))
    for scalar in [0, 1, N-1, 2**256-1]:
        case('infinity-mul', 'mul', [scalar.to_bytes(32, 'little'), b'\x00'], 'invalid')

    # Strict SEC1 range/curve/length/prefix checks. Infinity/compressed/hybrid
    # encodings and coordinate aliases must not enter protocol group logic.
    bad_points = [b'', b'\x00', sec1(G)[:-1], sec1(G)+b'\x00',
        b'\x02'+G[0].to_bytes(32, 'big'), b'\x03'+G[0].to_bytes(32, 'big')]
    bad_points += [bytes([prefix])+sec1(G)[1:] for prefix in [0, 1, 2, 3, 5, 6, 7, 255]]
    bad_points += [b'\x04'+x.to_bytes(32, 'big')+y.to_bytes(32, 'big')
        for x, y in [(P, G[1]), (P+1, G[1]), (G[0], P), (G[0], P+1),
                     (2**256-1, G[1]), (G[0], 2**256-1), (0, 0), (0, 1), (1, 0)]]
    for index in range(1, 65):
        damaged = bytearray(sec1(G))
        damaged[index] ^= 1
        x = int.from_bytes(damaged[1:33], 'big')
        y = int.from_bytes(damaged[33:], 'big')
        assert x >= P or y >= P or (y*y-x*x*x+3*x-B) % P != 0
        bad_points.append(bytes(damaged))
    valid_private = (1).to_bytes(32, 'big')
    for peer in bad_points:
        case('bad-peer', 'check', [peer], 'invalid')
        case('bad-peer', 'shared', [valid_private, peer], 'invalid')
    private_values = [b'', bytes(31), bytes(33), bytes(64), bytes(32)]
    private_values += [v.to_bytes(32, 'big') for v in [N, N+1, 2**256-1]]
    for private in private_values:
        case('bad-private', 'pub', [private], 'invalid')
        case('bad-private', 'shared', [private, sec1(G)], 'invalid')
    for point in points[1:]:
        case('canonical-peer', 'check', [sec1(point)], sec1(point).hex())

    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        private_path, peer_path = root/'private.der', root/'peer.der'
        for _ in range(8):
            a, b = rng.randrange(1, N), rng.randrange(1, N)
            private_a, private_b = a.to_bytes(32, 'big'), b.to_bytes(32, 'big')
            public_a = openssl_public(private_a, private_path)
            public_b = openssl_public(private_b, private_path)
            secret = openssl_shared(private_a, public_b, private_path, peer_path)
            assert public_a == sec1(mul(a, G)) and public_b == sec1(mul(b, G))
            assert secret == mul(a, (int.from_bytes(public_b[1:33], 'big'),
                int.from_bytes(public_b[33:], 'big')))[0].to_bytes(32, 'big')
            assert openssl_shared(private_b, public_a, private_path, peer_path) == secret
            case('OpenSSL', 'pub', [private_a], public_a.hex())
            case('OpenSSL', 'pub', [private_b], public_b.hex())
            case('OpenSSL', 'shared', [private_a, public_b], secret.hex())
            case('OpenSSL', 'shared', [private_b, public_a], secret.hex())

        # Small batches bound CLI arguments and report the exact failing case.
        for start_index in range(0, len(cases), 16):
            batch = cases[start_index:start_index+16]
            args = []
            for index, (_, op, inputs, _) in enumerate(batch):
                args.append(op)
                for operand, data in enumerate(inputs):
                    path = root/f'{index}-{operand}.bin'
                    path.write_bytes(data)
                    args.append(str(path))
            got = subprocess.run(binary+args, capture_output=True, text=True, timeout=180)
            assert got.returncode == 0, (start_index, got.returncode, got.stderr)
            lines = got.stdout.splitlines()
            assert len(lines) == len(batch), (start_index, lines, got.stderr)
            for index, ((group, op, _, output), line) in enumerate(zip(batch, lines)):
                assert line == output, (start_index+index, group, op, line, output)
            print(f'P-256: {start_index+len(batch)}/{len(cases)} cases passed', flush=True)
    print(f'P-256: {len(cases)} NIST/affine/scaled/infinity/order/canonical/malformed/OpenSSL cases passed in {time.monotonic()-start:.3f}s; {counts}')


if __name__ == '__main__':
    main()
