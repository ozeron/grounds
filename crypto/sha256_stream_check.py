"""Independent SHA streaming, exact length, short-read and cleanup checks."""
import argparse
import hashlib
import os
from pathlib import Path
import random
import resource
import subprocess
import tempfile
import threading
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bun', action='store_true')
    parser.add_argument('fixture')
    parser.add_argument('file_hash')
    options = parser.parse_args()
    prefix = ['bun'] if options.bun else []
    fixture = prefix + [options.fixture]
    file_hash = prefix + [options.file_hash]

    def run(command, low_fds=False):
        def limit_fds():
            resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
        result = subprocess.run(command, capture_output=True, text=True,
                                timeout=20, preexec_fn=limit_fds if low_fds else None)
        assert result.returncode == 0, (result.returncode, result.stderr[-2000:], result.stdout[-2000:])
        return result.stdout.splitlines()

    with tempfile.TemporaryDirectory(prefix='grounds-sha-stream-') as folder:
        root = Path(folder)
        rng = random.Random(0x53545245414D)
        records = []
        for n in (0, 1, 2, 3, 31, 55, 56, 63, 64, 65, 119, 120, 127,
                  128, 129, 193, 255, 256, 257, 513, 1023, 4095, 4096, 4097, 8193):
            data = bytes(range(256))[:n] if n <= 256 else rng.randbytes(n)
            path = root / f'{n}.bin'
            path.write_bytes(data)
            expected = hashlib.sha256(data).hexdigest()
            for size in (1, 3, 7, 31, 55, 63, 64, 65, 127, 257, 4096):
                records.append((['split', str(size), str(path)], expected))
        for offset in range(0, len(records), 60):
            batch = records[offset:offset + 60]
            got = run(fixture + [arg for args, _ in batch for arg in args])
            assert got == [expected for _, expected in batch], (offset, got)

        lengths, expected = [], []
        for high in (0, 1, 0x1FFFFFFF, 0x20000000, 0xFFFFFFFF):
            for low in (0, 1, 0x1FFFFFFF, 0x20000000, 0xFFFFFFFE, 0xFFFFFFFF):
                lengths += ['length', str(high), str(low)]
                count = (high << 32) | low
                expected.append((count * 8).to_bytes(8, 'big').hex()
                                if count < 2**61 else 'invalid')
        assert run(fixture + lengths) == expected
        guards = [hashlib.sha256(b'').hexdigest(), 'invalid', 'invalid',
                  '1:0:0:', '1:0:0:'] + ['invalid'] * 7
        assert run(fixture + ['guards']) == guards

        small = root / 'small.bin'
        small.write_bytes(b'abc')
        args = ['file', str(small)] * 200
        assert run(fixture + args, low_fds=True) == [hashlib.sha256(b'abc').hexdigest()] * 200
        assert run(fixture + ['overflow', str(small)] * 200, low_fds=True) == ['invalid'] * 200
        assert run(fixture + ['refuel', str(small)]) == [hashlib.sha256(b'abc').hexdigest()]

        fifo_cases = [b'', rng.randbytes(4097)]
        for index, data in enumerate(fifo_cases):
            fifo = root / f'input-{index}.fifo'
            os.mkfifo(fifo)
            errors = []

            def write_chunks():
                try:
                    with fifo.open('wb', buffering=0) as output:
                        offset = 0
                        sizes = (1, 2, 3, 7, 31, 64, 65, 129, 1023)
                        chunk = 0
                        while offset < len(data):
                            amount = min(sizes[chunk % len(sizes)], len(data) - offset)
                            written = output.write(data[offset:offset + amount])
                            assert written and written > 0
                            offset += written
                            chunk += 1
                            time.sleep(0.001)
                except BaseException as error:
                    errors.append(error)

            writer = threading.Thread(target=write_chunks, daemon=True)
            writer.start()
            got = run(file_hash + [str(fifo)])
            writer.join(timeout=5)
            assert not writer.is_alive() and not errors, errors
            assert got == [hashlib.sha256(data).hexdigest()]

        for path in (root / 'missing.bin', root):
            result = subprocess.run(file_hash + [str(path)], capture_output=True,
                                    text=True, timeout=10)
            assert result.returncode != 0 and result.stdout == '', (path, result)
        for size in ('0', 'bad'):
            result = subprocess.run(fixture + ['split', size, str(small)],
                                    capture_output=True, text=True, timeout=10)
            assert result.returncode != 0 and result.stdout == '', (size, result)

    print(f'SHA-256 streaming: {len(records)} chunk partitions, 30 exact length encodings, 12 state guards')
    print('SHA-256 file: 200 hashes and 200 overflows under 64 descriptors, refuel, two FIFO streams, four error cases passed')


if __name__ == '__main__':
    main()
