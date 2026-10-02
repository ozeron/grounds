"""Certificate civil-time admission against Python's independent calendar."""
import argparse
from collections import Counter
from datetime import datetime, timedelta
import hashlib
import json
from pathlib import Path
import random
import re
import subprocess
import tempfile
import time

import x509_algorithm_check as A
import x509_certificate_check as C

ROOT = Path(__file__).parent


def encoded(year, month=1, day=1, hour=0, minute=0, second=0, utc=False):
    body = f'{year % 100:02d}' if utc else f'{year:04d}'
    return A.tlv(23 if utc else 24, (body+f'{month:02d}{day:02d}{hour:02d}{minute:02d}{second:02d}Z').encode())


def seconds(data):
    try:
        tag, body, original = C.elements(data)[0]
        if original != data or tag not in (23, 24):
            return None
        digits = 12 if tag == 23 else 14
        if not re.fullmatch(rb'[0-9]{'+str(digits).encode()+rb'}Z', body):
            return None
        width = 2 if tag == 23 else 4
        year = int(body[:width])
        if tag == 23:
            year += 1900 if year >= 50 else 2000
        fields = [year]+[int(body[i:i+2]) for i in range(width, digits, 2)]
        value = datetime(*fields)
        return int((value-datetime(1, 1, 1)).total_seconds())
    except (ValueError, IndexError):
        return None


def interval(data):
    try:
        fields = C.elements(A.complete(data, 48))
        if len(fields) != 2:
            return None
        start, end = (seconds(f[2]) for f in fields)
        return (start, end) if start is not None and end is not None and start <= end else None
    except (ValueError, IndexError):
        return None


def oracle(operation, values):
    if operation == '0':
        value = seconds(values[0])
        return 'none' if value is None else str(value)
    if operation == '1':
        value = interval(values[0])
        return 'none' if value is None else ':'.join(map(str, value))
    data, now = values
    if operation == '3':
        try:
            data = C.parse(data)['validity']
        except (ValueError, IndexError):
            return 'false'
    value, current = interval(data), seconds(now)
    return str(value is not None and current is not None and value[0] <= current <= value[1]).lower()


def cases():
    def add(tag, operation, *values):
        return tag, operation, values, oracle(operation, values)

    # RFC 5280 Appendix C's three certificate validity examples and §4.1.2.5 sentinel.
    for start, end in (('040430142534Z', '050430142534Z'),
                       ('040915114821Z', '050315114821Z'),
                       ('040502164738Z', '050502164738Z')):
        before, after = A.tlv(23, start.encode()), A.tlv(23, end.encode())
        yield add('RFC5280-Appendix-C-time', '0', before)
        yield add('RFC5280-Appendix-C-time', '0', after)
        yield add('RFC5280-Appendix-C-validity', '1', A.tlv(48, before+after))
    yield add('RFC5280-indefinite-expiry-sentinel', '0', encoded(9999, 12, 31, 23, 59, 59))
    for year in range(1, 10000):
        yield add('every-year-February-29', '0', encoded(year, 2, 29))
        yield add('every-year-final-second', '0', encoded(year, 12, 31, 23, 59, 59))
    yield add('year-zero', '0', encoded(0))
    for year in range(1950, 2050):
        for month, day in ((1, 1), (2, 29), (12, 31)):
            yield add('every-UTCTime-year', '0', encoded(year, month, day, utc=True))
    for year in (1900, 2000, 2100, 2400):
        for month in range(14):
            for day in range(33):
                yield add('calendar-month-day-grid', '0', encoded(year, month, day))
    for utc in (True, False):
        good = encoded(2000, 2, 29, 23, 59, 59, utc)
        body = C.elements(good)[0][1]
        for index in range(len(body)):
            for byte in range(256):
                changed = bytearray(body); changed[index] = byte
                yield add('every-time-body-octet', '0', A.tlv(23 if utc else 24, bytes(changed)))
        for size in range(len(good)):
            yield add('every-time-truncation', '0', good[:size])
        for tag in range(256):
            yield add('every-time-tag', '0', A.tlv(tag, body))
        for bad in (good+b'\x00', bytes([good[0], 129, len(body)])+body,
                    bytes([good[0], 128])+body+b'\x00\x00', good[:-1],
                    A.tlv(good[0], body[:-3]+b'Z'), A.tlv(good[0], body[:-1]+b'.0Z'),
                    A.tlv(good[0], body[:-1]+b'+0000'), A.tlv(good[0], body[:-1]+b'-0000')):
            yield add('time-noncanonical-and-alias', '0', bad)
        for h, m, s in ((24, 0, 0), (0, 60, 0), (0, 0, 60), (99, 99, 99)):
            yield add('clock-range', '0', encoded(2000, 1, 1, h, m, s, utc))
    rng = random.Random(5280)
    for _ in range(256):
        before = datetime(rng.randrange(1950, 9900), rng.randrange(1, 13), rng.randrange(1, 28),
                          rng.randrange(24), rng.randrange(60), rng.randrange(60))
        after = before+timedelta(seconds=rng.randrange(1000000))
        b = encoded(before.year, before.month, before.day, before.hour, before.minute, before.second,
                    before.year < 2050)
        e = encoded(after.year, after.month, after.day, after.hour, after.minute, after.second,
                    after.year < 2050)
        validity = A.tlv(48, b+e)
        yield add('ordered-interval', '1', validity)
        yield add('reversed-interval', '1', A.tlv(48, e+b))
        for current in (before-timedelta(seconds=1), before, after, after+timedelta(seconds=1)):
            now = encoded(current.year, current.month, current.day, current.hour, current.minute, current.second)
            yield add('inclusive-interval-edges', '2', validity, now)
    before, after = encoded(2049, 12, 31, 23, 59, 59, True), encoded(2050)
    interval_bytes = A.tlv(48, before+after)
    for value in (A.tlv(48, b''), A.tlv(48, before), A.tlv(48, before+after+after),
                  A.tlv(48, A.tlv(5, b'')+after), interval_bytes+b'\x00',
                  A.tlv(48, before+A.tlv(24, b'not-a-time')), A.tlv(49, before+after)):
        yield add('validity-field-shape', '1', value)
        yield add('bad-validity-at', '2', value, before)
    for value in (before, after):
        yield add('mixed-year-transition', '2', interval_bytes, value)
        yield add('equal-endpoints', '2', A.tlv(48, value+value), value)
    for size in range(len(interval_bytes)):
        yield add('every-validity-truncation', '1', interval_bytes[:size])
    for size in (4096, 65534, 65535, 65536):
        yield add('time-input-bound', '0', bytes(size))
        yield add('validity-input-bound', '1', bytes(size))
    peers = json.loads((ROOT/'x509_algorithm_vectors.json').read_text())['peers']
    fresh = json.loads((ROOT/'x509_signature_vectors.json').read_text())['records']
    for peer in peers+fresh:
        cert = bytes.fromhex(peer['certificate_der'])
        validity = C.parse(cert)['validity']
        yield add('OpenSSL-certificate-validity', '1', validity)
        times = C.elements(A.complete(validity, 48))
        for row in times:
            yield add('OpenSSL-certificate-time', '0', row[2])
            yield add('certificate-at-extracted-edge', '3', cert, row[2])
        yield add('certificate-at-malformed-clock', '3', cert, b'')
        yield add('certificate-framing-required', '3', cert+b'\x00', times[0][2])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--report', type=Path)
    parser.add_argument('binary', nargs=argparse.REMAINDER)
    options = parser.parse_args()
    binary = options.binary[1:] if options.binary[:1] == ['--'] else options.binary
    if not binary:
        parser.error('supply evaluator after --')
    rows = iter(cases()); pending = next(rows, None); counts = Counter(); start = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='grounds-validity-') as folder:
        first = 0
        while pending is not None:
            batch = [pending]; pending = None
            while len(batch) < 64 and max(map(len, batch[0][2])) <= 4096:
                row = next(rows, None)
                if row is None: break
                if max(map(len, row[2])) > 4096:
                    pending = row; break
                batch.append(row)
            args = []
            for index, (_, operation, values, _) in enumerate(batch):
                args.append(operation)
                for part, value in enumerate(values):
                    path = Path(folder)/f'{index}-{part}.der'
                    path.write_bytes(value); args.append(str(path))
            result = subprocess.run(binary+['check']+args, capture_output=True, text=True, timeout=60)
            expected = [r[3] for r in batch]
            assert result.returncode == 0 and result.stdout.splitlines() == expected, (
                first, [r[0] for r in batch], result.returncode, result.stdout[-1000:], expected, result.stderr[-1000:])
            counts.update(r[0] for r in batch); first += len(batch)
            if pending is None: pending = next(rows, None)
        for args in ([], ['check', '0'], ['check', '2', 'one-path'], ['unknown']):
            result = subprocess.run(binary+args, capture_output=True, text=True, timeout=10)
            assert result.returncode == 2 and not result.stdout, args
    names = ('x509_validity.bend', 'x509_validity_cli.bend', 'x509_validity_check.py',
             'x509_certificate.bend', 'x509_algorithm.bend', 'bytes.bend', 'der.bend',
             'x509_certificate_check.py', 'x509_algorithm_check.py',
             'x509_algorithm_vectors.json', 'x509_signature_vectors.json')
    report = {'binary': binary, 'total': sum(counts.values()), 'cases': dict(counts),
              'CLI_failures': 4, 'elapsed_seconds': round(time.monotonic()-start, 3),
              'calendar_oracle': 'Python datetime', 'certificate_trust_validation': False,
              'input_sha256': {name: hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in names}}
    if options.report: options.report.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report))


if __name__ == '__main__': main()
