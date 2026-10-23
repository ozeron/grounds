"""Synthetic RSA-PSS CRT signing: RFC 8017 differential, Bend, OpenSSL peers.

The CLI checks every released signature with the existing Bend PSS verifier.
Frozen keys/signatures were generated/verified with Python cryptography; Python
pow and this independent EMSA-PSS implementation check every generated output.
No Grounds runtime code calls a host crypto implementation.
"""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import random
import shutil
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parent
FIELDS = ('n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi')
SECTIONS = ('arithmetic', 'keys', 'sign', 'reject')


def be(value, width=None):
    return value.to_bytes(width or max(1, (value.bit_length()+7)//8), 'big')


def pss(bits, digest, salt):
    """RFC 8017 9.1.1, independent of Grounds rsa_encoding_check.py."""
    length = (bits+7)//8
    h = hashlib.sha256(bytes(8)+digest+salt).digest()
    db = bytes(length-66)+b'\x01'+salt
    mask = b''.join(hashlib.sha256(h+i.to_bytes(4, 'big')).digest()
                    for i in range((length-33+31)//32))
    masked = bytes(a^b for a, b in zip(db, mask))
    return bytes([masked[0] & (255 >> (8*length-bits))])+masked[1:]+h+b'\xbc'


def load():
    fixture = json.loads((ROOT/'rsa_private_fixture.json').read_text())
    for record in fixture['keys']:
        record['integers'] = {k: int(record['key'][k], 16) for k in FIELDS}
        record['values'] = [bytes.fromhex(record['key'][k]) for k in FIELDS]
        k = record['integers']
        assert k['n'] == k['p']*k['q']
        assert k['dp'] == k['d'] % (k['p']-1)
        assert k['dq'] == k['d'] % (k['q']-1)
        assert k['qi']*k['q'] % k['p'] == 1
        digest, salt = (bytes.fromhex(record[x]) for x in ('digest', 'salt'))
        expected = pow(int.from_bytes(pss(record['bits']-1, digest, salt), 'big'),
                       k['d'], k['n'])
        assert be(expected, len(record['values'][0])).hex() == record['signature']
    return fixture


def op(tag, mode, values, expected, record=None, digest=None):
    return dict(tag=tag, mode=mode, values=values, expected=expected,
                record=record, digest=digest)


def key_op(tag, record, changes=None, *, mode='0', expected='true', digest=None, salt=None, blind=None):
    values = record['values'].copy()
    for field, replacement in (changes or {}).items():
        values[FIELDS.index(field)] = replacement
    digest = bytes.fromhex(record['digest']) if digest is None else digest
    salt = bytes.fromhex(record['salt']) if salt is None else salt
    blind = be(2, len(values[0])) if blind is None else blind
    return op(tag, mode, values+[digest, salt, blind], expected, record, digest)


def arithmetic_cases():
    rng = random.Random(0x8017)
    cases = []
    # Cross-limb carries, even-modulus reduction, masked private powers, and
    # Montgomery multiplication. Fixed seed makes the full corpus reproducible.
    for bits in (2, 7, 15, 16, 31, 64, 127, 255, 521, 1024, 2048):
        n = rng.getrandbits(bits) | (1 << (bits-1)) | 1
        width = len(be(n))
        a, b = rng.randrange(n), rng.randrange(n)
        cases += [op(f'multiply-{bits}', '5', [be(n), be(a), be(b)], be(a*b % n, width).hex()),
                  op(f'power-{bits}', '4', [be(n), be(13), be(a)], be(pow(a, 13, n), width).hex()),
                  op(f'reduce-odd-{bits}', '3', [be(n), be(rng.getrandbits(bits*2)), b''], None),
                  op(f'reduce-even-{bits}', '3', [be(n+1), be(rng.getrandbits(bits*2)), b''], None)]
        for case in cases[-2:]:
            mod, value = (int.from_bytes(x, 'big') for x in case['values'][:2])
            case['expected'] = be(value % mod, len(case['values'][0])).hex()
    # Fixed-window boundaries, leading zero windows and all-zero exponents.
    for bits in (15, 16, 127, 1024, 2048):
        n = rng.getrandbits(bits) | (1 << (bits-1)) | 1
        width = len(be(n))
        for exponent in (0, 1, 15, 16, 255, 256, 65535, 65536):
            base = rng.randrange(n)
            encoded = b'\x00' + be(exponent)
            cases.append(op(f'window-power-{bits}-{exponent}', '4',
                            [be(n), encoded, be(base)], be(pow(base, exponent, n), width).hex()))
    for width in (1, 2, 4, 16, 64, 128, 256):
        a, b = (1 << (width*8))-1, rng.getrandbits(width*8)
        cases.append(op(f'product-{width}', '2', [b'', be(a), be(b)], be(a*b, 512).hex()))
    for width in (1, 2, 128, 256):
        value = 3 if width == 1 else 1 << (8*(width-1))
        for amount in (0, 1, 2):
            cases.append(op(f'subtract-{width}-amount-{amount}', '6',
                            [b'', be(value, width), be(amount)],
                            be(value-amount, width).hex()))
    return cases


def key_cases(records):
    cases = [key_op(r['tag']+'-validate', r) for r in records]
    r = records[0]
    n, k = r['values'][0], r['integers']
    for field in FIELDS:
        original = k[field]
        # n/e/p/q remain odd, so these exercise congruence or factor rejection.
        cases.append(key_op('inconsistent-'+field, r, {field: be(original ^ 2)}, expected='false'))
        cases.append(key_op('noncanonical-'+field, r, {field: b'\x00'+be(original)}, expected='false'))
        cases.append(key_op('empty-'+field, r, {field: b''}, expected='false'))
    for tag, changes in (
        ('equal-factors', {'q': be(k['p'])}),
        ('even-factor', {'p': be(k['p']-1)}),
        ('exponent-one', {'e': b'\x01'}),
        ('exponent-even', {'e': b'\x02'}),
        ('exponent-over-U32', {'e': be((1 << 32)+1)}),
        ('small-modulus', {'n': n[1:]}),
        ('oversized-modulus', {'n': b'\x01'+bytes(511)+b'\x01'}),
        ('small-factor', {'p': be(17)}),
        ('oversized-factor', {'p': b'\x01'+bytes(255)+b'\x01'}),
        ('factor-above-arithmetic-capacity', {'p': b'\x01'+bytes(4095)+b'\x01'}),
        ('d-equals-n', {'d': n}),
        ('dp-equals-p-minus-one', {'dp': be(k['p']-1)}),
        ('dq-equals-q-minus-one', {'dq': be(k['q']-1)}),
        ('qi-equals-p', {'qi': be(k['p'])}),
    ):
        cases.append(key_op(tag, r, changes, expected='false'))
    swapped = dict(p=be(k['q']), q=be(k['p']), dp=be(k['dq']), dq=be(k['dp']),
                   qi=be(pow(k['p'], -1, k['q'])))
    cases.append(key_op('valid-reversed-factors', r, swapped))
    large = next(record for record in records if record['bits'] == 4096)
    truncated = large['integers']['n'] % (1 << 2048)
    assert truncated.bit_length() == 2048, 'fixture must reach full-product check, not size rejection'
    cases.append(key_op('reject-full-product-truncation', large,
                        {'n': be(truncated)}, expected='false'))
    return cases


def sign_case(tag, r, *, digest=None, salt=None, blind=None):
    digest = bytes.fromhex(r['digest']) if digest is None else digest
    salt = bytes.fromhex(r['salt']) if salt is None else salt
    k = r['integers']
    signature = be(pow(int.from_bytes(pss(k['n'].bit_length()-1, digest, salt), 'big'),
                       k['d'], k['n']), len(r['values'][0])).hex()
    return key_op(tag, r, mode='1', expected=signature, digest=digest, salt=salt, blind=blind)


def sign_cases(records):
    cases = [sign_case(r['tag']+'-sign', r) for r in records]
    r = records[0]
    width, n = len(r['values'][0]), r['integers']['n']
    for tag, digest, salt, blind in (
        ('zero-salt', None, bytes(32), be(3, width)),
        ('max-salt', None, b'\xff'*32, be(17, width)),
        ('zero-digest', bytes(32), None, be(n-1, width)),
        ('different-blinder-same-signature', None, None, be(65537, width)),
    ):
        cases.append(sign_case(tag, r, digest=digest, salt=salt, blind=blind))
    return cases


def reject_cases(records):
    r, cases = records[0], []
    k, width = r['integers'], len(r['values'][0])
    for tag, blind in (
        ('empty', b''), ('short', bytes(width-1)), ('long', bytes(width+1)),
        ('zero', bytes(width)), ('one', be(1, width)),
        ('equals-n', be(k['n'], width)), ('above-n', be(k['n']+1, width)),
        ('all-ones', b'\xff'*width),
        ('multiple-p', be(k['p'], width)), ('multiple-q', be(k['q'], width)),
    ):
        cases.append(key_op('blind-'+tag, r, mode='1', expected='invalid', blind=blind))
    for size in (0, 1, 31, 33, 48):
        cases.append(key_op(f'digest-{size}', r, mode='1', expected='invalid', digest=bytes(size)))
        cases.append(key_op(f'salt-{size}', r, mode='1', expected='invalid', salt=bytes(size)))
    for field in FIELDS:
        cases.append(key_op('sign-bad-key-'+field, r, {field: be(k[field] ^ 2)},
                            mode='1', expected='invalid'))
    return cases


def openssl_verify(case, signature, folder, openssl):
    public = folder/'public.pem'
    public.write_text(case['record']['public_pem'])
    digest, sig = folder/'digest.bin', folder/'signature.bin'
    digest.write_bytes(case['digest'])
    sig.write_bytes(signature)
    result = subprocess.run([openssl, 'pkeyutl', '-verify', '-pubin', '-inkey', str(public),
                             '-in', str(digest), '-sigfile', str(sig),
                             '-pkeyopt', 'rsa_padding_mode:pss', '-pkeyopt', 'rsa_pss_saltlen:32',
                             '-pkeyopt', 'digest:sha256', '-pkeyopt', 'rsa_mgf1_md:sha256'],
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, (case['tag'], result.stdout, result.stderr)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--section', choices=('all',)+SECTIONS, default='all')
    parser.add_argument('--case-index', type=int)
    parser.add_argument('--phase-prefix')
    parser.add_argument('--report', type=Path)
    parser.add_argument('--oracle-only', action='store_true')
    parser.add_argument('binary', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    binary = args.binary[1:] if args.binary[:1] == ['--'] else args.binary
    if not binary and not args.oracle_only:
        parser.error('supply evaluator after --')
    backend = 'oracle' if args.oracle_only else ('bun' if Path(binary[0]).name == 'bun' else 'native')
    fixture, counts, signatures = load(), Counter(), 0
    records = fixture['keys']
    factories = dict(arithmetic=arithmetic_cases, keys=lambda: key_cases(records),
                     sign=lambda: sign_cases(records), reject=lambda: reject_cases(records))
    openssl = shutil.which('openssl')
    assert openssl, 'OpenSSL independent verifier is required'
    version = subprocess.check_output([openssl, 'version'], text=True).strip()
    begin = time.monotonic()
    if args.phase_prefix:
        import sys
        sys.path.insert(0, str(ROOT.parent/'tools'))
        from check_phase import announce
    with tempfile.TemporaryDirectory(prefix='grounds-rsa-private-') as directory:
        folder = Path(directory)
        for section, factory in factories.items():
            if (args.section not in ('all', section) or
                    (args.oracle_only and section != 'sign')):
                continue
            cases = factory()
            if args.case_index is not None:
                cases = cases[args.case_index:args.case_index+1]
                assert cases, 'case index outside full corpus'
            for index, case in enumerate(cases):
                phase = f'{args.phase_prefix}/{section}/case-{index if args.case_index is None else args.case_index:03d}'
                if args.phase_prefix:
                    announce(['start', phase])
                if args.oracle_only:
                    if section == 'sign':
                        openssl_verify(case, bytes.fromhex(case['expected']), folder, openssl)
                        signatures += 1
                else:
                    paths = []
                    for field, value in enumerate(case['values']):
                        path = folder/f'{field}.bin'
                        path.write_bytes(value)
                        paths.append(str(path))
                    result = subprocess.run(binary+[case['mode']]+paths, capture_output=True,
                                            text=True, timeout=115)
                    assert result.returncode == 0, (section, index, case['tag'], result.stderr)
                    assert result.stdout.splitlines() == [case['expected']], (
                        section, index, case['tag'], result.stdout, case['expected'])
                    if section == 'sign':
                        openssl_verify(case, bytes.fromhex(result.stdout.strip()), folder, openssl)
                        signatures += 1
                counts[section] += 1
                if args.phase_prefix:
                    announce(['end', phase, '0'])
            print(f'RSA private {section}: {counts[section]} cases passed', flush=True)
    report = dict(binary=binary, backend=backend, section=args.section, case_index=args.case_index,
                  counts=dict(counts), total=sum(counts.values()), signatures_independently_verified=signatures,
                  openssl_version=version, cryptography_fixture_version=fixture['cryptography_version'],
                  elapsed_seconds=round(time.monotonic()-begin, 3),
                  private_key_material='public synthetic fixtures only',
                  prime_generation_or_constant_time_approval=False,
                  every_released_signature_checked_by_existing_bend_verifier=not args.oracle_only,
                  input_sha256={name: hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in
                                ('rsa_private.bend', 'rsa_private_cli.bend', 'rsa_private_check.py',
                                 'rsa_private_fixture.json', 'rsa_integer.bend', 'rsa_signature256.bend',
                                 'rsa_encoding.bend', 'bytes.bend', 'sha256.bend')})
    report_path = args.report
    if report_path is None and os.environ.get('GROUNDS_M2_REPORT_DIR'):
        folder = Path(os.environ['GROUNDS_M2_REPORT_DIR'])
        folder.mkdir(parents=True, exist_ok=True)
        report_path = folder/f'rsa-private-{backend}-{args.section}-{args.case_index}.json'
    if report_path:
        report_path.write_text(json.dumps(report, indent=2)+'\n')
    print('RSA private: '+json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
