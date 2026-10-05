"""Independent record-payload reassembly and key-boundary checks."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import random
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parent
LIMIT = 1048576
ALIGNED = {1, 2, 5, 20, 24}


def message(kind, body=b''):
    return bytes([kind]) + len(body).to_bytes(3, 'big') + body


def emitted(encoded):
    return f'message:{len(encoded)}:{hashlib.sha256(encoded).hexdigest()}'


def expected(events):
    # Independent buffered reference; production consumes individual bytes.
    pending, total, alive, lines = b'', 0, True, []
    for event in events:
        if event == 'end':
            lines.append('closed' if not alive else 'incomplete' if pending else 'clean')
            alive = False
        elif event == 'boundary':
            good = alive and not pending
            lines.append('boundary' if good else 'error:boundary')
            alive = good
        elif not alive:
            lines.append('error:closed')
        elif event == 'nonbyte' or event == b'':
            lines.append('error:invalid')
            alive = False
        elif len(event) > 16384 or total + len(event) > LIMIT:
            lines.append('error:overflow')
            alive = False
        else:
            total += len(event)
            pending += event
            batch = []
            while len(pending) >= 4:
                size = int.from_bytes(pending[1:4], 'big') + 4
                if size > LIMIT:
                    alive = False
                    batch = ['error:overflow']
                    break
                if len(pending) < size:
                    break
                complete, pending = pending[:size], pending[size:]
                if complete[0] in ALIGNED and pending:
                    alive = False
                    batch = ['error:alignment']
                    break
                batch.append(emitted(complete))
            lines += batch
            if alive:
                lines.append('record')
    return lines


def regular_cases():
    data = json.loads((ROOT/'tls_handshake_vectors.json').read_text())
    cases = []
    for trace in data['traces']:
        messages = [bytes.fromhex(next(iter(row['fields'].values()))) for row in trace['operations'] if 'construct ' in row['operation']]
        cases.append((f'rfc8448-{trace["section"]}-records', messages + ['boundary', 'end']))
        for encoded in messages:
            cases.append(('published-byte-fragments', [encoded[i:i+1] for i in range(len(encoded))] + ['end']))
    hello = bytes.fromhex(data['traces'][0]['operations'][0]['fields']['ClientHello'])
    # Locate the server's coalescible EE/Certificate/Verify/Finished flight.
    rows = data['traces'][0]['operations']
    selected = [bytes.fromhex(next(iter(row['fields'].values()))) for row in rows
                if row['operation'].startswith('{server}') and 'construct ' in row['operation']]
    flight = b''.join(selected[1:5])
    assert hello[0] == 1 and [part[0] for part in selected[:5]] == [2, 8, 11, 15, 20]
    for name, encoded in [('every-hello-split', hello), ('every-server-flight-split', flight)]:
        for split in range(1, len(encoded)):
            cases.append((name, [encoded[:split], encoded[split:], 'end']))
    cases.append(('coalesced-server-flight', [flight, 'end']))
    cases.append(('empty-messages', [message(8) + message(11) + message(15), 'boundary', 'end']))
    cases.append(('unknown-type-framing-only', [message(255, b'future'), 'end']))
    rng = random.Random(984651)
    for _ in range(32):
        encoded = b''.join(message(rng.choice((8,11,13,15)), rng.randbytes(rng.randrange(513))) for _ in range(4))
        fragments = []
        while encoded:
            take = rng.randrange(1, 129)
            fragments.append(encoded[:take]); encoded = encoded[take:]
        cases.append(('independent-random-fragments', fragments + ['boundary', 'end']))
    for size in (1,2,3):
        cases.append(('partial-header', [hello[:size], 'boundary', hello[size:], 'end']))
        cases.append(('partial-header-eof', [hello[:size], 'end']))
    cases += [
        ('partial-body', [hello[:-1], 'boundary', hello[-1:], 'end']),
        ('partial-body-eof', [hello[:-1], 'end']),
        ('empty-record', [b'', message(8), 'end']),
        ('nonoctet-record', ['nonbyte', message(8), 'end']),
        ('oversized-record', [bytes(16385), 'end']),
        ('oversized-declaration', [b'\x0b\xff\xff\xff', 'end']),
        ('declared-limit-plus-one', [b'\x0b' + (LIMIT-3).to_bytes(3,'big'), 'end']),
        ('valid-prefix-then-bad-header', [message(8) + b'\x0b\xff\xff\xff', 'end']),
        ('trailing-header-pending', [message(8) + b'\x0b', 'end']),
        ('maximum-record', [message(11, bytes(16380)), 'end']),
    ]
    for kind in ALIGNED:
        encoded = message(kind, b'abc')
        cases += [('key-change-before-record-end', [encoded + message(8), 'end']),
                  ('fragmented-key-change-before-record-end', [encoded[:-1], encoded[-1:] + message(8), 'end']),
                  ('key-change-at-record-end', [message(8) + encoded, 'boundary', 'end'])]
    return cases


def stress_cases():
    exact = message(11, b'\x5a' * (LIMIT-4))
    cumulative = message(11, b'\x61' * (LIMIT-8)) + message(8)
    fragments = lambda data: [data[i:i+16384] for i in range(0,len(data),16384)]
    return [('exact-total-limit', fragments(exact) + ['boundary', 'end']),
            ('cumulative-total-limit', fragments(cumulative) + ['boundary', 'end']),
            ('total-overflow-consumes-owner', fragments(exact) + [b'\x08', 'end'])]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stress', action='store_true')
    parser.add_argument('--report', type=Path)
    parser.add_argument('binary', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    binary = args.binary[1:] if args.binary[:1] == ['--'] else args.binary
    if not binary: parser.error('compiled evaluator required')
    started, counts, corpus = time.monotonic(), Counter(), hashlib.sha256()
    cases = stress_cases() if args.stress else regular_cases()
    with tempfile.TemporaryDirectory(prefix='grounds-handshake-stream-') as tmp:
        folder = Path(tmp)
        for offset in range(0,len(cases),16):
            command, want = [*binary,'run'], []
            for number,(name,events) in enumerate(cases[offset:offset+16]):
                command.append('reset')
                expected_lines = expected(events)
                want += expected_lines
                counts[name] += 1
                corpus.update(json.dumps([name,[e.hex() if isinstance(e,bytes) else e for e in events],expected_lines],separators=(',',':')).encode())
                for index,event in enumerate(events):
                    if isinstance(event,str): command.append(event)
                    else:
                        path=folder/f'{number}-{index}.bin';path.write_bytes(event);command.append(str(path))
            run=subprocess.run(command,text=True,capture_output=True,timeout=110)
            assert run.returncode==0,(offset,run.returncode,run.stderr[-2000:])
            actual=run.stdout.splitlines()
            assert len(actual)==len(want),(offset,len(actual),len(want),run.stderr[-2000:])
            for index,(got,expected_line) in enumerate(zip(actual,want)):
                assert got==expected_line,(offset,index,got,expected_line)
    report={'binary':binary,'scenarios':dict(counts),'total_scenarios':sum(counts.values()),'stress':args.stress,
            'corpus_sha256':corpus.hexdigest(),'elapsed_seconds':round(time.monotonic()-started,3),
            'full_tls_state_or_interop':False,
            'source_sha256':{name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in ('tls_handshake_stream.bend','tls_handshake_stream_cli.bend','tls_handshake_stream_check.py','tls_handshake_vectors.json')}}
    if args.report:args.report.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,sort_keys=True))


if __name__=='__main__':main()
