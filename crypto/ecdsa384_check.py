"""Offline CAVP/Wycheproof P-384 SHA-384 verification and cryptography differentials."""
import argparse
from collections import Counter
import json
from pathlib import Path
import subprocess
import tempfile
import sys


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--phase-prefix')
    p.add_argument('--batch-index', type=int)
    p.add_argument('--batch-size', type=int, default=8)
    p.add_argument('binary')
    args = p.parse_args()
    fixture = json.loads(Path(__file__).with_name('ecdsa384_vectors.json').read_text())
    rows = fixture['cases']
    batches = [rows[i:i+args.batch_size] for i in range(0,len(rows),args.batch_size)]
    if args.phase_prefix:
        sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'tools'))
        from check_phase import announce
    counts = Counter()
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        for index, batch in enumerate(batches):
            if args.batch_index is not None and index != args.batch_index:
                continue
            phase = f'{args.phase_prefix}/batch-{index:03}'
            if args.phase_prefix: announce(['start',phase])
            code = 1
            try:
                command = [args.binary]
                expected = []
                tags = []
                for row in batch:
                    files = {}
                    for field in ('peer','digest','signature','raw'):
                        if row[field] is None:continue
                        path = root / f'{row["tag"]}-{field}'
                        path.write_bytes(bytes.fromhex(row[field]));files[field] = str(path)
                    command += ['der',files['peer'],files['digest'],files['signature']]
                    expected.append(str(row['expected']).lower());tags.append(row['tag']+'/der')
                    if row['raw'] is not None:
                        command += ['raw',files['peer'],files['digest'],files['raw']]
                        expected.append(str(row['expected']).lower());tags.append(row['tag']+'/raw')
                    counts[row['group']] += 1
                result = subprocess.run(command,capture_output=True,text=True,timeout=115)
                assert result.returncode == 0,(index,result.returncode,result.stderr)
                actual = result.stdout.splitlines()
                assert len(actual)==len(expected),(index,len(actual),len(expected))
                for tag,got,want in zip(tags,actual,expected):assert got==want,(tag,got,want)
                code = 0
                print(f'P-384 batch {index}: {len(batch)} corpus cases / {len(expected)} raw+DER checks passed',flush=True)
            finally:
                if args.phase_prefix:announce(['end',phase,str(code)])
    print('P-384 completed:',dict(counts),flush=True)

if __name__ == '__main__':main()
