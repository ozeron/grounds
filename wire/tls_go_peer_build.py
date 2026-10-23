"""Build the independent crypto/tls peer into a caller-owned temporary path."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--report',type=Path,required=True)
    args=parser.parse_args()
    go=os.environ.get('GROUNDS_GO')
    if not go:
        installed=subprocess.check_output(['mise','where','go@1.26.9'],text=True).strip()
        go=str(Path(installed)/'bin/go')
    source=Path(__file__).with_name('tls_go_peer.go')
    command=[go,'build','-o',str(args.output.resolve()),str(source.resolve())]
    result=subprocess.run(command,text=True,capture_output=True)
    report=dict(command=command,exit=result.returncode,stdout=result.stdout,stderr=result.stderr,
                version=subprocess.check_output([go,'version'],text=True).strip(),
                source_sha256=hashlib.sha256(source.read_bytes()).hexdigest())
    if args.output.is_file():
        report['binary_sha256']=hashlib.sha256(args.output.read_bytes()).hexdigest()
    args.report.write_text(json.dumps(report,indent=2)+'\n')
    if result.returncode:
        print(result.stdout,result.stderr)
        raise SystemExit(result.returncode)


if __name__=='__main__':
    main()
