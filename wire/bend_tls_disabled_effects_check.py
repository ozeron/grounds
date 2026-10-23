"""Positive controls: the disabled compatibility effects really terminate."""
import argparse
import json
from pathlib import Path
import subprocess


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native',required=True)
    parser.add_argument('--js',required=True)
    parser.add_argument('--effect',required=True,choices=['wire_tls_listen_ctx','sign'])
    parser.add_argument('--report',required=True,type=Path)
    args=parser.parse_args()
    results=[]
    for command,expected in [([args.native],86),(['bun',args.js],1)]:
        result=subprocess.run(command,text=True,capture_output=True,timeout=10)
        marker='GROUNDS_FORBIDDEN_HOST_EFFECT:'+args.effect
        results.append(dict(command=command,exit=result.returncode,stdout=result.stdout,stderr=result.stderr,
                            passed=result.returncode==expected and marker in result.stderr))
    report=dict(passed=all(r['passed'] for r in results),results=results)
    args.report.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(passed=report['passed'],effect=args.effect)))
    if not report['passed']:
        raise SystemExit(1)


if __name__=='__main__':
    main()
