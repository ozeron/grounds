"""Imported private-key/credential wrappers reject owner copies and reuse."""
import json
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    root=Path(__file__).resolve().parent
    prefix='import Base\nimport ../private_key.bend as K\nimport ../credential.bend as C\n\n'
    valid={
      'consume-private':'def valid(owner: K.Private) -> Maybe<&1, C.Credential>:\n  C.from_key([], owner)\n',
      'consume-credential':'def valid(owner: C.Credential) -> K.Private:\n  match owner:\n    case C.Credential{_, key}:\n      key\n',
    }
    invalid={
      'copy-private':'def misuse(+owner: K.Private) -> K.Private & K.Private:\n  (owner, owner)\n',
      'copy-credential':'def misuse(+owner: C.Credential) -> C.Credential & C.Credential:\n  (owner, owner)\n',
      'import-private-twice':'def misuse(+owner: K.Private) -> Maybe<&1, C.Credential> & Maybe<&1, C.Credential>:\n  (C.from_key([], owner), C.from_key([], owner))\n',
      'retire-credential-twice':'def retire(owner: C.Credential) -> Unit:\n  Unit{}\n\ndef misuse(+owner: C.Credential) -> Unit & Unit:\n  (retire(owner), retire(owner))\n',
    }
    with tempfile.TemporaryDirectory(dir=root,prefix='private-key-type-') as directory:
        for accepted,probes in [(True,valid),(False,invalid)]:
            for name,body in probes.items():
                path=Path(directory)/(name+'.bend'); path.write_text(prefix+body)
                process=subprocess.run(['bend',str(path),'--check-only'],capture_output=True,text=True,timeout=20)
                diagnostic=process.stdout+process.stderr
                if accepted:
                    assert process.returncode==0,(name,diagnostic)
                else:
                    assert process.returncode!=0,(name,'affine misuse compiled')
                    assert 'Location: misuse' in diagnostic and 'Type' in diagnostic and 'Data' in diagnostic,(name,diagnostic)
    result={'valid_consumption':len(valid),'rejected_copy_or_reuse':len(invalid),'total':len(valid)+len(invalid)}
    directory=os.environ.get('GROUNDS_M2_REPORT_DIR')
    if directory:
        out=Path(directory); out.mkdir(parents=True,exist_ok=True)
        (out/'private-key-ownership.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result))

if __name__=='__main__': main()
