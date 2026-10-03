from pathlib import Path
import re,json,hashlib,argparse
parser=argparse.ArgumentParser(description='Regenerate pinned Unicode 3.2 RFC profile range tables from exact official text snapshots.')
parser.add_argument('--source-dir',required=True,type=Path)
parser.add_argument('--output-dir',default=Path(__file__).resolve().parent,type=Path)
args=parser.parse_args();root=args.source_dir;out=args.output_dir
for name,expected in [('rfc3454.txt','eb722fa698fb7e8823b835d9fd263e4cdb8f1c7b0d234edf7f0e3bd2ccbb2c79'),('rfc4518.txt','a12b9a04e49cf778f7a26e59d32a2bda02d6d4ab4d4151b6a8cc9db21070a068')]:
 assert hashlib.sha256((root/name).read_bytes()).hexdigest()==expected, name
def ranges(tokens):
 rows=[]
 for token in tokens:
  fields=token.split('-');rows.append([int(fields[0],16),int(fields[-1],16)])
 assert all(a<=b for a,b in rows)
 assert all(rows[i][1]<rows[i+1][0] for i in range(len(rows)-1))
 return rows
rfc=(root/'rfc3454.txt').read_text();section=rfc.split('----- Start Table A.1 -----')[1].split('----- End Table A.1 -----')[0]
unassigned=ranges(re.findall(r'^\s+([0-9A-F]{4,6}(?:-[0-9A-F]{4,6})?)\s*$',section,re.M))
rfc=(root/'rfc4518.txt').read_text();section=rfc.split('Appendix A.  Combining Marks')[1].split('Appendix B.')[0]
marks=ranges(re.findall(r'\b[0-9A-F]{4,6}(?:-[0-9A-F]{4,6})?\b',section))
assert len(unassigned)==396 and len(marks)==112,(len(unassigned),len(marks))
data={'unicode_version':'3.2.0','sources':{'rfc3454_sha256':hashlib.sha256((root/'rfc3454.txt').read_bytes()).hexdigest(),'rfc4518_sha256':hashlib.sha256((root/'rfc4518.txt').read_bytes()).hexdigest()},'unassigned':unassigned,'marks':marks}
(out/'unicode32_ranges.json').write_text(json.dumps(data,indent=2)+'\n')
text='import Base\n\n# Generated from RFC 3454 A.1 and RFC 4518 Appendix A; see unicode32_ranges.json.\n'
for name,rows in [('unassigned',unassigned),('marks',marks)]:
 vals=[x for row in rows for x in row]
 text+=f'\ndef {name}() -> List<&2, U32>:\n  ['+',\n   '.join(', '.join(str(v) for v in vals[i:i+12]) for i in range(0,len(vals),12))+']\n'
(out/'unicode32_ranges.bend').write_text(text)
print('ranges:',len(unassigned),len(marks))
