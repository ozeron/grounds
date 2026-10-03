"""Full Unicode 3.2 profile property/mapping differential check."""
import argparse,hashlib,json,stringprep,subprocess,unicodedata
from pathlib import Path
U=unicodedata.ucd_3_2_0
assert U.unidata_version=='3.2.0'
def expected(code):
 if code>0x10ffff:return 4,3
 c=chr(code); category=U.category(c)
 removed=(category in ('Cc','Cf') and code not in (9,10,11,12,13,133)) or code in (0xad,0x1806,0x034f,0xfffc,0x200b) or 0x180b<=code<=0x180d or 0xfe00<=code<=0xfe0f
 space=code in (9,10,11,12,13,133) or category in ('Zs','Zl','Zp') and code!=0x200b
 prohibited=(stringprep.in_table_a1(c) or stringprep.in_table_c3(c) or stringprep.in_table_c4(c) or stringprep.in_table_c5(c) or stringprep.in_table_c8(c) or code==0xfffd)
 # RFC4518 Appendix A is definitive and differs from UCD categories here.
 mark=(category in ('Mn','Mc','Me') and code!=0x05bd) or code in (0x094e,0x094f)
 flags=int(removed)+2*int(space)+4*int(prohibited)+8*int(mark)
 mapping=3 if 0xd800<=code<=0xdfff else 0 if removed else 1 if space else 2
 return flags,mapping

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--report',type=Path);p.add_argument('binary',nargs=argparse.REMAINDER)
 a=p.parse_args();binary=a.binary[1:] if a.binary[:1]==['--'] else a.binary
 if not binary:p.error('supply evaluator')
 r=subprocess.run(binary,capture_output=True,timeout=110)
 assert r.returncode==0,(r.returncode,r.stderr[-1000:])
 lines=r.stdout.splitlines();assert len(lines)==274,len(lines)
 raw=b''.join(lines);count=0;identity=hashlib.sha256()
 code_ranges=[range(0x110000),range(0x110000,0x111000),range(0xfffff000,0x100000000)]
 assert len(raw)==2*sum(len(r) for r in code_ranges),len(raw)
 for codes in code_ranges:
  for code in codes:
   flags,mapping=expected(code)
   actual=raw[count*2:count*2+2]
   wanted=bytes([48+flags,48+mapping])
   assert actual==wanted,(hex(code),actual,wanted,U.category(chr(code)) if code<=0x10ffff else None)
   identity.update(code.to_bytes(4,'big')+wanted);count+=1
 report={'binary':binary,'code_points':count,'property_and_mapping_checks':count*2,'all_Unicode_code_points':0x110000,'outside_repertoire_checks':8192,'unicode_version':U.unidata_version,'corpus_sha256':identity.hexdigest(),'full_casefold_NFKC_stringprep_or_Name_comparison':False}
 if a.report:a.report.write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps(report,sort_keys=True))
if __name__=='__main__':main()
