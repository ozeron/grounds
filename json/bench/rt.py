import json, sys
sys.stdout.write(json.dumps(json.load(open(sys.argv[1], encoding="utf-8")), ensure_ascii=False, separators=(",", ":")))
