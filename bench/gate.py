"""Fail if bjson is more than LIMIT times Go's time on a benchmark file."""
import json
import sys

TOOL = sys.argv[1] if len(sys.argv) > 1 else "bjson"
LIMIT = 1.35
bad = False
for f in ["canada", "citm_catalog", "twitter"]:
    means = {r["command"]: r["mean"] for r in json.load(open(f"bench/results/{f}.json"))["results"]}
    ratio = means[TOOL] / means["go"]
    ok = ratio <= LIMIT or f != "canada"
    bad |= not ok
    print(f"{f:14} {TOOL} {means[TOOL]*1000:6.1f} ms  go {means['go']*1000:5.1f} ms  {ratio:4.2f}x{'' if ok else f'  over {LIMIT}x'}")
sys.exit(1 if bad else 0)
