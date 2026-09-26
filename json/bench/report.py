"""Print the benchmark table from bench/results/*.json (hyperfine exports)."""
import json, os
files = ["canada", "citm_catalog", "twitter"]
sizes = {f: os.path.getsize(f"bench/data/{f}.json") for f in files}
load = lambda f: {r["command"]: r["mean"] for r in json.load(open(f"bench/results/{f}.json"))["results"]}
base, res = load("empty"), {f: load(f) for f in files}
print(f"{'tool':8}" + "".join(f"{f + ' (' + str(round(sizes[f]/1e6, 1)) + ' MB)':>22}" for f in files) + f"{'startup':>10}")
for t in res[files[0]]:
    row = f"{t:8}"
    for f in files:
        mbs = sizes[f] / max(res[f][t] - base[t], 1e-6) / 1e6
        row += f"{res[f][t]*1000:9.1f} ms {mbs:6.0f} MB/s"
    print(row + f"{base[t]*1000:8.1f} ms")
