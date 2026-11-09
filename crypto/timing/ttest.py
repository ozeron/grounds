#!/usr/bin/env python3
"""Leakage statistics over timing_cli output ("class cycles instructions result").

Cycles and instructions retired come from the per-thread counters in
effs/clock.c (modulo 2^47; Bend's Nat subtraction saturates, so a wrapped
sample shows as 0 and is dropped). For each file this reports

* a dudect-style Welch t-test on cycles, raw and cropped below several
  percentiles of the pooled distribution (cropping removes OS-noise tails);
  |t| > 4.5 is the usual leak indication;
* the instructions-retired distribution per class. Identical per-class
  instruction counts mean the executed instruction stream did not depend on
  the class. A difference is reported with its own t value.

Passing does not prove constant-time execution: it covers the sampled
inputs, this core and this build only, and instruction counts do not see
secret-dependent memory addresses. Stdlib only.
"""
import argparse
import json
import math
import sys

def welch(a, b):
    na, nb = len(a), len(b)
    if na < 2 or nb < 2:
        return 0.0
    ma = sum(a) / na
    mb = sum(b) / nb
    va = sum((x - ma) ** 2 for x in a) / (na - 1)
    vb = sum((x - mb) ** 2 for x in b) / (nb - 1)
    den = math.sqrt(va / na + vb / nb)
    if den == 0:
        return 0.0 if ma == mb else math.copysign(math.inf, ma - mb)
    return (ma - mb) / den


def median(xs):
    return sorted(xs)[len(xs) // 2] if xs else 0


def load(paths):
    samples = []
    for path in paths:
        with open(path) as handle:
            for line in handle:
                parts = line.split()
                if len(parts) < 3 or parts[0] not in ("0", "1"):
                    continue
                if not (parts[1].isdigit() and parts[2].isdigit()):
                    continue
                cycles, instrs = int(parts[1]), int(parts[2])
                if cycles == 0:
                    continue
                samples.append((int(parts[0]), cycles, instrs))
    return samples


def analyse(samples, warmup):
    samples = samples[warmup:]
    result = {"n": len(samples)}
    if not samples:
        return result
    pooled = sorted(c for _, c, _ in samples)
    result["median_cycles"] = pooled[len(pooled) // 2]
    tests = []
    for pct in (None, 99, 95, 90, 75, 50):
        limit = None if pct is None else pooled[min(len(pooled) - 1, int(len(pooled) * pct / 100))]
        a = [c for k, c, _ in samples if k == 0 and (limit is None or c < limit)]
        b = [c for k, c, _ in samples if k == 1 and (limit is None or c < limit)]
        tests.append({"crop": pct, "t": round(welch(a, b), 3), "n0": len(a), "n1": len(b),
                      "median0": median(a), "median1": median(b)})
    result["cycle_tests"] = tests
    result["max_abs_t"] = max(abs(x["t"]) for x in tests)
    ia = [i for k, _, i in samples if k == 0]
    ib = [i for k, _, i in samples if k == 1]
    result["instructions"] = {
        "class0": {"min": min(ia, default=0), "median": median(ia), "max": max(ia, default=0),
                   "distinct": len(set(ia))},
        "class1": {"min": min(ib, default=0), "median": median(ib), "max": max(ib, default=0),
                   "distinct": len(set(ib))},
        "t": round(welch(ia, ib), 3),
    }
    result["leak"] = result["max_abs_t"] > 4.5 or abs(result["instructions"]["t"]) > 4.5
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("files", nargs="+")
    parser.add_argument("--warmup", type=int, default=200)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = analyse(load(args.files), args.warmup)
    if args.json:
        json.dump(result, sys.stdout, indent=1)
        print()
        return
    ins = result.get("instructions", {})
    print(f"n={result['n']} median={result.get('median_cycles')}cyc max|t|={result.get('max_abs_t')}"
          f" instr-t={ins.get('t')} {'LEAK' if result.get('leak') else 'no leak indication'}")
    for x in result.get("cycle_tests", []):
        print(f"  crop<{x['crop'] or 'none'}: t={x['t']:8.3f} n0={x['n0']} n1={x['n1']}"
              f" med0={x['median0']} med1={x['median1']}")
    for k in ("class0", "class1"):
        v = ins.get(k, {})
        print(f"  instructions {k}: min={v.get('min')} median={v.get('median')} max={v.get('max')}"
              f" distinct={v.get('distinct')}")


if __name__ == "__main__":
    main()
