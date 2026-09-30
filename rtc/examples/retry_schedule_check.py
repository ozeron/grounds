"""Published timer vector and bounded arithmetic checks on compiled targets."""
import subprocess
import sys

command = sys.argv[1:]
cases = [(r, c, m) for r in (500, 1000, 60000) for c in range(1, 17) for m in (1, 16, 64)]
cases += [(r, c, m) for r, c, m in [(0, 7, 16), (499, 7, 16), (60001, 7, 16),
          (2**32-1, 7, 16), (500, 0, 16), (500, 17, 16), (500, 2**32-1, 16),
          (500, 7, 0), (500, 7, 65), (500, 7, 2**32-1)]]
for rto, count, factor in cases:
    result = subprocess.run(command + list(map(str, (rto, count, factor))), capture_output=True, text=True, timeout=5)
    assert result.returncode == 0, result.stderr
    if not (500 <= rto <= 60000 and 1 <= count <= 16 and 1 <= factor <= 64):
        assert result.stdout.strip() == "invalid", ((rto, count, factor), result.stdout)
        continue
    actual = list(map(int, result.stdout.splitlines()))
    expected = [rto * 2**i for i in range(count - 1)] + [rto * factor]
    assert actual == expected, ((rto, count, factor), actual, expected)
    assert max(actual) < 2**32 and sum(actual) < 2**31
    if (rto, count, factor) == (500, 7, 16):
        now = 0
        sends = []
        for wait in actual:
            sends.append(now)
            now += wait
        assert sends == [0, 500, 1500, 3500, 7500, 15500, 31500] and now == 39500
print(f"STUN retry schedules: {len(cases)} published/boundary cases passed")
