"""A soak test: the client and the server over many rounds, for leaks.

  python3 tests/soak.py SOAK STREAM ROUNDS

Starts tests/fake.py (with TLS) and STREAM (http/server's examples/stream)
on 8086, then SOAK ROUNDS (tests/soak.bend built). At each "round N" line
it samples the resident memory and open descriptors of the client and of
the server. After a warm-up of a fifth of the rounds, memory may grow by at
most 20% and 4 MB, and descriptors by at most 8; else it fails.
"""
import os
import subprocess
import sys
import tempfile
import time

SOAK, STREAM, ROUNDS = sys.argv[1], sys.argv[2], int(sys.argv[3])
HERE = os.path.dirname(os.path.abspath(__file__))


def rss_kb(pid):
    out = subprocess.run(["ps", "-o", "rss=", "-p", str(pid)], capture_output=True, text=True).stdout.strip()
    return int(out) if out else 0


def fds(pid):
    d = f"/proc/{pid}/fd"
    if os.path.isdir(d):
        return len(os.listdir(d))
    out = subprocess.run(["lsof", "-p", str(pid)], capture_output=True, text=True).stdout
    return max(0, len(out.splitlines()) - 1)


def main():
    tmp = tempfile.mkdtemp()
    fake = subprocess.Popen([sys.executable, os.path.join(HERE, "fake.py"), tmp], stdout=subprocess.PIPE, text=True)
    fake.stdout.readline()
    server = subprocess.Popen([STREAM], env={**os.environ, "PORT": "8086"}, stderr=subprocess.DEVNULL)
    time.sleep(0.5)
    client = subprocess.Popen([SOAK, str(ROUNDS)], env={**os.environ, "GROUNDS_TLS_CA": tmp + "/cert.pem"},
                              stdout=subprocess.PIPE, text=True)
    samples = []
    t0 = time.time()
    last = ""
    for line in client.stdout:
        line = line.strip()
        last = line
        if line.startswith("round "):
            n = int(line.split()[1])
            samples.append((n, rss_kb(client.pid), fds(client.pid), rss_kb(server.pid), fds(server.pid)))
            if n % 5000 == 0:
                print(f"soak: round {n}/{ROUNDS}, {time.time() - t0:.0f}s, client {samples[-1][1]} KB {samples[-1][2]} fds, server {samples[-1][3]} KB {samples[-1][4]} fds", flush=True)
    client.wait()
    server.terminate()
    fake.terminate()
    ok = last.startswith("done: 0 failed")
    warm = [s for s in samples if s[0] >= ROUNDS // 5 and s[1] > 0 and s[3] > 0]
    if not warm:
        sys.exit("soak: no samples past the warm-up")
    a, z = warm[0], warm[-1]

    def grew(i, name):
        good = z[i] <= a[i] * 1.2 + 4096
        print(f"  {name}: {a[i]} KB at round {a[0]}, {z[i]} KB at round {z[0]}: {'flat' if good else 'GREW'}")
        return good

    def fgrew(i, name):
        good = z[i] <= a[i] + 8
        print(f"  {name}: {a[i]} fds at round {a[0]}, {z[i]} at round {z[0]}: {'flat' if good else 'GREW'}")
        return good

    print(f"soak: {ROUNDS} rounds of 8 requests in {time.time() - t0:.0f}s, {last}")
    good = [grew(1, "client memory"), fgrew(2, "client sockets"), grew(3, "server memory"), fgrew(4, "server sockets")]
    sys.exit(0 if ok and all(good) else 1)


main()
