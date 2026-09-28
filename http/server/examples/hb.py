"""Heartbeats from sse.every, against examples/stream.

  python3 examples/hb.py BINARY PORT

Reads /hb for 300 ms and counts heartbeats, then hangs up. The heartbeat
loop must see the failed write and end: a SIGTERM then drains at once,
where a loop still running would hold the stop until drain_ms.
"""
import os
import signal
import socket
import subprocess
import sys
import time

binary, port = sys.argv[1], int(sys.argv[2])
p = subprocess.Popen([binary], env={**os.environ, "PORT": str(port), "HTTP_DRAIN_MS": "5000"}, stderr=subprocess.PIPE)
for _ in range(100):
    try:
        socket.create_connection(("127.0.0.1", port)).close()
        break
    except OSError:
        time.sleep(0.05)
s = socket.create_connection(("127.0.0.1", port))
s.sendall(b"GET /hb HTTP/1.1\r\nHost: x\r\n\r\n")
s.settimeout(0.5)
got = b""
t = time.time()
while time.time() - t < 0.3:
    try:
        got += s.recv(4096)
    except socket.timeout:
        break
s.close()
beats = got.count(b":\n\n")
time.sleep(0.3)
t0 = time.time()
p.send_signal(signal.SIGTERM)
p.wait(10)
took = time.time() - t0
err = p.stderr.read().decode().strip()
print(f"heartbeats: {beats} in 300 ms; stop after hanging up: {took:.1f}s, {err}")
sys.exit(0 if beats >= 3 and took < 2 and "every connection done" in err else 1)
