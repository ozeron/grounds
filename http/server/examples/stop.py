"""SIGTERM with an idle and a slow connection open, against examples/stream.

  python3 examples/stop.py BINARY PORT DRAIN_MS
"""
import socket, subprocess, sys, time, threading, os, signal
port = int(sys.argv[2])
p = subprocess.Popen([sys.argv[1]], env={**os.environ, "PORT": str(port), "HTTP_DRAIN_MS": sys.argv[3]}, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
for _ in range(100):
    try:
        socket.create_connection(("127.0.0.1", port)).close(); break
    except OSError:
        time.sleep(0.05)
idle = socket.create_connection(("127.0.0.1", port))
idle.sendall(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n"); idle.recv(4096)
slow = socket.create_connection(("127.0.0.1", port))
slow.sendall(b"GET /slow HTTP/1.1\r\nHost: x\r\n\r\n")
time.sleep(0.3)
t0 = time.time()
p.send_signal(signal.SIGTERM)
time.sleep(0.5)
idle.settimeout(2)
print("idle closed:", idle.recv(4096) == b"")
try:
    socket.create_connection(("127.0.0.1", port), timeout=1).close(); print("new connection: accepted (bad)")
except OSError:
    print("new connection: refused")
slow.settimeout(5)
got = b""
while True:
    c = slow.recv(4096)
    if not c: break
    got += c
print("slow answered:", b"slow done" in got, "| connection: close:", b"connection: close" in got)
p.wait(10)
print("exit", p.returncode, "after %.1fs" % (time.time() - t0), "|", p.stderr.read().decode().strip())
