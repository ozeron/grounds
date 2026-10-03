"""Real cookie expiry retires admitted sockets and prevents stale admissions."""
import contextlib
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import signaling_server_check as Live


@contextlib.contextmanager
def server(ttl):
    with socket.socket() as preflight:
        assert preflight.connect_ex(("127.0.0.1", 8089)) != 0, "fixture port occupied"
    process = subprocess.Popen(sys.argv[1:], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, bufsize=1, env=dict(os.environ, GROUNDS_SIGNALING_TTL_MS=str(ttl)))
    logs, errors = [], []
    readers = [threading.Thread(target=lambda stream=stream, dest=dest: dest.extend(iter(stream.readline, "")), daemon=True)
               for stream, dest in [(process.stdout, logs), (process.stderr, errors)]]
    for reader in readers:
        reader.start()
    try:
        Live.until(lambda: socket.create_connection(("127.0.0.1", 8089), timeout=0.2).close() is None)
        Live.COOKIE = Live.until(lambda: next((row.removeprefix("signaling-cookie:").strip()
                              for row in logs if row.startswith("signaling-cookie:")), None))
        yield process, logs
    finally:
        process.terminate()
        try:
            process.wait(timeout=7)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
        for reader in readers:
            reader.join(timeout=2)
        evidence = os.environ.get("GROUNDS_SIGNALING_EVIDENCE")
        if evidence:
            with Path(evidence).open("a") as output:
                output.write(f"fixture TTL {ttl}\n" + "".join(logs) + "".join(errors))
        assert process.returncode == 0, (process.returncode, errors[-10:])


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
        peer.bind(("127.0.0.1", 0))
        sdp = Live.BASE.replace("32123", str(peer.getsockname()[1]))
        started = time.monotonic()
        with server(2500) as (process, logs):
            old = Live.COOKIE
            sock, status = Live.connect()
            assert status == 101, (status, logs[-10:])
            with sock:
                answer = Live.offer(sock, 0, sdp)
                # The existing WebSocket is bounded by the issuer's deadline,
                # even though the ordinary fixture lifetime is 45 seconds.
                assert sock.recv(1) == b"", "expired session remained open"
            elapsed = time.monotonic() - started
            assert elapsed < 6, ("expiry took too long", elapsed)
            Live.until(lambda: Live.rebind(answer["port"]))
            Live.until(lambda: any(row.startswith("signaling-closed:") for row in logs))
            before = sum(row.startswith("signaling-base:") for row in logs)
            denied, status = Live.connect()
            denied.close()
            assert status == 401, ("expired cookie admitted", status)
            assert sum(row.startswith("signaling-base:") for row in logs) == before
            assert process.poll() is None
        with server(300000) as (_, logs):
            fresh = Live.COOKIE
            assert fresh != old
            Live.COOKIE = old
            denied, status = Live.connect()
            denied.close()
            assert status == 401, ("previous process cookie admitted", status)
            assert not any(row.startswith("signaling-base:") for row in logs)
            Live.COOKIE = fresh
            sock, status = Live.connect()
            assert status == 101
            with sock:
                answer = Live.offer(sock, 0, sdp)
                Live.send(sock, b"\x03\xe8", 8)
                Live.closed(sock, 1000)
            Live.until(lambda: Live.rebind(answer["port"]))
    print(f"Signed cookie lifecycle: actual expiry ({elapsed:.3f}s), socket/UDP cleanup, expired/stale denial and fresh reconnect passed")


if __name__ == "__main__":
    main()
