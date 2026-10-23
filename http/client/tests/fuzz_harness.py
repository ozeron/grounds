"""Run-local socket ownership for the HTTP and SSE differential corpora."""
import secrets
import socket
import subprocess
import threading
import traceback


class Fixture:
    def __init__(self):
        self.socket = socket.socket()
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen(16)
        self.socket.settimeout(0.1)
        self.target = "/" + secrets.token_hex(16)
        self.url = f"http://127.0.0.1:{self.socket.getsockname()[1]}{self.target}"
        self.stopped = threading.Event()

    def connections(self, count):
        served = 0
        while served < count and not self.stopped.is_set():
            try:
                conn, _ = self.socket.accept()
            except socket.timeout:
                continue
            with conn:
                conn.settimeout(10)
                try:
                    head = b""
                    while b"\r\n\r\n" not in head and len(head) <= 16384:
                        more = conn.recv(65536)
                        if not more:
                            break
                        head += more
                    if (b"\r\n\r\n" not in head or
                            head.split(b"\r\n", 1)[0] !=
                            f"GET {self.target} HTTP/1.1".encode()):
                        conn.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                        continue
                except OSError:
                    continue
                # Only the run's requests advance the corpus or its RNG.
                served += 1
                yield conn

    def close(self):
        self.stopped.set()
        self.socket.close()


def run(binary, count, serve):
    fixture = Fixture()
    want, errors = [], []

    def worker():
        try:
            serve(fixture.connections(count), want)
        except Exception as error:
            errors.append(error)
            traceback.print_exc()

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    try:
        result = subprocess.run([binary, str(count), fixture.url],
                                capture_output=True, text=True, timeout=110)
    except subprocess.TimeoutExpired:
        if errors:
            raise errors[0]
        raise
    finally:
        fixture.stopped.set()
        thread.join(10)
        fixture.close()
    if thread.is_alive():
        raise RuntimeError("differential server did not stop")
    if errors:
        raise errors[0]
    return want, result
