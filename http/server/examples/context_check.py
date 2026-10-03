"""An effect-created context survives keep-alive, streams and concurrent clients."""
import concurrent.futures
import http.client
import socket
import subprocess
import sys
import threading
import time


def main():
    with socket.socket() as preflight:
        assert preflight.connect_ex(("127.0.0.1", 8086)) != 0, "context fixture port occupied"
    process = subprocess.Popen(sys.argv[1:], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    logs, errors = [], []
    readers = [threading.Thread(target=lambda stream=stream, dest=dest: dest.extend(iter(stream.readline, "")), daemon=True)
               for stream, dest in [(process.stdout, logs), (process.stderr, errors)]]
    for reader in readers:
        reader.start()
    try:
        end = time.monotonic() + 5
        token = None
        while time.monotonic() < end:
            token = next((row.removeprefix("context:").strip() for row in logs if row.startswith("context:")), None)
            try:
                with socket.create_connection(("127.0.0.1", 8086), timeout=.2):
                    if token:
                        break
            except OSError:
                pass
            assert process.poll() is None, (process.returncode, errors)
            time.sleep(.02)
        assert token and token.isdecimal(), (logs, errors)
        connection = http.client.HTTPConnection("127.0.0.1", 8086, timeout=5)
        try:
            original = None
            for path in ["/first", "/second", "/stream", "/after-stream"]:
                connection.request("GET", path)
                response = connection.getresponse()
                assert response.status == 200
                expected = token + ":" + (token if path == "/stream" else path)
                assert response.read().decode() == expected
                if original is None:
                    original = connection.sock
                assert connection.sock is original, "context check lost keep-alive connection"
        finally:
            connection.close()

        def client(index):
            connection = http.client.HTTPConnection("127.0.0.1", 8086, timeout=5)
            try:
                path = f"/client-{index}"
                connection.request("GET", path)
                response = connection.getresponse()
                assert response.status == 200 and response.read().decode() == token + ":" + path
            finally:
                connection.close()

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(client, range(32)))
        assert process.poll() is None
    finally:
        process.terminate()
        try:
            process.wait(timeout=7)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
        for reader in readers:
            reader.join(timeout=2)
        assert process.returncode == 0, (process.returncode, errors)
    print("HTTP runtime context: whole/stream/keep-alive and 32 concurrent requests passed; graceful stop returned")


if __name__ == "__main__":
    main()
