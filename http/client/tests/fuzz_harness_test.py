"""Unrelated local HTTP probes must not consume differential corpus entries."""
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import textwrap
import threading
import unittest

from fuzz_harness import Fixture, run
import fake


class LiveFixtureTests(unittest.TestCase):
    def exchange(self, handler, target):
        server, client = socket.socketpair()
        errors = []

        def worker():
            try:
                handler(server)
            except Exception as error:
                errors.append(error)
            finally:
                server.close()

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        with client:
            client.settimeout(2)
            client.sendall(f"GET {target} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode())
            result = client.recv(4096)
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        return result

    def test_discovery_probes_do_not_consume_connection_ids(self):
        for key, handler in [("keep", fake.keep), ("each", fake.one_each)]:
            with self.subTest(key=key):
                fake.conns.clear()
                for _ in range(2):
                    self.assertTrue(self.exchange(handler, "/").startswith(b"HTTP/1.1 404 "))
                result = self.exchange(handler, "/a")
                self.assertIn(b"conn 1", result)
                self.assertEqual(fake.conns[key], 1)

    def test_discovery_probe_does_not_advance_retry_state(self):
        fake.tries.clear()
        self.assertTrue(self.exchange(fake.flaky, "/").startswith(b"HTTP/1.1 404 "))
        self.assertEqual(fake.tries, {})
        self.assertTrue(self.exchange(fake.flaky, "/2/a").startswith(b"HTTP/1.1 503 "))
        self.assertTrue(self.exchange(fake.flaky, "/2/a").startswith(b"HTTP/1.1 503 "))
        self.assertIn(b"GET after 3 tries", self.exchange(fake.flaky, "/2/a"))


class HarnessTests(unittest.TestCase):
    def client(self, directory, source):
        path = Path(directory) / "client"
        path.write_text(f"#!{sys.executable}\n" + textwrap.dedent(source))
        path.chmod(0o755)
        return str(path)

    def test_unrelated_probes_preserve_all_cases(self):
        with tempfile.TemporaryDirectory() as directory:
            client = self.client(directory, '''
                import socket, sys
                from urllib.parse import urlsplit
                url = urlsplit(sys.argv[2])
                address = (url.hostname, url.port)
                socket.create_connection(address).close()
                for host in ("127.0.0.1", "localhost"):
                    with socket.create_connection(address) as conn:
                        conn.sendall(f"GET / HTTP/1.1\\r\\nHost: {host}\\r\\nUser-Agent: Go-http-client/1.1\\r\\n\\r\\n".encode())
                        assert conn.recv(4096).startswith(b"HTTP/1.1 404 ")
                for _ in range(int(sys.argv[1])):
                    with socket.create_connection(address) as conn:
                        conn.sendall(f"GET {url.path} HTTP/1.1\\r\\nHost: test\\r\\n\\r\\n".encode())
                        data = b""
                        while part := conn.recv(4096):
                            data += part
                        print(data.decode())
            ''')

            def serve(connections, want):
                for conn in connections:
                    value = f"case {len(want)}"
                    want.append(value)
                    conn.sendall(value.encode())

            want, result = run(client, 3, serve)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(want, ["case 0", "case 1", "case 2"])
            self.assertEqual(result.stdout.splitlines(), want)

    def test_concurrent_fixtures_have_distinct_ports_and_routes(self):
        a, b = Fixture(), Fixture()
        try:
            self.assertNotEqual(a.socket.getsockname(), b.socket.getsockname())
            self.assertNotEqual(a.target, b.target)
        finally:
            a.close()
            b.close()

    def test_both_corpora_reject_output_without_served_cases(self):
        with tempfile.TemporaryDirectory() as directory:
            client = self.client(directory, '''
                print("err closed")
            ''')
            for script in ("fuzz.py", "fuzz_events.py"):
                with self.subTest(script=script):
                    result = subprocess.run(
                        [sys.executable, str(Path(__file__).with_name(script)), client, "1", "1"],
                        capture_output=True, text=True, timeout=5)
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertIn("server served 0 of 1", result.stdout)


if __name__ == "__main__":
    unittest.main()
