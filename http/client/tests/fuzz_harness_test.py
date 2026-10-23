"""Unrelated local HTTP probes must not consume differential corpus entries."""
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import textwrap
import unittest

from fuzz_harness import Fixture, run


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
