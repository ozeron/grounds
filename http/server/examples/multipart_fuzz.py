"""Compare Bend multipart parsing with Python's email parser over live HTTP."""

import argparse
from email import policy
from email.parser import BytesParser
import http.client
import random
import socket
import subprocess
import time


def python_parts(content_type, body):
    message = BytesParser(policy=policy.default).parsebytes(
        b"MIME-Version: 1.0\r\nContent-Type: "
        + content_type.encode()
        + b"\r\n\r\n"
        + body
    )
    if not message.is_multipart():
        return []
    return [
        (
            part.get_param("name", header="content-disposition"),
            part.get_filename(),
            part.get("Content-Type"),
            part.get_payload(decode=True),
        )
        for part in message.iter_parts()
    ]


def bend_parts(content_type, body):
    conn = http.client.HTTPConnection("127.0.0.1", 8095, timeout=3)
    conn.request("POST", "/", body, {"Content-Type": content_type})
    res = conn.getresponse()
    status, text = res.status, res.read().decode()
    conn.close()
    if status != 200:
        return status, text
    parts = []
    for line in text.splitlines()[1:]:
        tag, name, filename, kind, hex_body = line.split(" ", 4)
        assert tag == "P"
        parts.append((name, None if filename == "-" else filename, None if kind == "-" else kind, bytes.fromhex(hex_body)))
    return status, parts


def encode(boundary, parts):
    out = bytearray()
    for name, filename, kind, body in parts:
        out += b"--" + boundary.encode() + b"\r\n"
        out += b'Content-Disposition: form-data; name="' + name.encode() + b'"'
        if filename is not None:
            out += b'; filename="' + filename.encode() + b'"'
        out += b"\r\n"
        if kind is not None:
            out += b"Content-Type: " + kind.encode() + b"\r\n"
        out += b"\r\n" + body + b"\r\n"
    out += b"--" + boundary.encode() + b"--\r\n"
    return bytes(out)


def run(executable, count, seed, client=None):
    rng = random.Random(seed)
    server = subprocess.Popen([executable], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        for _ in range(100):
            try:
                with socket.create_connection(("127.0.0.1", 8095), timeout=0.1):
                    break
            except OSError:
                time.sleep(0.05)
        else:
            raise AssertionError("multipart server did not start")

        for index in range(count):
            boundary = "b" + "".join(rng.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=18))
            parts = []
            for part_index in range(rng.randrange(6)):
                name = f"field{part_index}"
                filename = f"file{part_index}.bin" if rng.randrange(2) else None
                kind = "application/octet-stream" if filename and rng.randrange(2) else None
                body = rng.randbytes(rng.randrange(81))
                if index % 17 == 0:
                    body += b"\r\n--" + boundary.encode() + b"X"
                parts.append((name, filename, kind, body))
            body = encode(boundary, parts)
            content_type = (
                f'multipart/form-data; boundary="{boundary}"'
                if index % 2 else f"multipart/form-data; boundary={boundary}"
            )
            expected = python_parts(content_type, body)
            assert not parts or expected, (index, "Python did not recognize a nonempty multipart message")
            got = bend_parts(content_type, body)
            assert got == (200, expected), (index, parts, got, expected)

        boundary = "limitcheck"
        too_many = encode(boundary, [(f"p{i}", None, None, b"x") for i in range(11)])
        assert bend_parts(f"multipart/form-data; boundary={boundary}", too_many) == (400, "TooManyParts")
        too_long = encode(boundary, [("x" * 2100, None, None, b"x")])
        assert bend_parts(f"multipart/form-data; boundary={boundary}", too_long) == (400, "HeadersTooLarge")
        extra = encode(boundary, [("x", None, None, b"x")]).replace(
            b"\r\n\r\n", b"\r\n" + b"X-A: v\r\n" * 8 + b"\r\n", 1
        )
        assert bend_parts(f"multipart/form-data; boundary={boundary}", extra) == (400, "TooManyHeaders")
        print(f"multipart: {count} Python email differential cases, seed {seed}; part and header limits")
        if client:
            got = subprocess.check_output([client], text=True, timeout=10)
            expected = "OK\nP blob data.bin application/octet-stream 00FF0D0A41\n\n"
            assert got == expected, (got, expected)
            print("multipart: client builder sent a binary file part over HTTP")
    finally:
        server.terminate()
        try:
            server.wait(timeout=3)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=3)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("executable")
    parser.add_argument("--count", type=int, default=200)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--client")
    args = parser.parse_args()
    run(args.executable, args.count, args.seed, args.client)
