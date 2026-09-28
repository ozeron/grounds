"""Exercise the Bend TLS server with two verified Python TLS clients."""

import socket
import ssl
import sys

ctx = ssl.create_default_context(cafile=sys.argv[1])
ctx.set_alpn_protocols(["http/1.1"])

for sent in (b"first", b"second"):
    with socket.create_connection(("127.0.0.1", 7203), timeout=3) as raw:
        with ctx.wrap_socket(raw, server_hostname="localhost") as conn:
            assert conn.selected_alpn_protocol() == "http/1.1"
            conn.sendall(sent)
            assert conn.recv(4096) == b"hello over tls"
