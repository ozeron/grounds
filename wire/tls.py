"""A TLS server on 7202 for tls.bend: answers each connection "hello over tls".

  python3 tls.py DIR     # writes DIR/cert.pem and DIR/key.pem, a self-signed
                         # certificate for localhost; prints "ready"
"""
import os
import socket
import ssl
import subprocess
import sys
import threading

d = sys.argv[1]
cert, key = os.path.join(d, "cert.pem"), os.path.join(d, "key.pem")
subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert,
                "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"],
               check=True, capture_output=True)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cert, key)
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 7202))
s.listen(16)
print("ready", flush=True)


def serve(c):
    try:
        t = ctx.wrap_socket(c, server_side=True)
        t.recv(4096)
        t.sendall(b"hello over tls")
        t.unwrap()
    except (OSError, ssl.SSLError):
        pass
    c.close()


while True:
    c, _ = s.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
