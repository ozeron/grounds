"""Exercise the auth middleware through a live HTTP server."""

import http.client
import socket
import subprocess
import sys
import time


def request(fields=()):
    conn = http.client.HTTPConnection("127.0.0.1", 8092, timeout=2)
    conn.putrequest("GET", "/private")
    for name, value in fields:
        conn.putheader(name, value)
    conn.endheaders()
    res = conn.getresponse()
    status, body, headers = res.status, res.read().decode(), res.getheaders()
    conn.close()
    return status, body, [value for name, value in headers if name.lower() == "www-authenticate"]


server = subprocess.Popen([sys.argv[1]], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
try:
    for _ in range(100):
        try:
            with socket.create_connection(("127.0.0.1", 8092), timeout=0.1):
                break
        except OSError:
            time.sleep(0.05)
    else:
        raise AssertionError("auth server did not start")

    assert request() == (
        401,
        "Unauthorized",
        ['Bearer realm="grounds"', 'Basic realm="grounds", charset="UTF-8"'],
    )
    assert request([("Authorization", "bEaReR good-token")]) == (
        200, "bearer-user; authorization=absent", []
    )
    assert request([("Authorization", "Basic dGVzdDoxMjPCow==")]) == (
        200, "basic-user; authorization=absent", []
    )
    assert request([("Authorization", "Bearer wrong")]) == (
        401, "Unauthorized", ['Bearer realm="grounds", error="invalid_token"']
    )
    assert request([("Authorization", "Bearer bad?")]) == (
        400, "Bad Request", ['Bearer realm="grounds", error="invalid_request"']
    )
    assert request([("Authorization", "Basic bad!")]) == (
        401, "Unauthorized", ['Basic realm="grounds", charset="UTF-8"']
    )
    assert request([("Authorization", "Digest token")]) == (
        401,
        "Unauthorized",
        ['Bearer realm="grounds"', 'Basic realm="grounds", charset="UTF-8"'],
    )
    assert request([("Authorization", "Bearer good-token"), ("Authorization", "Bearer good-token")]) == (
        400, "Bad Request", ['Bearer realm="grounds", error="invalid_request"']
    )
    print("auth: Bearer and Basic success, 401 challenges, malformed and duplicate rejection")
finally:
    server.terminate()
    try:
        server.wait(timeout=3)
    except subprocess.TimeoutExpired:
        server.kill()
        server.wait(timeout=3)
