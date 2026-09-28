"""Check CORS actual and preflight responses from a live server."""

import http.client
import socket
import subprocess
import sys
import time


def request(method="GET", fields=()):
    conn = http.client.HTTPConnection("127.0.0.1", 8093, timeout=2)
    conn.putrequest(method, "/resource")
    for name, value in fields:
        conn.putheader(name, value)
    conn.endheaders()
    res = conn.getresponse()
    status, body, headers = res.status, res.read().decode(), res.getheaders()
    conn.close()

    def all_headers(name):
        return [value for key, value in headers if key.lower() == name]

    return status, body, all_headers


server = subprocess.Popen([sys.argv[1]], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
try:
    for _ in range(100):
        try:
            with socket.create_connection(("127.0.0.1", 8093), timeout=0.1):
                break
        except OSError:
            time.sleep(0.05)
    else:
        raise AssertionError("CORS server did not start")

    status, body, headers = request()
    assert (status, body) == (200, "app")
    assert headers("vary") == ["Origin"]
    assert headers("access-control-allow-origin") == []

    status, body, headers = request(fields=[("Origin", "https://app.example")])
    assert (status, body) == (200, "app")
    assert headers("access-control-allow-origin") == ["https://app.example"]
    assert headers("access-control-allow-credentials") == ["true"]
    assert headers("vary") == ["Origin"]

    status, _, headers = request(fields=[("Origin", "https://wrong.example")])
    assert status == 200
    assert headers("access-control-allow-origin") == []
    assert headers("access-control-allow-credentials") == []

    status, body, headers = request("OPTIONS", [
        ("Origin", "https://app.example"),
        ("Access-Control-Request-Method", "POST"),
        ("Access-Control-Request-Headers", "X-Token, Content-Type"),
    ])
    assert (status, body) == (204, "")
    assert headers("access-control-allow-origin") == ["https://app.example"]
    assert headers("access-control-allow-credentials") == ["true"]
    assert headers("access-control-allow-methods") == ["POST"]
    assert headers("access-control-allow-headers") == ["x-token, content-type"]
    assert headers("access-control-max-age") == ["600"]
    assert headers("vary") == ["Origin", "Access-Control-Request-Method, Access-Control-Request-Headers"]

    for extra in (
        [("Access-Control-Request-Method", "DELETE")],
        [("Access-Control-Request-Method", "POST"), ("Access-Control-Request-Headers", "X-Secret")],
        [("Access-Control-Request-Method", "POST"), ("Access-Control-Request-Headers", "X-Token, X-Secret")],
    ):
        status, _, headers = request("OPTIONS", [("Origin", "https://app.example"), *extra])
        assert status == 403
        assert headers("access-control-allow-origin") == []

    status, _, headers = request("OPTIONS", [
        ("Origin", "https://wrong.example"),
        ("Access-Control-Request-Method", "POST"),
    ])
    assert status == 403
    assert headers("access-control-allow-origin") == []

    status, _, headers = request(fields=[
        ("Origin", "https://app.example"), ("Origin", "https://wrong.example")
    ])
    assert status == 200
    assert headers("access-control-allow-origin") == []
    print("cors: exact origin, credentials, Vary, 204 preflight, denied methods and headers")
finally:
    server.terminate()
    try:
        server.wait(timeout=3)
    except subprocess.TimeoutExpired:
        server.kill()
        server.wait(timeout=3)
