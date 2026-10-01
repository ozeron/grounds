"""Real HTTP/WS admissions, restart ownership and actual UDP cleanup checks."""
import base64
import hashlib
import json
import socket
import struct
import subprocess
import sys
import threading
import time

from sdp_check import BASE, PWD

HOST = "127.0.0.1:8089"
ORIGIN = "http://" + HOST
COOKIE = "grounds-fixture=local-synthetic-session"
KEY = base64.b64encode(b"GroundsFixture16").decode()


def until(run, seconds=5):
    end = time.monotonic() + seconds
    last = None
    while time.monotonic() < end:
        try:
            value = run()
            if value:
                return value
        except (OSError, AssertionError) as error:
            last = error
        time.sleep(0.02)
    raise AssertionError(f"deadline: {last}")


def exact(sock, size):
    result = b""
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        assert chunk, "socket closed early"
        result += chunk
    return result


def connect(headers=None):
    sock = socket.create_connection(("127.0.0.1", 8089), timeout=5)
    fields = headers if headers is not None else [("Host", HOST), ("Origin", ORIGIN), ("Cookie", COOKIE)]
    request = "GET /signal HTTP/1.1\r\n" + "".join(f"{key}: {value}\r\n" for key, value in fields)
    request += f"Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {KEY}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    sock.sendall(request.encode())
    response = b""
    while not response.endswith(b"\r\n\r\n"):
        response += exact(sock, 1)
        assert len(response) <= 8192
    status = int(response.split(b" ", 2)[1])
    if status == 101:
        expected = base64.b64encode(hashlib.sha1((KEY + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest())
        assert b"Sec-WebSocket-Accept: " + expected in response
    return sock, status


def send(sock, value, op=1, fin=True):
    payload = value if isinstance(value, bytes) else json.dumps(value).encode()
    head = bytes([(128 if fin else 0) | op])
    size = len(payload)
    if size < 126:
        head += bytes([128 | size])
    elif size <= 65535:
        head += b"\xfe" + struct.pack("!H", size)
    else:
        head += b"\xff" + struct.pack("!Q", size)
    mask = b"\x19\x26\x73\x85"
    sock.sendall(head + mask + bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload)))


def receive(sock):
    first, second = exact(sock, 2)
    assert first & 128 and not second & 128
    size = second & 127
    if size == 126:
        size = struct.unpack("!H", exact(sock, 2))[0]
    elif size == 127:
        size = struct.unpack("!Q", exact(sock, 8))[0]
    assert size <= 32768
    return first & 15, exact(sock, size)


def offer(sock, revision, sdp=BASE):
    send(sock, ["offer", revision, sdp])
    op, body = receive(sock)
    assert op == 1, (op, body)
    value = json.loads(body)
    assert value[0] == "answer" and len(value) == 2
    rows = value[1].splitlines()
    answer = {row.split(":", 1)[0]: row.split(":", 1)[1] for row in rows if ":" in row}
    answer["port"] = int(next(row for row in rows if row.startswith("a=candidate:")).split()[5])
    return answer


def closed(sock, code):
    op, payload = receive(sock)
    assert op == 8 and payload[:2] == struct.pack("!H", code), (op, payload, code)


def rebind(port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.bind(("127.0.0.1", port))
    return True


def main():
    # A disposable peer owns every candidate endpoint used in this test.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
        peer.bind(("127.0.0.1", 0))
        sdp = BASE.replace("32123", str(peer.getsockname()[1]))
        with socket.socket() as preflight:
            assert preflight.connect_ex(("127.0.0.1", 8089)) != 0, "fixture port occupied"
        process = subprocess.Popen(sys.argv[1:], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        logs, errors = [], []
        readers = [threading.Thread(target=lambda stream=stream, dest=dest: dest.extend(iter(stream.readline, "")), daemon=True)
                   for stream, dest in [(process.stdout, logs), (process.stderr, errors)]]
        for reader in readers:
            reader.start()
        scenarios = 0
        try:
            until(lambda: socket.create_connection(("127.0.0.1", 8089), timeout=0.2).close() is None)
            for name, fields, status in [
                ("missing Origin", [("Host", HOST), ("Cookie", COOKIE)], 403),
                ("wrong Origin", [("Host", HOST), ("Origin", "http://denied.invalid"), ("Cookie", COOKIE)], 403),
                ("opaque Origin", [("Host", HOST), ("Origin", "null"), ("Cookie", COOKIE)], 403),
                ("duplicate Origin", [("Host", HOST), ("Origin", ORIGIN), ("Origin", ORIGIN), ("Cookie", COOKIE)], 403),
                ("missing auth", [("Host", HOST), ("Origin", ORIGIN)], 401),
                ("wrong auth", [("Host", HOST), ("Origin", ORIGIN), ("Cookie", "grounds-fixture=wrong")], 401),
                ("duplicate auth", [("Host", HOST), ("Origin", ORIGIN), ("Cookie", COOKIE), ("Cookie", COOKIE)], 401),
                ("wrong Host", [("Host", "localhost:8089"), ("Origin", ORIGIN), ("Cookie", COOKIE)], 400),
            ]:
                before = sum(row.startswith("signaling-base:") for row in logs)
                sock, actual = connect(fields)
                sock.close()
                assert actual == status, (name, actual, status)
                assert sum(row.startswith("signaling-base:") for row in logs) == before, (name, "unauthorized UDP allocation")
                scenarios += 1

            for name, payload, op, fin, code in [
                ("object message", {"offer": sdp}, 1, True, 1008),
                ("bad JSON", b"[", 1, True, 1008),
                ("negative revision", ["offer", -1, sdp], 1, True, 1008),
                ("stale initial revision", ["offer", 1, sdp], 1, True, 1008),
                ("malformed candidate", ["offer", 0, sdp.replace("2130706431", "4294967296")], 1, True, 1008),
                ("binary", b"binary", 2, True, 1003),
                ("unsupported fragmentation", b"[", 1, False, 1003),
                ("invalid UTF8", b"\xff", 1, True, 1007),
                ("invalid close payload", b"\x00", 8, True, 1002),
                ("oversized message", b"x" * 33000, 1, True, 1009),
            ]:
                sock, status = connect()
                assert status == 101, (name, status, logs[-8:], errors[-8:])
                with sock:
                    send(sock, payload, op, fin)
                    closed(sock, code)
                until(lambda: sum(row.startswith("signaling-base:") for row in logs) == sum(row.startswith("signaling-closed:") for row in logs))
                scenarios += 1

            previous_credentials = set()
            for cycle in range(2):
                sock, status = connect()
                assert status == 101
                with sock:
                    first = offer(sock, 0, sdp)
                    pair = (first["a=ice-ufrag"], first["a=ice-pwd"])
                    assert pair not in previous_credentials
                    previous_credentials.add(pair)
                    assert len(pair[0]) == 16 and len(pair[1]) == 32
                    port = first["port"]
                    next_sdp = sdp.replace("abcd", "newFrag").replace(PWD, "NewSyntheticPassword123456")
                    second = offer(sock, 1, next_sdp)
                    assert second["port"] == port
                    assert second["a=ice-ufrag"] != pair[0] and second["a=ice-pwd"] != pair[1]
                    send(sock, b"\x03\xe8", 8)
                    closed(sock, 1000)
                until(lambda: f"signaling-closed:{port}\n" in logs)
                until(lambda: rebind(port))
                scenarios += 1

            for name, revision, next_sdp in [
                ("revision replay", 0, sdp),
                ("unchanged restart", 1, sdp),
                ("password-only restart", 1, sdp.replace(PWD, "NewSyntheticPassword123456")),
                ("ufrag-only restart", 1, sdp.replace("abcd", "newFrag")),
                ("fingerprint changed", 1, sdp.replace("abcd", "newFrag").replace(PWD, "NewSyntheticPassword123456").replace("00:01", "FF:01")),
            ]:
                sock, status = connect()
                assert status == 101
                with sock:
                    first = offer(sock, 0, sdp)
                    send(sock, ["offer", revision, next_sdp])
                    closed(sock, 1008)
                until(lambda: rebind(first["port"]))
                scenarios += 1
            sock, status = connect()
            assert status == 101
            with sock:
                first = offer(sock, 0, sdp)
                for revision in range(1, 8):
                    next_sdp = sdp.replace("abcd", f"frag{revision}").replace(PWD, f"SyntheticRoundPassword000{revision}")
                    answer = offer(sock, revision, next_sdp)
                    assert answer["port"] == first["port"]
                send(sock, ["offer", 8, sdp.replace("abcd", "frag8").replace(PWD, "SyntheticRoundPassword0008")])
                closed(sock, 1008)
            until(lambda: rebind(first["port"]))
            scenarios += 1
            sock, status = connect()
            assert status == 101
            with sock:
                first = offer(sock, 0, sdp)
                offer(sock, 1, sdp.replace("abcd", "frag1").replace(PWD, "SyntheticRoundPassword0001"))
                send(sock, ["offer", 2, sdp])
                closed(sock, 1008)
            until(lambda: rebind(first["port"]))
            scenarios += 1
            until(lambda: sum(row.startswith("signaling-base:") for row in logs) == sum(row.startswith("signaling-closed:") for row in logs))
            pool = []
            try:
                for _ in range(8):
                    sock, status = connect()
                    assert status == 101, status
                    pool.append(sock)
                ninth, status = connect()
                ninth.close()
                assert status == 503, ("connection cap", status)
                for sock in pool:
                    send(sock, b"\x03\xe8", 8)
                    closed(sock, 1000)
            finally:
                for sock in pool:
                    sock.close()
            until(lambda: sum(row.startswith("signaling-base:") for row in logs) == sum(row.startswith("signaling-closed:") for row in logs))
            scenarios += 1
            assert process.poll() is None, (process.poll(), errors)
            print(f"Signaling: {scenarios} actual HTTP/WS auth, Origin, malformed, restart, reconnect and UDP cleanup scenarios passed")
        finally:
            evidence = __import__("os").environ.get("GROUNDS_SIGNALING_EVIDENCE")
            if evidence:
                from pathlib import Path
                Path(evidence).write_text("".join(logs))
            process.terminate()
            try:
                process.wait(timeout=7)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
            for reader in readers:
                reader.join(timeout=2)
            if process.returncode not in (0, -15):
                raise AssertionError((process.returncode, "".join(errors)[-2000:]))


if __name__ == "__main__":
    main()
