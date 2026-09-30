"""Two independent UDP peers exercise server authentication while a client retries."""
import select
import socket
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from stun_reference import COOKIE, attr, attributes, fingerprint, packet, sign, validate

COMMAND = sys.argv[1:]
LOCAL_KEY = b"LocalFixturePassword123456"
REMOTE_KEY = b"SyntheticPassword123456789"


def binding(transaction, role=True, tie=2, username=b"localFrag:BeforeAnswerPeer"):
    return packet(attr(6, username) + attr(0x24, struct.pack("!I", 1845494271)) +
                  attr(0x802A if role else 0x8029, struct.pack("!Q", tie)), transaction=transaction)


def mapping(address):
    host, port = address
    return attr(0x20, b"\x00\x01" + struct.pack("!H", port ^ 0x2112) +
                bytes(x ^ y for x, y in zip(socket.inet_aton(host), COOKIE)))


with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_peer, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server_peer:
    client_peer.bind(("127.0.0.1", 0))
    server_peer.bind(("127.0.0.1", 0))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserve:
        reserve.bind(("127.0.0.1", 0))
        local_port = reserve.getsockname()[1]
    destination = ("127.0.0.1", local_port)
    client_peer.settimeout(2)
    server_peer.settimeout(0.1)
    with tempfile.TemporaryDirectory() as tmp:
        output_path = Path(tmp) / "stdout"
        with output_path.open("w") as output:
            process = subprocess.Popen(COMMAND + [str(local_port), str(client_peer.getsockname()[1]), "3"],
                                       stdout=output, stderr=subprocess.PIPE, text=True)
            try:
                request, address = client_peer.recvfrom(65535)
                began = time.monotonic()
                assert address == destination
                fields = validate(request, REMOTE_KEY, "dual")
                assert [(k, v) for k, v, _ in fields[:3]] == [
                    (6, b"remoteFrag:localFrag"), (0x24, struct.pack("!I", 1845494271)),
                    (0x802A, struct.pack("!Q", 1))]
                assert request[8:20] == struct.pack("!III", 1, 2, 3)

                def exchange(raw, code=0, mode="legacy", signed=True):
                    server_peer.sendto(raw, destination)
                    response, sender = server_peer.recvfrom(65535)
                    assert sender == destination
                    assert response[8:20] == raw[8:20]
                    items = validate(response, LOCAL_KEY, mode) if signed else attributes(response)
                    assert all(k != 6 for k, _, _ in items)
                    if code:
                        assert response[:2] == b"\x01\x11"
                        error = next(v for k, v, _ in items if k == 9)
                        assert (error[2] & 7)*100 + error[3] == code
                    else:
                        assert response[:2] == b"\x01\x01"
                        assert next(v for k, v, _ in items if k == 0x20) == mapping(server_peer.getsockname())[4:]
                    if not signed:
                        assert all(k not in (8, 28) for k, _, _ in items)
                    return response

                # Dropped invalid CRC must neither reply nor change role.
                broken = sign(binding(b"\x01"*12), LOCAL_KEY, "legacy")
                server_peer.sendto(broken[:-1] + bytes([broken[-1]^1]), destination)
                try:
                    server_peer.recvfrom(65535)
                    raise AssertionError("server answered invalid fingerprint")
                except socket.timeout:
                    pass
                exchange(fingerprint(binding(b"\x02"*12)), 400, signed=False)
                exchange(sign(binding(b"\x03"*12, username=b"wrongFrag:BeforeAnswerPeer"), LOCAL_KEY, "sha256"), 401, signed=False)
                exchange(sign(binding(b"\x04"*12, tie=2), b"wrong key", "dual"), 401, signed=False)
                # If the bad-MAC request changed role, this would succeed.
                exchange(sign(binding(b"\x05"*12, tie=0), LOCAL_KEY, "legacy"), 487)
                good = sign(binding(b"\x06"*12, tie=2), LOCAL_KEY, "dual")
                first = exchange(good, mode="sha256")
                assert exchange(good, mode="sha256") == first, "retransmission changed response bytes"
                exchange(sign(binding(b"\x07"*12, role=False, tie=0), LOCAL_KEY, "sha256"), mode="sha256")

                # A valid client response from the OTHER source remains raw;
                # answering incoming traffic cannot consume/cancel the client.
                successful = sign(packet(mapping(destination), kind=0x101, transaction=request[8:20]), REMOTE_KEY, "legacy")
                server_peer.sendto(successful, destination)
                retry, sender = client_peer.recvfrom(65535)
                retried = time.monotonic()
                assert retry == request and sender == destination
                assert 0.445 <= retried - began <= 1.05, retried - began
                client_peer.sendto(successful, destination)
                _, err = process.communicate(timeout=2)
                assert process.returncode == 0, (process.returncode, err, output_path.read_text())
            finally:
                if process.poll() is None:
                    process.kill()
                process.communicate()
        lines = output_path.read_text().splitlines()
        assert "reject:400:0" in lines and lines.count("reject:401:0") == 2 and "reject:487:1" in lines, lines
        accepts = [s for s in lines if s.startswith("accept:")]
        assert accepts == [
            "accept:BeforeAnswerPeer:1845494271:controlling:0:2:0:sha256:controlled:0:1:1",
            "accept:BeforeAnswerPeer:1845494271:controlling:0:2:0:sha256:controlled:0:1:0",
            "accept:BeforeAnswerPeer:1845494271:controlled:0:0:0:sha256:controlling:0:1:1"], accepts
        assert lines.count("sent") == 2 and "outgoing:success" in lines and lines.count("ignored") == 2, lines
        assert lines[-1] == "done:3:controlling:0:1", lines[-1]
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as rebind:
        rebind.bind(destination)
print("ICE duplex: independent peer requests/errors/role switches/pre-answer responses/client retry and socket cleanup passed")
