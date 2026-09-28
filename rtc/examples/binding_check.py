"""Exercise a Bend STUN Binding client against a separate UDP responder."""

import socket
import struct
import subprocess
import sys


command = sys.argv[1:]
cookie = bytes.fromhex("2112a442")
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind(("127.0.0.1", 47835))
server.settimeout(3)
seen = []

for _ in range(2):
    client = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    request, address = server.recvfrom(65535)
    assert len(request) == 20 and request[:8] == bytes.fromhex("000100002112a442"), request.hex()
    transaction = request[8:20]
    seen.append(transaction)
    host, port = address
    mapped = b"\x00\x01" + struct.pack("!H", port ^ 0x2112)
    mapped += bytes(a ^ b for a, b in zip(socket.inet_aton(host), cookie))
    response = bytes.fromhex("0101000c") + cookie + transaction + bytes.fromhex("00200008") + mapped
    server.sendto(response, address)
    stdout, stderr = client.communicate(timeout=3)
    assert client.returncode == 0 and stdout.strip() == f"{host}:{port}", (stdout, stderr, address)

assert seen[0] != seen[1], "transaction IDs did not change"

for attack in ("wrong transaction", "wrong source"):
    client = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    request, address = server.recvfrom(65535)
    transaction = request[8:20]
    if attack == "wrong transaction":
        transaction = bytes([transaction[0] ^ 1]) + transaction[1:]
    host, port = address
    mapped = b"\x00\x01" + struct.pack("!H", port ^ 0x2112)
    mapped += bytes(a ^ b for a, b in zip(socket.inet_aton(host), cookie))
    response = bytes.fromhex("0101000c") + cookie + transaction + bytes.fromhex("00200008") + mapped
    if attack == "wrong source":
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as other:
            other.bind(("127.0.0.1", 0))
            other.sendto(response, address)
    else:
        server.sendto(response, address)
    stdout, stderr = client.communicate(timeout=3)
    assert client.returncode != 0 and "missing or invalid" in stderr, (attack, stdout, stderr)

server.close()
print("STUN: two randomized UDP Binding exchanges; wrong transaction and source rejected")
