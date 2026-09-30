"""Authenticated Bend UDP transactions with a separate stdlib Python responder."""

import socket
import struct
import subprocess
import sys
import time

from stun_reference import COOKIE, attr, fingerprint, length, packet, sign, validate

command = sys.argv[1:]
KEY = b"SyntheticPassword123456789"
seen = []
count = 0


def mapped(host, port):
    value = b"\x00\x01" + struct.pack("!H", port ^ 0x2112)
    return attr(0x20, value + bytes(a ^ b for a, b in zip(socket.inet_aton(host), COOKIE)))


def check_request(request, mode, role):
    assert request[:2] == b"\x00\x01"
    items = validate(request, KEY, mode)
    fields = [(kind, value) for kind, value, _ in items[:3]]
    role_kind = 0x802A if role == "controlling" else 0x8029
    assert fields == [(6, b"remoteFrag:localFrag"), (0x24, struct.pack("!I", 1845494271)),
                      (role_kind, bytes.fromhex("fedcba9876543210"))], fields
    seen.append(request[8:20])


def corrupt(response, attack, key, mode):
    # Every invalid response carries a different address, so premature
    # acceptance cannot masquerade as success with the subsequent valid one.
    if attack == "deadline":
        return corrupt(response, "bad MAC", key, mode)
    if attack == "wrong transaction":
        return sign(packet(response[20:], kind=0x101, transaction=b"\xff" * 12), key, mode)
    if attack == "missing integrity":
        return fingerprint(response)
    if attack == "wrong key":
        return sign(response, b"wrong password", mode)
    if attack == "bad MAC":
        raw = bytearray(sign(response, key, mode, with_fingerprint=False))
        raw[-1] ^= 1
        return fingerprint(raw)
    if attack == "missing fingerprint":
        return sign(response, key, mode, with_fingerprint=False)
    if attack == "bad fingerprint":
        raw = bytearray(sign(response, key, mode))
        raw[-1] ^= 1
        return bytes(raw)
    if attack == "unsigned mapped address":
        raw = sign(packet(kind=0x101, transaction=response[8:20]), key, mode, with_fingerprint=False)
        return fingerprint(length(raw + response[20:], len(raw) - 20 + len(response) - 20))
    if attack == "wrong algorithm":
        return sign(response, key, "legacy")
    if attack == "dual response":
        return sign(response, key, "dual")
    if attack == "response username":
        return sign(packet(response[20:] + attr(6, b"remoteFrag:localFrag"), kind=0x101,
                           transaction=response[8:20]), key, mode)
    if attack == "wrong class":
        return sign(packet(response[20:], kind=1, transaction=response[8:20]), key, mode)
    if attack == "error response":
        return sign(packet(response[20:], kind=0x111, transaction=response[8:20]), key, mode)
    if attack == "malformed":
        raw = bytearray(sign(response, key, mode))
        raw[3] ^= 4
        return bytes(raw)
    if attack == "bad mapped value":
        return sign(packet(attr(0x20, b"\x00\x01"), kind=0x101,
                           transaction=response[8:20]), key, mode)
    return sign(response, key, mode)


with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
    server.bind(("127.0.0.1", 0))
    server.settimeout(5)
    port = str(server.getsockname()[1])

    def exchange(mode="dual", role="controlling", response_mode=None, attack=None, recover=False):
        global count
        process = subprocess.Popen(command + [port, mode, role], stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True)
        try:
            request, address = server.recvfrom(65535)
            check_request(request, mode, role)
            transaction = request[8:20]
            chosen = response_mode or ("sha256" if mode == "dual" else mode)
            good = sign(packet(mapped(*address), kind=0x101, transaction=transaction), KEY, chosen)
            if attack:
                bad = corrupt(packet(mapped("203.0.113.9", 9), kind=0x101, transaction=transaction), attack, KEY, chosen)
                if attack == "wrong source":
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as other:
                        other.sendto(bad, address)
                elif attack == "deadline":
                    start = time.monotonic()
                    while process.poll() is None and time.monotonic() - start < 0.8:
                        server.sendto(bad, address)
                        time.sleep(0.03)
                    assert time.monotonic() - start < 0.6, "invalid traffic reset the deadline"
                else:
                    server.sendto(bad, address)
                if recover:
                    time.sleep(0.015)
                    server.sendto(good, address)
            else:
                server.sendto(good, address)
            stdout, stderr = process.communicate(timeout=5)
            count += 1
            if attack and not recover:
                assert process.returncode == 1 and "missing or invalid" in stderr, (attack, stdout, stderr)
            else:
                assert process.returncode == 0 and stdout.strip() == f"{address[0]}:{address[1]}", (attack, stdout, stderr)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()

    for mode in ("legacy", "sha256", "dual"):
        for role in ("controlling", "controlled"):
            exchange(mode=mode, role=role)
    exchange(response_mode="legacy")  # dual request accepts a legacy-only peer
    for attack in ("wrong source", "wrong transaction", "missing integrity", "wrong key", "bad MAC",
                   "missing fingerprint", "bad fingerprint", "unsigned mapped address", "wrong algorithm",
                   "dual response", "response username", "wrong class", "error response", "malformed",
                   "bad mapped value", "deadline"):
        exchange(mode="sha256", attack=attack)
    for attack in ("wrong source", "wrong transaction", "missing integrity", "bad MAC", "bad fingerprint", "malformed"):
        exchange(attack=attack, recover=True)

    # The caller-owned socket survives two authenticated exchanges.
    process = subprocess.Popen(command + [port, "reuse", "controlling"], stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True)
    addresses = []
    try:
        for role in ("controlling", "controlled"):
            request, address = server.recvfrom(65535)
            check_request(request, "dual", role)
            addresses.append(address)
            server.sendto(sign(packet(mapped(*address), kind=0x101, transaction=request[8:20]), KEY, "sha256"), address)
        stdout, stderr = process.communicate(timeout=5)
        assert process.returncode == 0 and addresses[0] == addresses[1], (stdout, stderr, addresses)
        assert stdout.splitlines() == [f"{host}:{port}" for host, port in addresses]
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate()

assert len(set(seen)) == len(seen), "transaction IDs reused"
print(f"Authenticated UDP: {count} exchanges/rejections/recoveries; deadline and socket reuse passed")
