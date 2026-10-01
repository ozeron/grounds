"""Independent local-OS helpers for UDP address fixtures on Darwin and Linux."""
import ctypes
import socket
import subprocess
import sys
from pathlib import Path


def interface_ipv4s():
    class Entry(ctypes.Structure):
        pass

    Entry._fields_ = [("next", ctypes.POINTER(Entry)), ("name", ctypes.c_char_p),
                     ("flags", ctypes.c_uint), ("addr", ctypes.c_void_p),
                     ("mask", ctypes.c_void_p), ("dst", ctypes.c_void_p), ("data", ctypes.c_void_p)]
    lib = ctypes.CDLL(None)
    lib.getifaddrs.argtypes = [ctypes.POINTER(ctypes.POINTER(Entry))]
    lib.getifaddrs.restype = ctypes.c_int
    lib.freeifaddrs.argtypes = [ctypes.POINTER(Entry)]
    head = ctypes.POINTER(Entry)()
    assert lib.getifaddrs(ctypes.byref(head)) == 0, "getifaddrs failed"
    hosts = set()
    try:
        current = head
        while current:
            value = current.contents
            if value.addr and value.flags & 1:
                raw = ctypes.string_at(value.addr, 16)
                family = raw[1] if sys.platform == "darwin" else int.from_bytes(raw[:2], sys.byteorder)
                if family == socket.AF_INET:
                    hosts.add(socket.inet_ntoa(raw[4:8]))
            current = value.next
    finally:
        lib.freeifaddrs(head)
    return sorted(hosts)


def local_udp_roundtrip(host):
    """A bindable VPN/tunnel address may not route to a loopback peer."""
    payload = b"grounds-local-udp-address-probe"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as target, \
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
            target.bind((host, 0))
            peer.bind(("127.0.0.1", 0))
            target.settimeout(0.25)
            peer.settimeout(0.25)
            peer.sendto(payload, target.getsockname())
            received, source = target.recvfrom(128)
            if received != payload or source != peer.getsockname():
                return False
            target.sendto(received, source)
            return peer.recvfrom(128) == (payload, target.getsockname())
    except OSError:
        return False


def second_local_ipv4():
    for host in ["127.0.0.2"] + interface_ipv4s():
        if host in ("127.0.0.1", "0.0.0.0"):
            continue
        if local_udp_roundtrip(host):
            return host
    raise RuntimeError("UDP address proof requires a second locally reachable IPv4 address")


def udp_fd_count(pid):
    if sys.platform == "linux":
        inodes = {s[8:-1] for p in Path(f"/proc/{pid}/fd").iterdir()
                  if (s := p.readlink().as_posix()).startswith("socket:[")}
        tables = (Path(f"/proc/{pid}/net/udp"), Path(f"/proc/{pid}/net/udp6"))
        return sum(line.split()[9] in inodes for p in tables for line in p.read_text().splitlines()[1:])
    result = subprocess.run(["lsof", "-a", "-p", str(pid), "-iUDP", "-Ff"],
                            capture_output=True, text=True, timeout=3)
    assert result.returncode == 0, result.stderr
    return sum(line.startswith("f") for line in result.stdout.splitlines())
