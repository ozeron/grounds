"""Independent stdlib STUN encoder/validator for the Bend interoperability checks."""

import hashlib
import hmac
import struct
import zlib

COOKIE = bytes.fromhex("2112a442")
RFC_KEY = hashlib.sha256("マトリックス:example.org:TheMatrIX".encode()).digest()
# RFC 8489 B.1, with verified erratum 6268 (length/password algorithm/MAC).
RFC_SHA256 = bytes.fromhex(
    "000100902112a44278ad3433c6ad72c029da412e"
    "001e00204a3cf38fef6992bda952c6780417da0f24819415569e60b205c46e41407f1704"
    "001500296f624d61744a6f733241414143662f2f3439396b39353464364f4c33346f4c39"
    "4653547679363473410000000014000b6578616d706c652e6f726700"
    "001d000400020000001c0020"
    "b5c7bf005b6c52a21c51c5e892f81924136296cb927c43149309278cc6518e65"
)


def attr(kind, value, pad=0):
    return struct.pack("!HH", kind, len(value)) + value + bytes([pad]) * (-len(value) % 4)


def packet(body=b"", kind=1, transaction=bytes(range(12))):
    return struct.pack("!HH", kind, len(body)) + COOKIE + transaction + body


def length(raw, size):
    return raw[:2] + struct.pack("!H", size) + raw[4:]


def append_integrity(raw, key, algorithm):
    kind, size = (8, 20) if algorithm == "sha1" else (28, 32)
    prefix = length(raw, len(raw) - 20 + 4 + size)
    return prefix + attr(kind, hmac.digest(key, prefix, algorithm))


def fingerprint(raw):
    prefix = length(raw, len(raw) - 20 + 8)
    return prefix + attr(0x8028, struct.pack("!I", zlib.crc32(prefix) ^ 0x5354554E))


def sign(raw, key, mode, with_fingerprint=True):
    for algorithm in {"legacy": ("sha1",), "sha256": ("sha256",), "dual": ("sha1", "sha256")}[mode]:
        raw = append_integrity(raw, key, algorithm)
    return fingerprint(raw) if with_fingerprint else raw


def attributes(raw):
    assert len(raw) >= 20 and raw[0] < 64 and raw[4:8] == COOKIE
    assert int.from_bytes(raw[2:4], "big") == len(raw) - 20
    assert (len(raw) - 20) % 4 == 0
    offset = 20
    result = []
    while offset < len(raw):
        kind, size = struct.unpack_from("!HH", raw, offset)
        end = offset + 4 + size
        assert end <= len(raw)
        result.append((kind, raw[offset + 4:end], offset))
        offset = end + (-size % 4)
    assert offset == len(raw)
    return result


def validate(raw, key, mode, require_fingerprint=True):
    items = attributes(raw)
    kinds = [kind for kind, _, _ in items]
    expected = {"legacy": [8], "sha256": [28], "dual": [8, 28]}[mode]
    assert [kind for kind in kinds if kind in (8, 28)] == expected
    for kind, value, offset in items:
        if kind in (8, 28):
            algorithm, size = ("sha1", 20) if kind == 8 else ("sha256", 32)
            assert len(value) == size
            prefix = length(raw[:offset], offset - 20 + 4 + size)
            assert hmac.compare_digest(hmac.digest(key, prefix, algorithm), value)
    if require_fingerprint:
        assert kinds[-1] == 0x8028 and kinds.count(0x8028) == 1
        _, value, offset = items[-1]
        assert value == struct.pack("!I", zlib.crc32(raw[:offset]) ^ 0x5354554E)
    return items
