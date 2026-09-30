"""Independent signed ICE requests and exact server-response/role expectations."""
import itertools
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from stun_reference import COOKIE, append_integrity, attr, attributes, fingerprint, length, packet, sign, validate

COMMAND = sys.argv[1:]
KEY = b"LocalFixturePassword123456"
UFRAG = "localFrag"
COUNT = 0
SOURCE = (127, 0, 0, 1, 34567)
PHRASES = {400: b"Bad Request", 401: b"Unauthenticated", 420: b"Unknown Attribute", 487: b"Role Conflict"}


def body(remote="remoteFrag", priority=1845494271, controlling=True, tie=0xFEDCBA9876543210, nominate=False):
    raw = attr(6, f"{UFRAG}:{remote}".encode()) + attr(0x24, struct.pack("!I", priority))
    raw += attr(0x802A if controlling else 0x8029, struct.pack("!Q", tie))
    return raw + (attr(0x25, b"") if nominate else b"")


def expected_response(raw, code, mode, source=SOURCE, unknown=()):
    if code:
        fields = attr(9, bytes([0, 0, code // 100, code % 100]) + PHRASES[code])
        if unknown:
            fields += attr(10, b"".join(struct.pack("!H", k) for k in unknown))
    else:
        a, b, c, d, port = source
        fields = attr(0x20, b"\x00\x01" + struct.pack("!H", port ^ 0x2112) +
                      bytes(x ^ y for x, y in zip(bytes([a, b, c, d]), COOKIE)))
    reply = packet(fields, kind=0x111 if code else 0x101, transaction=raw[8:20])
    return sign(reply, KEY, mode) if mode else fingerprint(reply)


def run(raw, *, local_role=True, tie=1, code=0, signed=True, algorithm="legacy", priority=1845494271,
        peer_role=True, peer_tie=0xFEDCBA9876543210, nominate=False, remote="remoteFrag", unknown=(),
        ignored=False, invalid=False, ufrag=UFRAG, password=KEY.decode(), source=SOURCE):
    global COUNT
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "packet"
        path.write_bytes(raw)
        args = [ufrag, password, "controlling" if local_role else "controlled", str(tie >> 32), str(tie & 0xFFFFFFFF),
                *map(str, source), str(path)]
        result = subprocess.run(COMMAND + args, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, (args, result.stderr)
    lines = result.stdout.splitlines()
    if invalid or ignored:
        assert lines == ["invalid" if invalid else "ignore"], lines
    else:
        if not code and local_role == peer_role:
            own_wins = tie >= peer_tie
            if own_wins == local_role:
                code = 487
            else:
                local_role = not local_role
                switched = True
        else:
            switched = False
        if code:
            expected = f"reject:{code}:{int(signed)}"
        else:
            expected = (f"accept:{remote}:{priority}:" + ("controlling" if peer_role else "controlled") +
                        f":{peer_tie >> 32}:{peer_tie & 0xFFFFFFFF}:{int(nominate)}:{algorithm}:" +
                        ("controlling" if local_role else "controlled") + f":{tie >> 32}:{tie & 0xFFFFFFFF}:{int(switched)}")
        assert len(lines) == 2 and lines[0] == expected, (lines[:1], expected, raw.hex())
        reply = bytes.fromhex(lines[1])
        expected_raw = expected_response(raw, code, algorithm if signed else None, source, unknown)
        assert reply == expected_raw, (reply.hex(), expected_raw.hex())
        fields = validate(reply, KEY, algorithm) if signed else attributes(reply)
        assert all(kind != 6 for kind, _, _ in fields), "response leaks USERNAME"
        if not signed:
            assert all(kind not in (8, 28) for kind, _, _ in fields)
    COUNT += 1


for mode in ("legacy", "sha256", "dual"):
    algorithm = "sha256" if mode == "dual" else mode
    for peer_role, local_role, nominate in itertools.product((False, True), repeat=3):
        raw = sign(packet(body(controlling=peer_role, nominate=nominate)), KEY, mode)
        run(raw, local_role=local_role, peer_role=peer_role, nominate=nominate, algorithm=algorithm,
            code=400 if nominate and not peer_role else 0)
    # Respond before answer: a different, syntactically valid sender fragment
    # is authenticated from local credentials alone.
    for remote in ("abcd", "x"*256, "a+B/", "DifferentSessionPeer"):
        raw = sign(packet(body(remote=remote)), KEY, mode)
        run(raw, remote=remote, algorithm=algorithm)
    for priority in (1, 2**31-1, 0, 2**31, 2**32-1):
        raw = sign(packet(body(priority=priority)), KEY, mode)
        run(raw, priority=priority, code=0 if 1 <= priority < 2**31 else 400, algorithm=algorithm)
    # Authentication errors are unsigned and cannot expose accepted metadata.
    run(sign(packet(body()), b"wrong key", mode), code=401, signed=False)
    wrong_username = body().replace(b"localFrag", b"wrongFrag")
    run(sign(packet(wrong_username), KEY, mode), code=401, signed=False)
    for remote in ("", "abc", "a"*257, "bad:fragment", "has space", "\u00e9abcd"):
        run(sign(packet(body(remote=remote)), KEY, mode), code=401, signed=False)
    run(sign(packet(attr(0x24, struct.pack("!I", 1))), KEY, mode), code=400, signed=False)
    # Required fields after the integrity boundary are ignored, even if a
    # later CRC is valid. Protected values and first ordinary duplicates win.
    prefix = sign(packet(body()), KEY, mode, with_fingerprint=False)
    suffix = attr(0x24, b"x") + attr(0x8029, b"bad") + attr(0x25, b"") + attr(0x7777, b"")
    amended = fingerprint(length(prefix + suffix, len(prefix + suffix) - 20))
    run(amended, algorithm=algorithm)
    duplicate = body() + attr(6, b"wrong:peer") + attr(0x24, b"bad") + attr(0x802A, b"bad")
    run(sign(packet(duplicate), KEY, mode), algorithm=algorithm)
    # Malformed or missing protected ICE fields produce authenticated 400.
    good_attrs = [attr(6, b"localFrag:remoteFrag"), attr(0x24, struct.pack("!I", 1845494271)),
                  attr(0x802A, struct.pack("!Q", 0xFEDCBA9876543210))]
    for index in (1, 2):
        for replacement in (b"", attr(0x24 if index == 1 else 0x802A, b"x")):
            changed = good_attrs.copy()
            changed[index] = replacement
            run(sign(packet(b"".join(changed)), KEY, mode), code=400, algorithm=algorithm)
    for extra in (attr(0x8029, struct.pack("!Q", 1)), attr(0x25, b"x")):
        run(sign(packet(body() + extra), KEY, mode), code=400, algorithm=algorithm)
    # Authentication precedes unknown required attribute processing.
    for kinds in ((0x7777,), (0x7777, 0x1234, 0x7777)):
        extra = b"".join(attr(k, b"") for k in kinds)
        run(sign(packet(body() + extra), KEY, mode), code=420, unknown=kinds, algorithm=algorithm)
        run(sign(packet(body() + extra), b"wrong key", mode), code=401, signed=False)
    # Known-but-unexpected base fields and unknown optional fields are ignored.
    extra = attr(9, b"not an error") + attr(0xCCCC, b"optional")
    run(sign(packet(body() + extra), KEY, mode), algorithm=algorithm)
    # Large protected optional payload exercises all byte values and maximum
    # formatting without relying on a transport whose UDP limit is smaller.
    payload = bytes(range(256))*255
    run(sign(packet(body() + attr(0xCCCC, payload)), KEY, mode), algorithm=algorithm)

# Full 64-bit ordering and equality, both roles, with identical/unequal high words.
values = (0, 1, 2**32-1, 2**32, 0xFEDCBA9876543210, 2**64-1)
for local, peer, own, other in itertools.product((False, True), (False, True), values, values):
    raw = sign(packet(body(controlling=peer, tie=other)), KEY, "legacy")
    run(raw, local_role=local, peer_role=peer, tie=own, peer_tie=other)

# Missing integrity: 400, including a USERNAME hidden after the first MAC.
run(fingerprint(packet(body())), code=400, signed=False)
run(fingerprint(packet()), code=400, signed=False)
prefix = append_integrity(packet(), KEY, "sha1")
run(fingerprint(length(prefix + attr(6, b"localFrag:remoteFrag"), len(prefix + attr(6, b"localFrag:remoteFrag"))-20)), code=400, signed=False)
# Duplicate, malformed and reversed integrity layouts cannot authenticate.
for raw in (append_integrity(append_integrity(packet(body()), KEY, "sha1"), KEY, "sha1"),
            append_integrity(append_integrity(packet(body()), KEY, "sha256"), KEY, "sha1"),
            packet(body() + attr(8, b"short"))):
    run(fingerprint(raw), code=400, signed=False)
# Bad SHA-256 never falls back to an intact SHA-1.
raw = sign(packet(body()), KEY, "dual", with_fingerprint=False)
raw = raw[:-1] + bytes([raw[-1] ^ 1])
run(fingerprint(raw), code=401, signed=False)
# The SHA-1 value is ignored when the authenticated SHA-256 protects the packet.
raw = append_integrity(packet(body()), KEY, "sha1")
raw = raw[:-1] + bytes([raw[-1] ^ 1])
raw = append_integrity(raw, KEY, "sha256")
run(fingerprint(raw), algorithm="sha256")

valid = sign(packet(body()), KEY, "legacy")
for raw in (b"", b"not STUN", valid[:-1], valid[:-1]+bytes([valid[-1]^1]),
            sign(packet(body(), kind=0x11), KEY, "legacy"), sign(packet(body(), kind=0x101), KEY, "legacy"),
            sign(packet(body(), kind=3), KEY, "legacy"), sign(packet(body()), KEY, "legacy", with_fingerprint=False),
            fingerprint(valid)):
    run(raw, ignored=True)
for kwargs in (dict(ufrag="abc"), dict(ufrag="a"*33), dict(password="short"), dict(password="bad password"*2),
               dict(source=(256,0,0,1,1000)), dict(source=(127,0,0,1,0)), dict(source=(127,0,0,1,65536))):
    run(valid, invalid=True, **kwargs)
for source in ((0,0,0,0,1), (255,255,255,255,65535), (203,0,113,9,256)):
    run(valid, source=source)

for host, port, expected in (("127.0.0.1", "9000", "127.0.0.1/9000"),
                             ("0.0.0.0", "1", "0.0.0.0/1"),
                             ("255.255.255.255", "65535", "255.255.255.255/65535"),
                             ("203.0.113.9", "256", "203.0.113.9/256"),
                             *[(h, "9000", "invalid") for h in
                               ("", "localhost", "::1", "127.0.0", "127.0.0.1.2", "256.0.0.1",
                                "127.00.0.1", " 127.0.0.1", "127.0.0.1 ", "127.-1.0.1")],
                             *[("127.0.0.1", p, "invalid") for p in ("0", "65536", "4294967295")]):
    result = subprocess.run(COMMAND + ["address", host, port], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0 and result.stdout.splitlines() == [expected], (host, port, result)
    COUNT += 1
print(f"ICE incoming: {COUNT} authentication/response/role/nomination/boundary cases passed")
