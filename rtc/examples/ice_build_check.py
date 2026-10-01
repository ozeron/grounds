"""Check ICE request bytes, credential limits and 64-bit role values independently."""

import random
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

from stun_reference import attr, packet, sign, validate

command = sys.argv[1:]
rng = random.Random(8445)
count = 0

with tempfile.TemporaryDirectory() as directory:
    transaction_path = Path(directory) / "transaction"

    def run(mode="dual", role="controlling", local="localFrag", remote="remoteFrag",
            password="SyntheticPassword123456789", priority=1845494271,
            high=0xFEDCBA98, low=0x76543210, transaction=None, valid=True, intent=None):
        global count
        transaction = rng.randbytes(12) if transaction is None else transaction
        transaction_path.write_bytes(transaction)
        cli_role = role if intent is None else role + ("-nominate" if intent else "-ordinary")
        args = [mode, cli_role, local, remote, password, str(priority), str(high), str(low), str(transaction_path)]
        result = subprocess.run(command + args, capture_output=True, text=True, timeout=10)
        count += 1
        if not valid:
            assert result.returncode == 1 and "invalid STUN" in result.stderr, (args, result)
            return
        assert result.returncode == 0, (args, result.stderr)
        role_kind = 0x802A if role == "controlling" else 0x8029
        body = attr(6, (remote + ":" + local).encode())
        body += attr(0x24, struct.pack("!I", priority))
        body += attr(role_kind, struct.pack("!II", high, low))
        if intent:
            body += attr(0x25, b"")
        expected = sign(packet(body, transaction=transaction), password.encode(), mode)
        assert bytes.fromhex(result.stdout.strip()) == expected
        items = validate(expected, password.encode(), mode)
        assert [item[0] for item in items[:3]] == [6, 0x24, role_kind]
        assert sum(item[0] == 0x25 for item in items) == int(bool(intent))
        if intent:
            assert items[3][:2] == (0x25, b"")

    for mode in ("legacy", "sha256", "dual"):
        for role in ("controlling", "controlled"):
            for high, low in ((0, 0), (0, 1), (0x80000000, 0), (0xFFFFFFFF, 0xFFFFFFFF), (0xFEDCBA98, 0x76543210)):
                run(mode=mode, role=role, high=high, low=low)
    for priority in (1, 0x7FFFFFFF):
        run(priority=priority)
    for priority in (0, 0x80000000, 0xFFFFFFFF):
        run(priority=priority, valid=False)
    for transaction in (b"", b"\x00" * 11, b"\x00" * 13):
        run(transaction=transaction, valid=False)
    run(local="a+/Z", remote="b+/Y", password="+/" * 11)
    run(local="a" * 32, remote="b" * 256, password="c" * 256)
    for name, value in (("local", ""), ("local", "abc"), ("local", "a" * 33),
                        ("remote", "abc"), ("remote", "a" * 257),
                        ("password", "a" * 21), ("password", "a" * 257),
                        ("local", "bad:frag"), ("remote", "bad\nfrag"),
                        ("password", "bad password" * 2), ("local", "éabc")):
        run(**{name: value}, valid=False)

    # Both additive modes preserve ordinary bytes; only a controlling request
    # can include one empty protected USE-CANDIDATE before the integrity fields.
    for mode in ("legacy", "sha256", "dual"):
        for high, low in ((0, 0), (0, 1), (0x80000000, 0), (0xFFFFFFFF, 0xFFFFFFFF), (0xFEDCBA98, 0x76543210)):
            for role in ("controlling", "controlled"):
                run(mode=mode, role=role, high=high, low=low, intent=False)
                run(mode=mode, role=role, high=high, low=low, intent=True, valid=role == "controlling")
    for priority in (1, 0x7FFFFFFF):
        run(priority=priority, intent=True)
    for priority in (0, 0x80000000, 0xFFFFFFFF):
        run(priority=priority, intent=True, valid=False)
    for transaction in (b"", b"\x00" * 11, b"\x00" * 13):
        run(transaction=transaction, intent=True, valid=False)
    run(local="a" * 32, remote="b" * 256, password="c" * 256, intent=True)
    run(local="bad:frag", intent=True, valid=False)

print(f"ICE builder: {count} byte-exact credential/priority/role/transaction checks passed")
