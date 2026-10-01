"""Independent TLS 1.3 ChaCha20-Poly1305 record/framing evaluator."""

from pathlib import Path
import json
import random
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "crypto"))
from traffic_check import record as protect, updated


def reference(secret, seq, kind, content, padding=0, version=b"\x03\x03"):
    inner = content + bytes([kind]) + bytes(padding)
    return raw_inner(secret, seq, inner, version)


def raw_inner(secret, seq, inner, version=b"\x03\x03"):
    header = b"\x17" + version + (len(inner) + 16).to_bytes(2, "big")
    ciphertext, tag = protect(secret, seq, inner, header)
    return header + ciphertext + tag


def main():
    global protect
    command = sys.argv[1:]
    aes = "--aes" in command
    if aes:
        from traffic_aes_check import record
        protect = record
        command.remove("--aes")
    rng = random.Random(0x1350)
    count = 0
    with tempfile.TemporaryDirectory() as folder:
        serial = 0

        def put(data):
            nonlocal serial
            serial += 1
            path = Path(folder) / str(serial)
            path.write_bytes(data)
            return str(path)

        def run(args, expected):
            nonlocal count
            if aes and args[0] in ("write", "read"):
                args = [args[0] + "-aes"] + args[1:]
            result = subprocess.run(command + args, capture_output=True, text=True, timeout=60)
            assert result.returncode == 0 and result.stdout.splitlines() == expected, (args, result.stderr, result.stdout, expected)
            count += 1

        if aes:
            vectors = json.loads(Path(__file__).with_name("tls_aes_vectors.json").read_text())["cases"]
            groups = {}
            for vector in vectors:
                groups.setdefault(vector["context"], []).append(vector)
                assert reference(bytes.fromhex(vector["secret"]), vector["sequence"],
                                 vector["kind"], bytes.fromhex(vector["content"])) == bytes.fromhex(vector["record"])
            for group in groups.values():
                secret_path = put(bytes.fromhex(group[0]["secret"]))
                wa, ra = ["write", secret_path], ["read", secret_path]
                we, re = ["write-state:0:0:0:0"], ["read-state:0:0"]
                for sequence, vector in enumerate(group):
                    assert vector["sequence"] == sequence
                    content = bytes.fromhex(vector["content"])
                    wa += ["seal", str(vector["kind"]), "0", put(content)]
                    ra += ["open", put(bytes.fromhex(vector["record"]))]
                    we += [f'sealed:{vector["record"]}', f"write-state:0:{sequence + 1}:0:0"]
                    re += [f'record:{vector["kind"]}:0:{vector["content"]}', f"read-state:0:{sequence + 1}"]
                run(wa, we); run(ra, re)

            cap = 2**24
            secret = bytes.fromhex(groups["client-application"][0]["secret"])
            content = b"usage cap fixture"
            final = reference(secret, cap - 1, 23, content)
            run(["write", put(secret), "seed", "0", str(cap - 1), "seal", "23", "0", put(content),
                 "seal", "23", "0", put(content), "update"],
                ["write-state:0:0:0:0", f"write-state:0:{cap - 1}:0:0", f"sealed:{final.hex()}",
                 f"write-state:0:{cap}:0:0", "seal-error:crypto-usage-limit", "write-state:closed:0:0",
                 "update-error:closed", "write-state:closed:0:0"])
            peer = reference(secret, cap, 23, content)
            run(["read", put(secret), "seed", "0", str(cap), "open", put(peer)],
                ["read-state:0:0", f"read-state:0:{cap}", f"record:23:0:{content.hex()}", f"read-state:0:{cap + 1}"])
            message = bytes.fromhex("1800000100")
            last = reference(secret, cap - 1, 22, message)
            next_record = reference(updated(secret), 0, 23, content)
            run(["write", put(secret), "seed", "0", str(cap - 1), "seal", "22", "0", put(message),
                 "update", "seal", "23", "0", put(content)],
                ["write-state:0:0:0:0", f"write-state:0:{cap - 1}:0:0", f"sealed:{last.hex()}",
                 f"write-state:0:{cap}:0:0", "updated", "write-state:0:0:0:1",
                 f"sealed:{next_record.hex()}", "write-state:0:1:0:1"])
            run(["read", put(secret), "seed", "0", str(cap - 1), "open", put(last), "update", "open", put(next_record)],
                ["read-state:0:0", f"read-state:0:{cap - 1}", f"record:22:0:{message.hex()}", f"read-state:0:{cap}",
                 "updated", "read-state:0:0", f"record:23:0:{content.hex()}", "read-state:0:1"])

        secret = rng.randbytes(32)
        for length in (0, 1, 15, 16, 17, 63, 64, 65, 16383, 16384):
            content = rng.randbytes(length)
            for padding in sorted({0, min(1, 16384 - length), 16384 - length}):
                expected = reference(secret, 0, 23, content, padding)
                run(["write", put(secret), "seal", "23", str(padding), put(content)],
                    ["write-state:0:0:0:0", f"sealed:{expected.hex()}", "write-state:0:1:0:0"])
                run(["read", put(secret), "open", put(expected)],
                    ["read-state:0:0", f"record:23:{padding}:{content.hex()}", "read-state:0:1"])
        for kind, content in ((21, b"\x01\x00"), (22, b"\x08\x00\x00\x00"), (23, b"ends in zero\0\0")):
            first = reference(secret, 0, kind, content, 15)
            second = reference(secret, 1, kind, content, 16)
            run(["write", put(secret), "seal", str(kind), "15", put(content), "seal", str(kind), "16", put(content)],
                ["write-state:0:0:0:0", f"sealed:{first.hex()}", "write-state:0:1:0:0",
                 f"sealed:{second.hex()}", "write-state:0:2:0:0"])
            run(["read", put(secret), "open", put(first), "open", put(second)],
                ["read-state:0:0", f"record:{kind}:15:{content.hex()}", "read-state:0:1",
                 f"record:{kind}:16:{content.hex()}", "read-state:0:2"])

        good = reference(secret, 0, 23, b"synthetic payload\0\0", 3)
        # Every split point of a small record, plus multiple coalesced records.
        for cut in range(len(good)):
            run(["frame", put(good[:cut])], ["more"])
        run(["frame", put(good)], [f"frame:{good[:5].hex()}:{good[5:].hex()}:"])
        extra = reference(secret, 1, 23, b"next")
        run(["frame", put(good + extra)], [f"frame:{good[:5].hex()}:{good[5:].hex()}:{extra.hex()}"])
        maximum = reference(secret, 0, 23, bytes(16384))
        for cut in (0, 1, 4, 5, 6, 8192, len(maximum) - 16, len(maximum) - 1):
            run(["frame", put(maximum[:cut])], ["more"])
        run(["frame", put(maximum)], [f"frame:{maximum[:5].hex()}:{maximum[5:].hex()}:"])

        def denied(record, why):
            # A failed record permanently retires the owner; a valid retry cannot
            # disclose plaintext or use its sequence again.
            run(["read", put(secret), "open", put(record), "open", put(good), "update"],
                ["read-state:0:0", f"open-error:{why}", "read-state:closed",
                 "open-error:crypto-closed", "read-state:closed", "update-error:closed", "read-state:closed"])

        denied(good[:-1], "incomplete")
        denied(good + b"x", "invalid")
        denied(b"\x16" + good[1:], "unexpected")
        denied(b"\x17\x03\x03\x00\x0f" + bytes(15), "crypto-authentication")
        denied(b"\x17\x03\x03\x40\x12", "overflow")
        denied(raw_inner(secret, 0, bytes(16386)), "overflow")
        for position in (1, 2, 5, len(good) - 16, len(good) - 1):
            changed = bytearray(good); changed[position] ^= 1
            denied(changed, "crypto-authentication")
        for inner in (b"", bytes(1), bytes(17), b"\x14", b"\x19", b"\x16", b"\x16\0\0", b"\x01\x15", b"\x01\x02\x03\x15"):
            denied(raw_inner(secret, 0, inner), "unexpected")
        # Legacy version is ignored as a protocol selector but authenticated.
        for version in (b"\x03\x01", b"\x03\x04", b"\x00\x00"):
            peer = reference(secret, 0, 23, b"version fixture", version=version)
            run(["read", put(secret), "open", put(peer)],
                ["read-state:0:0", "record:23:0:76657273696f6e2066697874757265", "read-state:0:1"])

        for kind, content, padding, why in ((20, b"x", 0, "invalid"), (0, b"x", 0, "invalid"),
                (256, b"x", 0, "invalid"), (22, b"", 0, "invalid"), (21, b"", 0, "invalid"),
                (21, b"x", 0, "invalid"), (21, b"abc", 0, "invalid"),
                (23, bytes(16385), 0, "overflow"), (23, b"x", 16384, "overflow"),
                (23, b"", 16385, "overflow"), (23, b"", 4294967295, "overflow")):
            run(["write", put(secret), "seal", str(kind), str(padding), put(content), "seal", "23", "0", put(b"valid"), "update"],
                ["write-state:0:0:0:0", f"seal-error:{why}", "write-state:closed:0:0",
                 "seal-error:crypto-closed", "write-state:closed:0:0", "update-error:closed", "write-state:closed:0:0"])

        denied(reference(secret, 1, 23, b"reordered"), "crypto-authentication")
        run(["read", put(secret), "open", put(good), "open", put(good)],
            ["read-state:0:0", "record:23:3:73796e746865746963207061796c6f61640000", "read-state:0:1",
             "open-error:crypto-authentication", "read-state:closed"])
        # Actual KeyUpdate bytes protected under the old key, followed by the
        # explicit owner update and a new-generation sequence-zero record.
        key_update = b"\x18\x00\x00\x01\x00"
        old_record = reference(secret, 0, 22, key_update)
        next_record = reference(updated(secret), 0, 23, b"new epoch")
        run(["write", put(secret), "seal", "22", "0", put(key_update), "update", "seal", "23", "0", put(b"new epoch")],
            ["write-state:0:0:0:0", f"sealed:{old_record.hex()}", "write-state:0:1:0:0", "updated",
             "write-state:0:0:0:1", f"sealed:{next_record.hex()}", "write-state:0:1:0:1"])
        run(["read", put(secret), "open", put(old_record), "update", "open", put(next_record)],
            ["read-state:0:0", "record:22:0:1800000100", "read-state:0:1", "updated", "read-state:0:0",
             "record:23:0:6e65772065706f6368", "read-state:0:1"])
        denied(next_record, "crypto-authentication")
    suite = "AES-GCM" if aes else "ChaCha20-Poly1305"
    print(f"TLS {suite} records: {count} independent framing/protection/padding/bounds/tampering/lifecycle scenarios passed")


if __name__ == "__main__":
    main()
