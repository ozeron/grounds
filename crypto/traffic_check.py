"""Synthetic TLS traffic lifecycle checks, independent HKDF and AEAD oracles."""

from pathlib import Path
import hashlib
import hmac
import random
import subprocess
import sys
import tempfile

from aead_check import reference as aead


def expand_label(secret, label, context, length):
    full_label = b"tls13 " + label
    info = length.to_bytes(2, "big") + bytes([len(full_label)]) + full_label
    info += bytes([len(context)]) + context
    output = previous = b""
    for counter in range(1, (length + 31) // 32 + 1):
        previous = hmac.digest(secret, previous + info + bytes([counter]), "sha256")
        output += previous
    return output[:length]


def record(secret, sequence, message, aad):
    key = expand_label(secret, b"key", b"", 32)
    iv = expand_label(secret, b"iv", b"", 12)
    padded = sequence.to_bytes(12, "big")
    nonce = bytes(a ^ b for a, b in zip(iv, padded))
    return aead(key, nonce, aad, message)


def updated(secret):
    return expand_label(secret, b"traffic upd", b"", 32)


def main():
    command = sys.argv[1:]
    rng = random.Random(0x9846)
    cases = 0
    with tempfile.TemporaryDirectory() as folder:
        serial = 0

        def put(data):
            nonlocal serial
            serial += 1
            path = Path(folder) / str(serial)
            path.write_bytes(data)
            return str(path)

        def run(args, expected=None, rejected=False):
            nonlocal cases
            result = subprocess.run(command + args, capture_output=True, text=True, timeout=30)
            if rejected:
                assert result.returncode == 1 and result.stdout == "", (args, result)
            else:
                assert result.returncode == 0, (args, result.stderr)
                assert result.stdout.splitlines() == expected, (args, result.stdout, expected)
            cases += 1

        def label(secret, label, context, length, expected=None):
            expected = expand_label(secret, label, context, length) if expected is None else expected
            run(["label", put(secret), put(label), put(context), str(length)], [expected.hex()])

        # RFC 8448 section 3 client handshake key/IV and derived-secret vectors.
        # The 16-byte key vector checks the TLS label encoding, not AES support.
        published = bytes.fromhex("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21")
        label(published, b"key", b"", 16, bytes.fromhex("dbfaa693d1762c5b666af5d950258d01"))
        label(published, b"iv", b"", 12, bytes.fromhex("5bd3c71b836e0b76bb73265f"))
        label(bytes.fromhex("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"),
              b"derived", hashlib.sha256(b"").digest(), 32,
              bytes.fromhex("6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba"))
        for length in (0, 1, 12, 16, 31, 32, 33, 65, 8160):
            label(rng.randbytes(32), b"traffic upd", rng.randbytes(32), length)
        for label_length, context_length in ((1, 0), (249, 255), (3, 1), (12, 254)):
            label(rng.randbytes(32), b"a" * label_length, rng.randbytes(context_length), 32)
        for secret, name, context, size in ((bytes(31), b"key", b"", 32),
                (bytes(33), b"key", b"", 32), (bytes(32), b"", b"", 32),
                (bytes(32), b"a" * 250, b"", 32), (bytes(32), b"key", bytes(256), 32),
                (bytes(32), b"key", b"", 8161)):
            run(["label", put(secret), put(name), put(context), str(size)], rejected=True)

        def wstate(seq, generation=0):
            counter = "spent" if seq == 2**64 else f"{seq >> 32}:{seq & 0xffffffff}"
            return f"write-state:{counter}:{generation >> 32}:{generation & 0xffffffff}"

        def rstate(seq):
            counter = "spent" if seq == 2**64 else f"{seq >> 32}:{seq & 0xffffffff}"
            return f"read-state:{counter}"

        def seal_cmd(secret, seq, message, aad, generation=0):
            ciphertext, tag = record(secret, seq, message, aad)
            return ["seal", put(aad), put(message)], [
                f"ciphertext:{ciphertext.hex()}", f"tag:{tag.hex()}", wstate(seq + 1, generation)]

        def open_cmd(secret, seq, message, aad):
            ciphertext, tag = record(secret, seq, message, aad)
            return ["open", put(aad), put(ciphertext), put(tag)], [
                f"plaintext:{message.hex()}", rstate(seq + 1)]

        for length in (0, 1, 15, 16, 17, 63, 64, 65, 16385):
            secret = rng.randbytes(32)
            message = rng.randbytes(length)
            aad = bytes([23, 3, 3]) + (length + 16).to_bytes(2, "big")
            wa, ra = ["write", put(secret)], ["read", put(secret)]
            we, re = [wstate(0)], [rstate(0)]
            for seq in range(3):
                a, e = seal_cmd(secret, seq, message, aad); wa += a; we += e
                a, e = open_cmd(secret, seq, message, aad); ra += a; re += e
            run(wa, we); run(ra, re)

        secret = rng.randbytes(32)
        message, aad = b"synthetic TLS inner plaintext\x17\0\0", b"\x17\x03\x03\x00\x30"
        # Counter carry is checked through ciphertext, not just the state printer.
        for start in (2**32 - 1, 2**63 - 1, 2**64 - 2):
            wa = ["write", put(secret), "seed", str(start >> 32), str(start & 0xffffffff)]
            ra = ["read", put(secret), "seed", str(start >> 32), str(start & 0xffffffff)]
            we, re = [wstate(0), wstate(start)], [rstate(0), rstate(start)]
            for seq in range(start, min(start + 3, 2**64)):
                a, e = seal_cmd(secret, seq, message, aad); wa += a; we += e
                a, e = open_cmd(secret, seq, message, aad); ra += a; re += e
            if start == 2**64 - 2:
                # Last sequence is used once; the next attempt retires the owner.
                a, _ = seal_cmd(secret, 0, message, aad)
                wa += a + a + ["update"]
                we += ["seal-error:exhausted", "write-state:closed:0:0",
                       "seal-error:closed", "write-state:closed:0:0",
                       "update-error:closed", "write-state:closed:0:0"]
                a, _ = open_cmd(secret, 0, message, aad)
                ra += a + a + ["update"]
                re += ["open-error:exhausted", "read-state:closed", "open-error:closed",
                       "read-state:closed", "update-error:closed", "read-state:closed"]
            run(wa, we); run(ra, re)

        # Multiple old-key records followed by explicit application key updates.
        wa, ra = ["write", put(secret)], ["read", put(secret)]
        we, re = [wstate(0)], [rstate(0)]
        current = secret
        for generation in range(5):
            for seq in range(2):
                a, e = seal_cmd(current, seq, message, aad, generation); wa += a; we += e
                a, e = open_cmd(current, seq, message, aad); ra += a; re += e
            if generation < 4:
                current = updated(current)
                wa += ["update"]; we += ["updated", wstate(0, generation + 1)]
                ra += ["update"]; re += ["updated", rstate(0)]
        run(wa, we); run(ra, re)

        # Sending updates stop at 2^48-1 without discarding the still-usable key.
        cap = 2**48 - 1
        wa = ["write", put(secret), "generation", "65535", "4294967294", "update"]
        we = [wstate(0), wstate(0, cap - 1), "updated", wstate(0, cap)]
        a, e = seal_cmd(updated(secret), 0, message, aad, cap)
        wa += a + ["update"]; we += e + ["update-error:update-limit", wstate(1, cap)]
        a, e = seal_cmd(updated(secret), 1, message, aad, cap)
        run(wa + a, we + e)
        # Carry between generation words, independent of the record counter.
        a, e = seal_cmd(updated(secret), 0, message, aad, 2**32)
        run(["write", put(secret), "generation", "0", "4294967295", "update"] + a,
            [wstate(0), wstate(0, 2**32 - 1), "updated", wstate(0, 2**32)] + e)

        good_cipher, good_tag = record(secret, 0, message, aad)
        good = ["open", put(aad), put(good_cipher), put(good_tag)]
        for pos in (0, 7, 15):
            bad_tag = bytearray(good_tag); bad_tag[pos] ^= 1
            run(["read", put(secret), "open", put(aad), put(good_cipher), put(bad_tag)] + good + ["update"],
                [rstate(0), "open-error:authentication", "read-state:closed",
                 "open-error:closed", "read-state:closed", "update-error:closed", "read-state:closed"])
        for bad_aad, bad_cipher, bad_tag in ((aad + b"x", good_cipher, good_tag),
                (aad, bytes([good_cipher[0] ^ 1]) + good_cipher[1:], good_tag),
                (aad, good_cipher, good_tag[:15]), (aad, good_cipher, good_tag + b"x")):
            run(["read", put(secret), "open", put(bad_aad), put(bad_cipher), put(bad_tag)] + good,
                [rstate(0), "open-error:authentication", "read-state:closed",
                 "open-error:closed", "read-state:closed"])
        run(["read", put(updated(secret))] + good, [rstate(0), "open-error:authentication", "read-state:closed"])
        # Replays, reordered records, and missed key updates are fatal.
        second, _ = open_cmd(secret, 1, message, aad)
        run(["read", put(secret)] + second + good,
            [rstate(0), "open-error:authentication", "read-state:closed", "open-error:closed", "read-state:closed"])
        run(["read", put(secret)] + good + good,
            [rstate(0), f"plaintext:{message.hex()}", rstate(1), "open-error:authentication", "read-state:closed"])
        run(["read", put(secret), "update"] + good,
            [rstate(0), "updated", rstate(0), "open-error:authentication", "read-state:closed"])

        a, _ = seal_cmd(secret, 0, message, aad)
        run(["write", put(secret), "bad"] + a + ["update"],
            [wstate(0), "seal-error:invalid", "write-state:closed:0:0", "seal-error:closed",
             "write-state:closed:0:0", "update-error:closed", "write-state:closed:0:0"])
        run(["write", put(secret), "close", "close", "update"] + a,
            [wstate(0), "write-state:closed:0:0", "write-state:closed:0:0", "update-error:closed",
             "write-state:closed:0:0", "seal-error:closed", "write-state:closed:0:0"])
        run(["read", put(secret), "close", "close", "update"] + good,
            [rstate(0), "read-state:closed", "read-state:closed", "update-error:closed",
             "read-state:closed", "open-error:closed", "read-state:closed"])
        for bad_secret in (b"", bytes(31), bytes(33)):
            for mode in ("write", "read"):
                run([mode, put(bad_secret)], rejected=True)
    print(f"TLS traffic: {cases} published/differential/counter/update/replay/tampering/retirement scenarios passed")


if __name__ == "__main__":
    main()
