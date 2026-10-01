"""AES-GCM TLS traffic owners: independent HKDF/AES/GHASH and usage limits."""

from pathlib import Path
import random
import subprocess
import sys
import tempfile

from gcm_check import oracle as gcm
from traffic_check import expand_label, updated, record as chacha


def record(secret, sequence, message, aad):
    key = expand_label(secret, b"key", b"", 16)
    iv = expand_label(secret, b"iv", b"", 12)
    nonce = bytes(a ^ b for a, b in zip(iv, sequence.to_bytes(12, "big")))
    return gcm(key, nonce, aad, message)


def wstate(sequence, generation=0):
    counter = "spent" if sequence == 2**64 else f"{sequence >> 32}:{sequence & 0xffffffff}"
    return f"write-state:{counter}:{generation >> 32}:{generation & 0xffffffff}"


def rstate(sequence):
    counter = "spent" if sequence == 2**64 else f"{sequence >> 32}:{sequence & 0xffffffff}"
    return f"read-state:{counter}"


def main():
    command = sys.argv[1:]
    rng = random.Random(0x1301)
    count = 0
    with tempfile.TemporaryDirectory() as folder:
        serial = 0

        def put(data):
            nonlocal serial
            serial += 1
            path = Path(folder) / str(serial)
            path.write_bytes(data)
            return str(path)

        def run(args, expected=None, rejected=False):
            nonlocal count
            result = subprocess.run(command + args, capture_output=True, text=True, timeout=60)
            if rejected:
                assert result.returncode == 1 and not result.stdout, (args, result)
            else:
                assert result.returncode == 0 and result.stdout.splitlines() == expected, (args, result, expected)
            count += 1

        def seal(secret, seq, message, aad, generation=0):
            c, t = record(secret, seq, message, aad)
            return ["seal", put(aad), put(message)], [f"ciphertext:{c.hex()}", f"tag:{t.hex()}", wstate(seq + 1, generation)]

        def opened(secret, seq, message, aad):
            c, t = record(secret, seq, message, aad)
            return ["open", put(aad), put(c), put(t)], [f"plaintext:{message.hex()}", rstate(seq + 1)]

        for length in (0, 1, 15, 16, 17, 63, 64, 65, 16385):
            secret, message = rng.randbytes(32), rng.randbytes(length)
            aad = b"\x17\x03\x03" + (length + 16).to_bytes(2, "big")
            wa, ra = ["write-aes", put(secret)], ["read-aes", put(secret)]
            we, re = [wstate(0)], [rstate(0)]
            for seq in range(3):
                a, e = seal(secret, seq, message, aad); wa += a; we += e
                a, e = opened(secret, seq, message, aad); ra += a; re += e
            run(wa, we); run(ra, re)

        secret, message, aad = rng.randbytes(32), b"traffic fixture\x17", b"\x17\x03\x03\x00\x20"
        cap = 2**24
        wa = ["write-aes", put(secret), "seed", "0", str(cap - 2)]
        we = [wstate(0), wstate(cap - 2)]
        for seq in (cap - 2, cap - 1):
            a, e = seal(secret, seq, message, aad); wa += a; we += e
        a, _ = seal(secret, 0, message, aad)
        run(wa + a + a + ["update"], we + ["seal-error:usage-limit", "write-state:closed:0:0",
            "seal-error:closed", "write-state:closed:0:0", "update-error:closed", "write-state:closed:0:0"])
        for start in (cap, 2**32, 2**63, 2**64 - 1):
            run(["write-aes", put(secret), "seed", str(start >> 32), str(start & 0xffffffff)] + a,
                [wstate(0), wstate(start), "seal-error:usage-limit", "write-state:closed:0:0"])

        # The old-key KeyUpdate consumes the last permitted record, then reset.
        update_message = bytes.fromhex("1800000100")
        a, e = seal(secret, cap - 1, update_message, aad)
        b, f = seal(updated(secret), 0, message, aad, 1)
        run(["write-aes", put(secret), "seed", "0", str(cap - 1)] + a + ["update"] + b,
            [wstate(0), wstate(cap - 1)] + e + ["updated", wstate(0, 1)] + f)

        # Receive usage is not capped; full sequence carry/exhaustion still apply.
        for start in (cap - 1, cap, 2**32 - 1, 2**63 - 1, 2**64 - 2):
            args = ["read-aes", put(secret), "seed", str(start >> 32), str(start & 0xffffffff)]
            expected = [rstate(0), rstate(start)]
            for seq in range(start, min(start + 3, 2**64)):
                a, e = opened(secret, seq, message, aad); args += a; expected += e
            if start == 2**64 - 2:
                a, _ = opened(secret, 0, message, aad)
                args += a + a + ["update"]
                expected += ["open-error:exhausted", "read-state:closed", "open-error:closed", "read-state:closed",
                             "update-error:closed", "read-state:closed"]
            run(args, expected)

        wa, ra = ["write-aes", put(secret)], ["read-aes", put(secret)]
        we, re = [wstate(0)], [rstate(0)]
        current = secret
        for generation in range(5):
            for seq in range(2):
                a, e = seal(current, seq, message, aad, generation); wa += a; we += e
                a, e = opened(current, seq, message, aad); ra += a; re += e
            if generation < 4:
                current = updated(current)
                wa += ["update"]; we += ["updated", wstate(0, generation + 1)]
                ra += ["update"]; re += ["updated", rstate(0)]
        run(wa, we); run(ra, re)

        generation_cap = 2**48 - 1
        a, e = seal(updated(secret), 0, message, aad, generation_cap)
        b, f = seal(updated(secret), 1, message, aad, generation_cap)
        run(["write-aes", put(secret), "generation", "65535", "4294967294", "update"] + a + ["update"] + b,
            [wstate(0), wstate(0, generation_cap - 1), "updated", wstate(0, generation_cap)] + e +
            ["update-error:update-limit", wstate(1, generation_cap)] + f)
        a, e = seal(updated(secret), 0, message, aad, 2**32)
        run(["write-aes", put(secret), "generation", "0", "4294967295", "update"] + a,
            [wstate(0), wstate(0, 2**32 - 1), "updated", wstate(0, 2**32)] + e)

        good, good_expected = opened(secret, 0, message, aad)
        cipher, tag = record(secret, 0, message, aad)

        def deny(k=secret, a=aad, c=cipher, t=tag):
            run(["read-aes", put(k), "open", put(a), put(c), put(t)] + good + ["update"],
                [rstate(0), "open-error:authentication", "read-state:closed", "open-error:closed", "read-state:closed",
                 "update-error:closed", "read-state:closed"])

        for i in range(16):
            bad = bytearray(tag); bad[i] ^= 1; deny(t=bad)
        deny(k=updated(secret)); deny(a=aad + b"x"); deny(c=bytes([cipher[0] ^ 1]) + cipher[1:])
        deny(t=tag[:-1]); deny(t=tag + b"x")
        second, _ = opened(secret, 1, message, aad)
        run(["read-aes", put(secret)] + second + good,
            [rstate(0), "open-error:authentication", "read-state:closed", "open-error:closed", "read-state:closed"])
        run(["read-aes", put(secret)] + good + good,
            [rstate(0)] + good_expected + ["open-error:authentication", "read-state:closed"])
        run(["read-aes", put(secret), "update"] + good,
            [rstate(0), "updated", rstate(0), "open-error:authentication", "read-state:closed"])

        for bad_aad, bad_message in ((aad + b"x", message), (aad, bytes(16386))):
            a = ["seal", put(bad_aad), put(bad_message)]
            run(["write-aes", put(secret)] + a + ["update"],
                [wstate(0), "seal-error:invalid", "write-state:closed:0:0", "update-error:closed", "write-state:closed:0:0"])
            c, t = record(secret, 0, bad_message, bad_aad); deny(a=bad_aad, c=c, t=t)
        a, _ = seal(secret, 0, message, aad)
        run(["write-aes", put(secret), "bad"] + a + ["update"],
            [wstate(0), "seal-error:invalid", "write-state:closed:0:0", "seal-error:closed", "write-state:closed:0:0",
             "update-error:closed", "write-state:closed:0:0"])
        run(["write-aes", put(secret), "close", "update"] + a,
            [wstate(0), "write-state:closed:0:0", "update-error:closed", "write-state:closed:0:0",
             "seal-error:closed", "write-state:closed:0:0"])
        run(["read-aes", put(secret), "close", "update"] + good,
            [rstate(0), "read-state:closed", "update-error:closed", "read-state:closed", "open-error:closed", "read-state:closed"])
        for bad_secret in (b"", bytes(31), bytes(33)):
            for mode in ("write-aes", "read-aes"):
                run([mode, put(bad_secret)], rejected=True)

        # Negotiated algorithm identity is retained; no authentication fallback.
        c, t = chacha(secret, 0, message, aad); deny(c=c, t=t)
        run(["read", put(secret), "open", put(aad), put(cipher), put(tag)],
            [rstate(0), "open-error:authentication", "read-state:closed"])
    print(f"AES-GCM TLS traffic: {count} differential/usage-limit/update/counter/algorithm/retirement scenarios passed")


if __name__ == "__main__":
    main()
