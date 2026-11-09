#!/usr/bin/env python3
"""Write a synthetic RSA key pool for timing_cli kind 4 (RSA-PSS sign).

Record format per key: n, e, d, p, q, dp, dq, qi, each as a 2-byte big-endian
length plus the canonical big-endian integer. Key 0 is the fixed class; the
others form the random class. Synthetic keys only: never point this at a live
credential.
"""
import argparse

from cryptography.hazmat.primitives.asymmetric import rsa


def canonical(value: int) -> bytes:
    return value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("output")
    parser.add_argument("--count", type=int, default=32)
    parser.add_argument("--bits", type=int, default=2048)
    args = parser.parse_args()
    out = bytearray()
    for _ in range(args.count):
        private = rsa.generate_private_key(public_exponent=65537, key_size=args.bits)
        numbers = private.private_numbers()
        public = numbers.public_numbers
        for value in (public.n, public.e, numbers.d, numbers.p, numbers.q,
                      numbers.dmp1, numbers.dmq1, numbers.iqmp):
            data = canonical(value)
            out += len(data).to_bytes(2, "big") + data
    with open(args.output, "wb") as handle:
        handle.write(out)


if __name__ == "__main__":
    main()
