# Timing leakage harness

Native-only evidence for [TIMING_REVIEW.md](../TIMING_REVIEW.md). Bun is not
measured (it is synthetic-only). Every key here is synthetic.

`timing_cli.bend` runs one server secret operation in a loop, in-process. Each
iteration picks class 0 or class 1 at random. Class 0 is a fixed or special
secret; class 1 is a random secret. The public inputs are the same for both.
The harness prepares the input and copies every list fresh, so the class
does not also pick a memory placement. Only then does it read the per-thread
instruction and cycle counters (`effs/clock.c`). The operation runs inside the
continuation of the first read, and its result feeds the second read. Each
iteration prints one line, `class cycles instructions result`.

`ttest.py` reports two things.

- **Cycles:** a dudect-style Welch t-test, on the raw samples and on samples
  cropped at several percentiles.
- **Instructions retired:** the counts for each class, with their own t-test.

A |t| above 4.5 indicates a leak. Equal instruction counts show that the
instruction stream did not depend on the class for the sampled inputs. They
say nothing about memory addresses, and an if/else whose two arms have equal
length leaves the count unchanged. **A pass does not prove constant time.**

| kind | operation | class 0 | class 1 |
|---:|---|---|---|
| 0 | X25519 shared (u=9) | scalar 0 (clamped) | random scalar |
| 1 | P-256 ECDH with G | d=1 | random d |
| 2 | P-256 keygen d*G | d=1 | random d |
| 3 | ECDSA P-256 sign (RFC 6979) | d=1, digest 0 | random d, digest |
| 4 | RSA-PSS sign, 2048-bit | pool key 0 | random pool key |
| 5/6 | AES-128/256-GCM seal, 64 B | zero key and plaintext | random |
| 7 | ChaCha20-Poly1305 seal, 64 B | zero key and plaintext | random |
| 8/9 | AES-GCM / ChaCha open with bad tag | first tag byte wrong | last tag byte wrong |
| 10 | HMAC-SHA256 | zero key | random key |
| 11 | Finished verify | first byte wrong | last byte wrong |
| 12 | empty (negative control) | zero bytes | random bytes |
| 13 | positive control: loop count = low nibble of a secret byte | 0 | random |
| 14 | RSA CRT product q*h | top byte of h is zero | full-width h |
| 15 | RSA blinder check r < n | differs from n at byte 0 | shares 128 bytes with n |
| 16 | P-256 d*G | d with 16 leading zero bits | full-width d |
| 17 | P-256 d*G | fixed random-looking d | random d |

Kinds 0–11 are the server operations themselves. Each goes through the same
entry point that the TLS server calls, including the per-signature RSA
validation and the AEAD length and tag checks. Kinds 14–17 isolate one
component.

## Rerun (macwork, Apple M4 Pro)

```sh
cd crypto/timing
bend timing_cli.bend -o /tmp/t/timing.c        # "unsafe/foreign" note is expected
../../tools/bend_native.sh /tmp/t/timing.c /tmp/t/timing
python3 keys.py /tmp/t/pool.bin --count 32      # needs Python cryptography
export BENDRTS="--threads 1"                    # counters are per thread
/tmp/t/timing <kind> <count> <seed> /tmp/t/pool.bin > o<kind>.txt
python3 ttest.py o<kind>.txt                    # --json for the full record
```

Drop the first 200 samples as warm-up (this is the default). Run several
kinds in parallel only if you accept extra cycle noise. Instruction counts
are per thread, so parallel runs do not disturb them.

There is also a count mode. Kind `100*(c+1)+k` runs kind `k` with class `c`
fixed and prints only one XOR of the results, so `/usr/bin/time -l` can
compare whole processes. For RSA, `c` selects the pool key.

`asm_lines.py program.c program.s PATTERN...` checks the generated machine
code. It maps the instructions of `clang -O3 -g -S` back to lines of emitted
C, and reports any conditional branches or selects that the compiler emitted
for masked-selection lines.
