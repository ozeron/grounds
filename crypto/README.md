# grounds-crypto

Pure Bend cryptographic primitives. This package implements SHA-256, HMAC-SHA-256, HKDF-SHA-256, ChaCha20, Poly1305, and ChaCha20-Poly1305 AEAD. They are **experimental**: cookie signing and TLS still use OpenSSL while the Bend implementation is verified and its generated code is reviewed for timing behavior.

| Module | Public calls | Source |
|---|---|---|
| `sha256.bend` | `digest(bytes)`, `digest_hex(bytes)` | FIPS 180-4 / RFC 6234 |
| `hmac.bend` | `digest(key, bytes)`, `digest_hex(key, bytes)` | RFC 2104 / RFC 4231 |
| `hkdf.bend` | `extract(salt, ikm)`, `expand(length, prk, info)` | RFC 5869 |
| `chacha20.bend` | `block(key, nonce, counter)`, `crypt(key, nonce, counter, bytes)` | RFC 8439 |
| `poly1305.bend` | `mac(one_time_key, bytes)` | RFC 8439 |
| `aead.bend` | `seal(key, nonce, aad, plaintext)`, `open(key, nonce, aad, ciphertext, tag)` | RFC 8439 |
| `bytes.bend` | `length`, `valid`, `append`, `hex` | Tail-recursive byte-list helpers |

Byte input and output use `List<U32>` with values 0–255. The public calls return `None{}` for an out-of-range byte; `expand` also rejects a PRK other than 32 bytes or a requested length over 8160 bytes. The hash and HMAC calls return 32 bytes. The hex helpers are for diagnostics and tests; protocols should use raw bytes.

ChaCha20 requires a 32-byte key and 12-byte nonce. `block` returns 64 keystream bytes; `crypt` XORs a message with successive blocks and rejects a request that would wrap the 32-bit counter. It does **not** authenticate ciphertext. Poly1305 requires a fresh 32-byte one-time key per message. AEAD derives that key from ChaCha20 block zero, encrypts from counter one, authenticates the associated data and ciphertext, and returns plaintext only after checking all 16 tag bytes. The caller must ensure a unique nonce for every message under a key; these calls do not manage nonce allocation.

Run `moon run crypto:check --force`. The check proves that SHA-256 state output is always 32 bytes, compiles the native adapters, tests invalid-byte handling, compares SHA-256 against four published vectors and boundary/binary cases, compares HMAC against RFC 4231 and Python, and checks three RFC 5869 extract/expand vectors plus output-length boundaries. The million-`a` SHA-256 vector exercises a multi-block message.

The check also proves the RFC 8439 quarter-round example, compares the ChaCha20 block and stream functions with RFC 8439 vectors, and checks additional block and stream cases against OpenSSL on native and, when Bun is installed, JS targets. It checks malformed key/nonce lengths and counter limits.

Poly1305 passes nine RFC 8439 vectors and 34 cases against an independent bigint reference. AEAD matches the RFC ciphertext and tag, plus 12 differential records against OpenSSL ChaCha20 and the independent Poly1305 reference, including a 64 KiB seal/open on both native and Bun JS. The check rejects changed key, nonce, associated data, ciphertext and tag bytes, and bad key, nonce and tag lengths. Bend proofs cover invalid-byte rejection and basic MAC input layout. `bytes.bend` avoids JS stack overflow from Bend Base's non-tail list length and append operations on the tested 64 KiB record.

This is correctness evidence for tested inputs, not a proof of constant-time execution or production security. The current compiled CLI has reference-counted constructors (`json/scripts/cold.py` reports hot types), so byte representation and throughput need more work. The next gates are generated-code timing review, throughput work, nonce management, public-key primitives, and integration with cookie signing before replacing its OpenSSL effect.
