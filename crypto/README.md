# grounds-crypto

Pure Bend cryptographic primitives. This package currently implements SHA-256, HMAC-SHA-256, HKDF-SHA-256, and the ChaCha20 block and stream functions. They are **experimental**: cookie signing and TLS still use OpenSSL while the Bend implementation is verified and its generated code is reviewed for timing behavior.

| Module | Public calls | Source |
|---|---|---|
| `sha256.bend` | `digest(bytes)`, `digest_hex(bytes)` | FIPS 180-4 / RFC 6234 |
| `hmac.bend` | `digest(key, bytes)`, `digest_hex(key, bytes)` | RFC 2104 / RFC 4231 |
| `hkdf.bend` | `extract(salt, ikm)`, `expand(length, prk, info)` | RFC 5869 |
| `chacha20.bend` | `block(key, nonce, counter)`, `crypt(key, nonce, counter, bytes)` | RFC 8439 |

Byte input and output use `List<U32>` with values 0–255. The public calls return `None{}` for an out-of-range byte; `expand` also rejects a PRK other than 32 bytes or a requested length over 8160 bytes. The hash and HMAC calls return 32 bytes. The hex helpers are for diagnostics and tests; protocols should use raw bytes.

ChaCha20 requires a 32-byte key and 12-byte nonce. `block` returns 64 keystream bytes; `crypt` XORs a message with successive blocks and rejects a request that would wrap the 32-bit counter. It does **not** authenticate ciphertext. A protocol must never reuse a key and nonce pair; use an AEAD construction once Poly1305 and tag verification are ready.

Run `moon run crypto:check --force`. The check proves that SHA-256 state output is always 32 bytes, compiles the native adapters, tests invalid-byte handling, compares SHA-256 against four published vectors and boundary/binary cases, compares HMAC against RFC 4231 and Python, and checks three RFC 5869 extract/expand vectors plus output-length boundaries. The million-`a` SHA-256 vector exercises a multi-block message.

The check also proves the RFC 8439 quarter-round example, compares the ChaCha20 block and stream functions with RFC 8439 vectors, and checks additional block and stream cases against OpenSSL on native and, when Bun is installed, JS targets. It checks malformed key/nonce lengths and counter limits.

This is correctness evidence for tested inputs, not a proof of constant-time execution or production security. The current compiled CLI has reference-counted constructors (`json/scripts/cold.py` reports hot types), so byte representation and throughput need more work. The next gates are Poly1305 and authenticated encryption, generated-code timing review, throughput work, and integration with cookie signing before replacing its OpenSSL effect.
