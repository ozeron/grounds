# Full Bend stack progress

Target: a native, browser-interoperable network stack with crypto, TLS/DTLS and RTC protocols authored in Bend. C/JS should only implement OS and device effects. `bounty/` is unrelated and must never be staged.

| Layer | Current state | Next proof of progress |
|---|---|---|
| `wire` | Byte TCP and IPv4 UDP effects; OpenSSL TLS effects. UDP handles all octets, zero datagrams, timeout and oversize errors. Bend Base already supplies `IO.random_u32` from the host RNG and monotonic `IO.now`. | Build a bulk random-byte helper and efficient byte storage; benchmark UDP throughput. |
| `crypto` | Bend SHA-256, HMAC-SHA-256, HKDF-SHA-256 added in `crypto/`; OpenSSL remains in live cookie/TLS paths. | Add meaningful laws, timing/throughput evidence and Bend cookie integration; then AEAD and public-key primitives. |
| `tls` | TLS client/server work through OpenSSL C effects; JS TLS returns `ENOSYS`. | Bend TLS 1.3 handshake, records, certificates, and real client/server interop; DTLS 1.2 for RTC. |
| `http` | Bend HTTP/1.1 client/server, routing, JSON, cookies, auth, CORS, multipart, SSE. | WebSocket upgrade/framing and Bend TLS/HMAC integration. |
| `rtc` | No RTC protocol package. | Raw UDP + STUN/ICE, then DTLS/SCTP data channels, then SRTP/media. |

## Evidence ledger

- 2026-09-28: `moon run wire:check --force` passed, including `udp.bend` on native and Bun JS targets. Both tested all 256 octets, a zero-byte datagram, timeout, oversize rejection and consumption, and invalid-byte rejection. UDP uses Base's socket bind/close and OS `sendto`/`recvfrom` effects, with `List<U32>` as the Bend byte representation.
- 2026-09-28: Bend Base 2.0.27 already has `IO.random_u32` (macOS `arc4random_buf`, Linux `getrandom`, JS `crypto.getRandomValues`) and `IO.now` (`io_tick` or `performance.now`). A wrapper is only needed for bulk byte output and protocol-facing error handling.
- 2026-09-28: After the UDP addition, `moon run :check --force` passed all 12 packages (4m 16s). Optional Redis live tests were skipped locally because no Redis server was running; fault and fuzz checks passed.
- 2026-09-28: `moon run crypto:check --force` passed: 29 SHA-256 standard/differential cases, 11 HMAC-SHA-256 cases, three RFC 5869 HKDF cases and seven HKDF length boundaries. SHA includes the million-`a` vector; HMAC includes a 131-byte key. `bend test.bend` passed invalid-byte, bad-PRK, overlong-output and rotate checks.
- 2026-09-28: A native file hash of one million `a` bytes matched the published digest in about 0.39 seconds on this machine. `json/scripts/cold.py` on `crypto/cli.bend` reports hot constructors (`SNIL`, `SCON`, `WCON`, `FALSE`, `TRUE`, `NIL`, `CON`, `CHR`); this is a performance gap, not a failed correctness vector.
- 2026-09-28: `crypto/PROOF.bend` proves SHA-256 state output is 32 bytes. Replacing its last four-byte word with an empty list made the proof fail; the restored source passed `moon run crypto:check --force`.
- 2026-09-28: `moon run :check --force` passed all 12 packages, including crypto (4m 44s). Optional Redis live tests were skipped because no local Redis server was running; their fault and fuzz tests passed.
- Remaining before live crypto use: independent code review, generated-code timing audit, benchmark against the existing OpenSSL path, and proof obligations. The current vector results do not establish those properties.
