# grounds-rtc

Early pure Bend WebRTC protocol work. `stun.bend` parses RFC 8489 STUN datagrams, validates the 20-byte header, declared length, magic cookie, attribute boundaries and padding, and decodes IPv4 `XOR-MAPPED-ADDRESS`. It builds a Binding request with a caller-supplied 96-bit transaction ID. `stun_client.bend` generates that ID with Bend Base's host RNG, sends one unauthenticated Binding request over `grounds-wire` UDP, checks the source and transaction ID, and returns the mapped IPv4 address.

`stun_integrity.bend` verifies the legacy HMAC-SHA1 `MESSAGE-INTEGRITY` attribute over the RFC-adjusted header and preceding attributes. It rejects a missing or duplicate attribute and refuses to treat a message with `MESSAGE-INTEGRITY-SHA256` as SHA-1-only. The caller supplies the already prepared credential key. This verifier is not yet wired into the discovery client, which sends no authenticated request.

`stun_fingerprint.bend` validates an optional final `FINGERPRINT` attribute with the RFC 8489 CRC-32/XOR calculation. It rejects duplicate, misplaced, incorrectly sized, and incorrect fingerprints. FINGERPRINT distinguishes packet types; it does not authenticate a peer.

`stun_sign.bend` preserves the legacy HMAC-SHA1 signer and final `FINGERPRINT`. The caller must construct the required credential and ICE attributes before signing.

`stun_auth.bend` adds SHA-256 and dual-integrity signing and authentication. Its `Mode` is `Legacy{}`, `Sha256{}`, or `Dual{}`. Use dual requests unless an external mechanism has established a shared algorithm. `seal(raw, key, mode)` appends integrity without FINGERPRINT; `sign(raw, key, mode)` also adds the final FINGERPRINT. Dual packets contain SHA-1 before SHA-256, with the header length adjusted separately for each HMAC and CRC. SHA-256 uses the full 32-byte value; truncated usages are not supported. Already sealed packets, malformed envelopes, invalid key bytes and body-length overflow are rejected.

`authenticate(raw, key, mode)` returns a parsed packet containing only ordinary attributes before the first integrity field, or `None{}`. SHA-256 takes precedence when both are present; a bad SHA-256 never falls back to SHA-1. Duplicate or incorrectly ordered integrity fields and misplaced/bad fingerprints fail. `authenticate_response` additionally requires a response class, a single integrity algorithm and no authenticated USERNAME. Single-algorithm modes require the matching algorithm; dual mode permits either response algorithm. The caller supplies the prepared key and remains responsible for credential lookup, transaction/source correlation and STUN usage rules. These functions do not derive long-term keys or implement Unicode credential preparation.

```python
import ../rtc/stun_client.bend as Stun
import ../rtc/stun.bend as Packet

reply : Maybe<&2, Packet.IPv4> <- Stun.request("127.0.0.1", 3478, 1000)
```

Pass an IPv4 address as the host, rather than a DNS name: the current client compares the response source directly. A timeout, malformed response, wrong transaction, or wrong source returns `None{}`. This is a single request with no retransmission. It does not validate MESSAGE-INTEGRITY or FINGERPRINT and is not yet an ICE connectivity check or a full STUN client. Do not use its unauthenticated result as proof of peer identity.

`moon run rtc:check --force` checks the RFC 5769 IPv4 Binding response and malformed inputs in Bend, then uses a separate Python UDP responder to verify two random Binding requests, source port mapping, and rejection of wrong transaction IDs and sources. RFC 5769 request and response HMAC and FINGERPRINT values pass on native and Bun JS; changed content, MAC, key, and CRC fail. Both signers reproduce the legacy RFC request byte for byte.

The SHA-256 vector uses [RFC 8489 Appendix B.1 with verified erratum 6268](https://www.rfc-editor.org/rfc/inline-errata/rfc8489.html#appendix-B.1), correcting its message length, adding PASSWORD-ALGORITHM and updating its MAC. Native and Bun run 139 independent stdlib Python comparisons and rejection cases, including the corrected vector, padding/hash boundaries, dual integrity, response policy, ignored attributes after integrity and the maximum 65,532-byte STUN body. This is a STUN format maximum; an IPv4 UDP payload has a smaller transport limit. SHA-256 byte traversals use the crypto package's tail-recursive helpers to avoid JS stack overflow. Authenticated live ICE checks remain separate work.
