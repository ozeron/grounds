# grounds-rtc

Early pure Bend WebRTC protocol work. `stun.bend` parses RFC 8489 STUN datagrams, validates the 20-byte header, declared length, magic cookie, attribute boundaries and padding, and decodes IPv4 `XOR-MAPPED-ADDRESS`. It builds a Binding request with a caller-supplied 96-bit transaction ID. `stun_client.bend` generates that ID with Bend Base's host RNG, sends one unauthenticated Binding request over `grounds-wire` UDP, checks the source and transaction ID, and returns the mapped IPv4 address.

`stun_integrity.bend` verifies the legacy HMAC-SHA1 `MESSAGE-INTEGRITY` attribute over the RFC-adjusted header and preceding attributes. It rejects a missing or duplicate attribute and refuses to treat a message with `MESSAGE-INTEGRITY-SHA256` as SHA-1-only. The caller supplies the already prepared credential key. This verifier is not yet wired into the discovery client, which sends no authenticated request.

`stun_fingerprint.bend` validates an optional final `FINGERPRINT` attribute with the RFC 8489 CRC-32/XOR calculation. It rejects duplicate, misplaced, incorrectly sized, and incorrect fingerprints. FINGERPRINT distinguishes packet types; it does not authenticate a peer.

```python
import ../rtc/stun_client.bend as Stun
import ../rtc/stun.bend as Packet

reply : Maybe<&2, Packet.IPv4> <- Stun.request("127.0.0.1", 3478, 1000)
```

Pass an IPv4 address as the host, rather than a DNS name: the current client compares the response source directly. A timeout, malformed response, wrong transaction, or wrong source returns `None{}`. This is a single request with no retransmission. It does not validate MESSAGE-INTEGRITY or FINGERPRINT and is not yet an ICE connectivity check or a full STUN client. Do not use its unauthenticated result as proof of peer identity.

`moon run rtc:check --force` checks the RFC 5769 IPv4 Binding response and malformed inputs in Bend, then uses a separate Python UDP responder to verify two random Binding requests, source port mapping, and rejection of wrong transaction IDs and sources. RFC 5769 request and response HMAC and FINGERPRINT values pass on native and Bun JS; changed content, MAC, key, and CRC fail. A 65,532-byte attribute section also parses on both targets, checking the maximum STUN header length without overflowing the JS stack. Request signing and SHA-256 integrity are separate work.
