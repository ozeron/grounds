<p align="center"><img src="assets/grounds.svg" width="160" alt="grounds: coffee grounds pouring onto a mound"></p>

# grounds

A monorepo of [Bend 2](https://github.com/bendlang/bend) packages: JSON, UTF-8, TCP/UDP, HTTP/1.1, Redis, cryptographic primitives, and early RTC protocols. json, http and redis prove their guarantees in `LAWS.bend`; each package has its own README.

| Package | Does |
|---|---|
| [`json`](json/) | JSON parse, print, path reads; proven to round-trip |
| [`utf8`](utf8/) | strict UTF-8 decoding |
| [`io`](io/) | whole-file reads |
| [`wire`](wire/) | TCP and UDP on raw bytes |
| [`crypto`](crypto/) | pure Bend SHA-1, SHA-256, HMAC-SHA1/SHA256, HKDF-SHA-256, ChaCha20-Poly1305 AEAD and X25519; experimental, not yet used by TLS or cookies |
| [`http`](http/) | HTTP/1.1: messages, parsing, server, client, router, JSON bodies and WebSocket server transport |
| [`redis`](redis/) | Redis client: RESP2 and RESP3, pipelining, a pool; proven framing |
| [`rtc`](rtc/) | STUN SHA-1/SHA-256/dual authentication, FINGERPRINT, UDP discovery and authenticated ICE Binding exchanges; candidate pairs, nomination, DTLS, SCTP and media remain |

```sh
mise install        # pinned bend and moon
moon run :check     # every package's tests, laws and examples
```

For local builds and checks, use the [resource guard](tools/README.md) to keep
jobs sequential and stop their process group at a measured memory cutoff.

From BendHub, 0.1.0 is one bundle, `0x64e1b9e0466cf913fa57e70aeb11c176` (tag `grounds/v0.1.0`). Take every module from that one bundle.
