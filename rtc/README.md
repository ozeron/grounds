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

`ice_binding.bend` builds authenticated ICE Binding requests from `Credentials{local, remote, password}`, `Check{priority, role}`, a 12-byte transaction ID, and an integrity mode. `password` is the remote peer's password; USERNAME is `remote:local`. PRIORITY is supplied by the caller for the prospective peer-reflexive candidate and must be 1–2^31−1. `Controlling{high, low}` and `Controlled{high, low}` emit exactly one role attribute; the two U32 words form the big-endian 64-bit tie-breaker without using an oversized Bend Nat. These initial checks omit USE-CANDIDATE; nomination is later work.

Credential validation uses the [RFC 8839 SDP grammar](https://www.rfc-editor.org/rfc/rfc8839.html#section-5.4): ASCII letters/digits/`+`/`/`, local ufrag 4–32 characters, remote ufrag 4–256, and remote password 22–256. The caller exchanges credentials through signaling and supplies their required randomness and a session tie-breaker; syntax checks do not establish entropy. ASCII ICE credentials need no Unicode preparation. The generic STUN authentication interface still accepts already prepared byte keys.

`ice_client.bend` performs a single authenticated UDP exchange. `request(host, port, ms, credentials, check, mode)` generates a transaction ID and binds/closes its own socket. `exchange(socket, transaction, host, port, ms, credentials, check, mode)` instead returns `(socket, result)` so the caller can retain the same bound port. Both require an IPv4 literal and accept a mapped address only after source, transaction, success-class, response algorithm, HMAC and required FINGERPRINT checks. Decoding uses only authenticated attributes. Invalid datagrams are discarded while waiting for a valid response; they do not reset the deadline. Waiting is also bounded at 65,536 received datagrams. Invalid configuration, timeout, exhausted receive turns or wire send/receive failure yields `None{}`; bind/RNG failures in the convenience request propagate as IO errors.

```python
import ../rtc/ice_client.bend as Client
import ../rtc/ice_binding.bend as Ice
import ../rtc/stun_auth.bend as Auth
import ../rtc/stun.bend as Packet

# Synthetic example credentials; port must belong to a cooperating ICE peer.
credentials = Ice.Credentials{"localFrag", "remoteFrag", "SyntheticPassword123456789"}
check = Ice.Check{1845494271, Ice.Controlling{4275878552, 1985229328}}
reply : Maybe<&2, Packet.IPv4> <- Client.request("127.0.0.1", 50000, 1000, credentials, check, Auth.Dual{})
```

`ice_reliable.bend` adds a separate retained-socket retry API:

```python
import ../rtc/ice_reliable.bend as Reliable
import ../rtc/stun_retry.bend as Retry

reply : Reliable.Reply() <- Reliable.exchange(socket, transaction, "127.0.0.1", 50000,
  Retry.default(), credentials, check, Auth.Dual{})
# reply contains the same owned socket and an explicit outcome.
```

`request(host, port, policy, credentials, check, mode)` instead generates the
transaction and binds/closes its own socket. The original `ice_client.bend`
API retains its single-send behavior. A reliable transaction signs once and
resends identical bytes from the same socket. `stun_retry.bend` supplies the
[RFC 8489 section 6.2.1](https://www.rfc-editor.org/rfc/rfc8489.html#section-6.2.1)
default: RTO 500 ms, seven total sends (including the first), exponential
backoff, and a final wait of 16 times the initial RTO. Send times are
0/500/1500/3500/7500/15500/31500 ms; timeout is 39500 ms. Monotonic deadlines
are anchored before each send, and invalid traffic does not reset them. Late
OS wakeups shift subsequent sends; this synchronous API owns receives for one
transaction and discards other traffic rather than multiplexing it.

`Policy{rto, requests, final_factor}` permits RTO 500–60000 ms, 1–16 total
requests and a final factor 1–64; larger or zero values are rejected before
sending. These bounds keep OS timeouts and total duration representable.
The 500 ms minimum follows [RFC 8445 section 14.3](https://www.rfc-editor.org/rfc/rfc8445.html#section-14.3).
The caller must calculate the appropriate ICE RTO for its candidates/checklist;
this API does not supply checklist pacing or a generic STUN RTT estimator/cache.

`Outcome` distinguishes `Received{response, algorithm}`, `TimedOut{}`,
`IntegrityViolation{}`, `TransportError{code}`, `FloodLimit{}` (65,536
receive/timer turns across the whole transaction), and `InvalidInput{}`. Correlated response envelopes with
missing/incorrect integrity are discarded while retries continue. If no
acceptable response arrives before exhaustion, this is `IntegrityViolation{}`
rather than `TimedOut{}`, as required by RFC 8489 section 9.1.4. Unrelated
source/transaction/class or invalid CRC/envelope traffic cannot set that flag.
A subsequent acceptable response still completes normally. The socket is
returned on every outcome. An authenticated, correlated response terminates the transaction:
`Success{address}`, `Error{code}` or `Invalid{}` for unusable protected response
structure. `ice_response.bend` validates ERROR-CODE class/number and UTF-8
reason length, ignores reserved bits and later duplicate ordinary attributes,
and rejects unknown comprehension-required attributes. It understands base
RFC 8489/ICE required attributes; other extensions need explicit support.
Only protected attributes are processed; unknown optional and unexpected known base attributes are ignored. Bad source/transaction/algorithm,
integrity or FINGERPRINT packets are discarded. An authenticated error such as
487 is returned to the caller immediately; role switching and a new transaction
remain caller work. An accepted response also returns its single authenticated
`Legacy{}` or `Sha256{}` algorithm. The caller must retain it for subsequent
transactions to the same IP/port (RFC 8489 section 9.1.5); retries themselves
always preserve the original packet. No automatic redirection or server-error transaction retry
is performed. Bind/RNG errors in `request` still propagate as IO errors.

Candidate-pair/checklist management, triggered checks, role-conflict resolution,
nomination, consent/restart, shared-socket demultiplexing/cancellation, TURN,
IPv6, DTLS/SCTP, media protocols and browser interoperability remain unfinished. Generated-code timing safety is unproven;
the live checks use synthetic local credentials.

`moon run rtc:check --force` checks the RFC 5769 IPv4 Binding response and malformed inputs in Bend, then uses a separate Python UDP responder to verify two random Binding requests, source port mapping, and rejection of wrong transaction IDs and sources. RFC 5769 request and response HMAC and FINGERPRINT values pass on native and Bun JS; changed content, MAC, key, and CRC fail. Both signers reproduce the legacy RFC request byte for byte.

The SHA-256 vector uses [RFC 8489 Appendix B.1 with verified erratum 6268](https://www.rfc-editor.org/rfc/inline-errata/rfc8489.html#appendix-B.1), correcting its message length, adding PASSWORD-ALGORITHM and updating its MAC. Native and Bun run 139 independent stdlib Python comparisons and rejection cases, including the corrected vector, padding/hash boundaries, dual integrity, response policy, ignored attributes after integrity and the maximum 65,532-byte STUN body. This is a STUN format maximum; an IPv4 UDP payload has a smaller transport limit. SHA-256 byte traversals use the crypto package's tail-recursive helpers to avoid JS stack overflow.

Each target also runs 51 byte-exact ICE builder cases covering credential limits, username direction, priority, transaction length and both roles with 64-bit extreme values. A separate Python UDP responder independently checks outgoing request HMACs and attributes, signs responses, and exercises 29 success/rejection/recovery cases plus two exchanges on one retained socket. Tests reject missing/bad integrity or FINGERPRINT, wrong source/transaction/key/algorithm/class, response USERNAME, dual-integrity responses, malformed input and unsigned mapped addresses. They check recovery after invalid packets, randomized transaction IDs, deadline behavior under repeated bad MACs, and bound-port reuse. This proves an authenticated ICE Binding transaction slice on native and Bun, not full ICE or end-to-end WebRTC.

The reliable API additionally runs 154 compiled schedule/vector/boundary cases
per target and an independent UDP evaluator covering loss of the first or first
two packets, exact byte/socket reuse, every default retry and the real 39.5-second
timeout, invalid-traffic floods, authenticated and unauthenticated errors,
response attribute/UTF-8 failures, and late-response isolation while reusing a
socket after timeout. These are synthetic transaction tests; they do not prove
checklist pacing, timing safety or browser interoperation.
