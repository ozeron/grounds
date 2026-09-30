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

`ice_candidates.bend` represents UDP/IPv4 candidates and explicit local bases.
It validates component IDs 1–256, positive priorities up to 2^31−1,
foundations of 1–32 ASCII ICE characters and IPv4 addresses/ports. Candidate
priorities follow the recommended RFC 8445 formula. Pair priorities use two
U32 words so all 64 bits survive Bend's smaller Nat representation. Foundation
assignment, candidate gathering and signaling remain caller work.

`ice_checklist.bend` exposes `build(streams, controlling, limit)`,
`begin(checklists, stream_id, pair_index)` and
`finish_check(checklists, stream_id, pair_index, success)`. Formation pairs
matching components, orders by advertised pair priority, substitutes reflexive
bases, prunes redundant pairs, and discards low ranks evenly across streams to
a configurable global limit (normally 100). Initial unfreezing chooses the
lowest component, then highest priority, in the first stream containing each
foundation. Foundation pairs are compared as two strings, avoiding ambiguous
concatenation. Successful checks unfreeze matching foundations across streams;
invalid state transitions return `None{}`. Inputs are bounded at 16 streams,
64 local and 64 remote candidates per stream, unique advertised priorities
within each side/stream, unique stream IDs and a global limit of 1–256 pairs.
Sorting retains at most the configured cap per stream while counting all unique
pairs for the global discard allocation. This bookkeeping records check results;
valid pairs, nomination and terminal checklist/agent states are still pending.
It does not choose or send ordinary/triggered checks automatically.

`ice_transactions.bend` is a pure shared-socket transaction engine. Its default
state uses Ta 50 ms and capacity 100; configurable states require Ta 5–60000 ms
and capacity 1–256. `start` validates/signs once and returns `Ready{step}`,
`Later{at}` for pacing, or `Rejected{}`. Each active transaction needs a unique
token and a fresh 96-bit transaction ID. `tick(state, now)` emits at most one
retransmission per turn, with a 5 ms minimum between send commands;
`receive(state, host, port, bytes, now)` correlates Binding responses by exact
source/transaction and authenticates them before producing the existing
reliable outcomes. Invalid input cannot move deadlines. A packet processed at
or after the final deadline cannot revive that transaction. `cancel` and
`failed` retire only the named transaction. Unmatched responses, malformed
packets, incoming requests and media return byte-exact `Datagram` notices.
These notices are untrusted input; no incoming ICE server authentication is
implied. Completed results include the negotiated response algorithm, which
the caller must retain for subsequent requests to that peer.

`ice_socket.bend` executes `Send` notices with OS UDP effects, acknowledges the
actual send completion timestamp, and suppresses commands invalidated before
execution. `execute(socket, step)` and `poll(socket, state, cap_ms)` each return
the owned socket and a `Step{state, events}`. Successful sends become `Sent`
notices; send failures terminate only the affected transaction. A receive
failure emits `SocketFailure` and terminates every active transaction; an
oversize datagram error is consumed without changing them. The caller handles
notices between bounded turns and closes the socket on every terminal path.
Pacing is shared by transactions in one engine; coordinating multiple engines
and agents remains caller work. Deadline selection uses comparisons, avoiding
Base's native recursive Nat.min/max reconstruction at large monotonic clock
values. `examples/ice_shared.bend` demonstrates two checklist checks over one
socket; it is a local fixture, not a complete ICE agent.

`ice_incoming.bend` handles incoming Binding requests through
`receive(raw, Secret{ufrag, password}, local_role, observed_source)`. The secret
contains the local session password, separate from outgoing remote credentials.
It validates local credential syntax and the observed IPv4 endpoint, requires a
valid final FINGERPRINT, processes only protected ordinary attributes and checks
that USERNAME has the local fragment followed by a valid remote fragment.
This permits a response before receiving the peer's answer. SHA-256 takes
precedence over SHA-1, with no fallback after a failed SHA-256. Only a successfully
authenticated request can expose metadata or request a role switch.

`Accepted{reply, request, role, switched}` contains a signed IPv4 mapping response
and the authenticated transaction, remote fragment, priority, peer role,
USE-CANDIDATE flag and selected algorithm. `Rejected{reply, code, authenticated}`
contains an error response; missing credential fields produce unsigned 400,
unknown usernames/bad MACs produce unsigned 401, and authenticated malformed
ICE fields, unsupported required attributes and role conflicts produce signed
400/420/487. Error 420 includes UNKNOWN-ATTRIBUTES. Ordinary duplicates use the
first value; unknown required attribute types are reported in wire order,
including repeats. Unknown optional and known-but-unexpected base attributes are
ignored. Responses omit USERNAME, use exactly one integrity algorithm when
signed, and end with FINGERPRINT. Malformed envelopes, invalid/missing CRC and
non-Binding-request classes/methods return `Ignored{}`; invalid local configuration
or observed endpoints return `InvalidInput{}` without a reply.

`ice_roles.bend` compares tie-breakers as two U32 words and resolves incoming
role conflicts, including equality, according to [RFC 8445 section 7.3.1.1](https://www.rfc-editor.org/rfc/rfc8445.html#section-7.3.1.1).
A server-side role switch retains its own tie-breaker and is reported with the
accepted request. The session owner must apply it and recompute pair priorities
before scheduling another check. The interface makes no checklist/session
mutation, valid-pair or nomination claim. USE-CANDIDATE is authenticated intent;
receiving it alone does not nominate a full-agent pair.

The caller owns session lookup, credential expiry/restart and signaling binding,
uses the actual observed source for the XOR mapping, sends replies from the same
bound socket, and handles only accepted metadata as trusted ICE input. A valid
request's remote fragment is exposed even before an answer; binding deferred
triggered work to the later peer credentials remains agent work. This stateless
receiver produces byte-identical responses to identical retransmissions; the
agent must deduplicate triggered work and manage replay/lifecycle state.
`ice_candidates.address_read` accepts canonical dotted IPv4 UDP source strings
and rejects DNS, IPv6, noncanonical octets and invalid ports. Relay observations
must eventually come from TURN's authenticated peer metadata, rather than a
relay server's UDP address.

The next agent integration includes stable pair identities and ordinary/triggered
selection, role-switch priority recomputation and client-side 487 retries,
dynamic/valid pairs, nomination, consent/restart, candidate gathering, TURN,
IPv6, DTLS/SCTP, media protocols and browser interoperability. Generated-code
timing safety is unproven; live checks use synthetic local credentials.
Formation and initial state rules follow [RFC 8445 sections 5.1.2 and 6.1.2](https://www.rfc-editor.org/rfc/rfc8445.html#section-6.1.2).
The [2026-09-30 errata search](https://errata.rfc-editor.org/search/?rfc_number=8445&presentation=records) lists only reported editorial erratum 7526 about a
broken reference link, with no verified protocol correction. The later agent
must also implement the PAC timer from [RFC 8863 section 4](https://www.rfc-editor.org/rfc/rfc8863.html#section-4)
before declaring checklist/session failure; individual failed checks do not
establish ICE failure.

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

The checklist model runs 132 independent full-sort reference fixtures per
target, including candidate/pair priority bounds and bigint ranks, reflexive
pruning, multi-stream/component foundation states, tight caps, malformed input,
seeded randomized sets and the maximum 16×64×64 candidate combinations. The
clock fixture runs 32 cases per target for exact Ta/RTO gates, large timestamps,
final response boundaries, send acknowledgement, duplicate tokens/transaction
IDs, cancellation and transport failures. Ten independent real UDP cases per
target run overlapping checks over one bound socket, including reordered
responses, loss, authentication failures, error 487 reporting, timeouts,
cancellation before/after sending, and byte-exact delivery of interleaved
requests/media/invalid or wrong-source packets. The large raw UDP case is 8 KiB
because macOS defaults `net.inet.udp.maxdgram` to 9216 bytes; format-maximum STUN
checks remain in the authentication suite. These are foundation tests; they do
not complete full checklist scheduling, role handling, nomination or browser ICE.

Incoming processing runs 308 independent compiled cases per target for
legacy/SHA-256/dual authentication, exact success/error response bytes, credential
and field rejection, integrity-boundary filtering, large protected payloads,
64-bit role/equality cases, nomination syntax, source mapping and canonical
source parsing. The independent duplex UDP test keeps an outgoing check active
on the same socket while handling invalid CRC, unsigned authentication errors,
a protected role conflict, pre-answer success, duplicate requests and both role
switches. Incoming traffic cannot consume the outgoing response: its correct
MAC from the wrong source stays raw, its 500 ms retry preserves bytes/port, and
the correct source completes it. Both targets close and release the bound port.
This verifies incoming authentication and role decisions; triggered queues,
priority changes, valid pairs and nomination state still need agent integration.
