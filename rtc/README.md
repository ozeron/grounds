# grounds-rtc

RTC's Moon check inputs cover the five crypto modules actually imported by its
Bend sources: bytes, SHA-1/SHA-256 and HMAC-SHA1/HMAC-SHA256. Changes to these
still invalidate RTC checks. Changes to an unused TLS primitive no longer
require the entire RTC build/test suite. `check_inputs.py` walks all local Bend
imports, including transitive and nested crypto modules, and fails before the
suite if a required crypto file is absent from `rtc/moon.yml` inputs. Update
that declaration whenever adding an imported dependency. The guard's regression
checks cover transitive additions, nested glob scope and unused primitives.
All existing native/Bun/browser protocol checks remain in `check.sh`; this
input change does not remove a verification scenario.

The local signaling evaluator is in `examples/signaling_server.bend`. It checks
an exact Host and Origin and one synthetic fixture cookie before the WebSocket
upgrade or UDP allocation. Each upgraded connection owns one retained IPv4 UDP
base and one `signaling.State`; offers use `["offer", revision, SDP]` and answers
use `["answer", SDP]`. Revision zero creates the owner. Subsequent revisions must
increase by one, replace both remote ICE credentials, preserve MID/SCTP port and
the peer fingerprint, and supply fresh local host-generated credentials. The
answer's successful socket write starts local-signaled PAC timing. Reconnects
create independent owners. A rejected message closes its connection.
Fresh offers now obtain 32 bytes through `wire_random_bytes` in one bounded OS
request. Bend converts them into the 64-bit local fragment, 128-bit password and
64-bit tie-breaker; entropy failure rejects the offer and closes the connection.

`sdp.decode` accepts one `application UDP/DTLS/SCTP webrtc-datachannel` section,
session-level credential/fingerprint/setup defaults with media overrides, one
MID, SHA-256 fingerprints and an `actpass` offer. Duplicate required attributes
at either level fail admission. Limits are 16,384 SDP characters, 128 lines,
1,024 characters per line and 64 candidate lines, including ignored candidates.
Candidate integers are bounded before conversion; canonical IPv4 UDP candidates
are admitted, IPv6/DNS/TCP and unknown candidate kinds are reported as ignored,
and unknown extension name/value pairs are ignored. Related addresses are
required for reflexive/relay candidates and forbidden for host candidates.
The decoder extracts this explicit ICE profile; it is not a general SDP validator
or an implementation of media negotiation, BUNDLE multiplexing or trickle ICE.

Exact token comparisons and separate line/state dispatch keep this decoder's
compiler workload bounded on the development host. The SDP native fixture uses
`tools/bend_native.sh` to release the Bend frontend before C compilation;
native and Bun run the same admission, malformed-input and bound cases. Run
checks through the memory guard described in [tools/README.md](../tools/README.md).

Fixture formatting and host entropy helpers live in separate `examples/*_output.bend`
and `examples/ice_entropy.bend` modules; original CLI helper interfaces forward to
them. Signaling uses the bounded retained-socket operations in
`examples/ice_transport_effects.bend`, copied from the UDP fixture, rather than
importing that fixture's entire CLI. The protocol owners and their send/reply,
consent and restart decisions remain in the same Bend modules. Package checks
still include every existing CLI and browser scenario.

The latest guarded full RTC run passes type/admission checks and native SDP,
then reaches the memory cutoff during signaling C emission. Its new signaling
runtime and browser checks remain pending; [STACK_PROGRESS.md](../STACK_PROGRESS.md)
records the current commands, evidence and remaining compiler work.

The adapter caps upgraded fixture connections at eight using the server's live
connection counter, text messages at 32,768 bytes, frames at 64, revisions at
0–7 and each connection lifetime at 45 seconds. Restarts never extend that
lifetime. It supports unfragmented text signaling, ping/pong and valid close
frames; fragmented/binary signaling is rejected. Existing general-purpose
WebSocket framing/session APIs retain their behavior. Close, stop and deadline
discard the transport and close both sockets; tests rebind the actual UDP port.

Run `sh examples/build_signaling.sh /tmp/grounds-signaling` and start that
binary. On Apple Clang 21 arm64 the fixture build emits Bend C and uses
`-O3 -fno-stack-check`: the compiler's Darwin stack probe conflicts with live
registers in the generated `preserve_none` runtime function `WL_FID_ENTER`.
Default `-O3`, `-O1`, `-O0` and disabled shrink wrapping all reproduced the
backend failure; the explicit stack-probe workaround compiled the same C.
This disables compiler-inserted stack probes for this evaluator only. It is a
build limitation, not a memory/timing safety finding resolved for the full stack.
Other checks retain Bend's normal native build. The generated-runtime ABI and
stack behavior remain part of the required review before production acceptance.
The fixture uses port 8089, accepts Origin `http://127.0.0.1:8089` and
cookie `grounds-fixture=local-synthetic-session`, and binds its UDP base to
127.0.0.1. The current HTTP listener's OS effect listens on all interfaces; the
cookie is a public synthetic test selector, not deployable authentication.
This is plaintext HTTP/WS and ICE only. The answer renderer is explicitly a
fixture in `examples/signaling_answer.bend`: it advertises a public placeholder
fingerprint and does not implement DTLS. Production authentication, Bend
cookie/HMAC, HTTPS/WSS, DTLS fingerprint verification, data and media remain open.

`examples/signaling_browser_check.mjs` launches an isolated real Chrome profile,
uses the browser's ICE implementation as a peer, and records offers, answers,
actual selected `RTCIceTransport` pairs and server packet logs. It checks denied
authentication/Origin, initial nomination, fresh consent, credential restart,
reconnect, malformed signaling and closure. `signaling_browser_packets.py`
independently validates both generations' HMAC-SHA1, FINGERPRINT, USERNAME,
transactions, controlling nomination and role-free consent. A selected pair is
combined with authenticated packet evidence; DTLS/data/media are not claimed.
Run `bun examples/signaling_browser_check.mjs <evidence-dir> <server-command...>`
then `python3 examples/signaling_browser_packets.py <evidence-dir>`. Set
`GROUNDS_CHROME` to a Chrome executable outside the default macOS location.
`check.sh` runs native/Bun admission and socket tests and this browser evaluator
when Chrome and Bun are available; an unavailable browser is explicitly skipped
and cannot satisfy the full stack contract.

The profile follows [RFC 8839](https://www.rfc-editor.org/rfc/rfc8839.html),
[RFC 8866](https://www.rfc-editor.org/rfc/rfc8866.html),
[RFC 8841](https://www.rfc-editor.org/rfc/rfc8841.html) and the
[WebRTC selected-pair API](https://www.w3.org/TR/webrtc/#dom-rtcicetransport-getselectedcandidatepair).
On 2026-10-01 the RFC Editor's current errata service returned no verified
records for those three RFC numbers. Query the current
`https://errata.rfc-editor.org/search/?rfc_number=<number>&status=verified`;
the legacy `errata_search.php` redirects its old status selector to Reported.

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

`ice_binding.bend` builds authenticated ICE Binding requests from `Credentials{local, remote, password}`, `Check{priority, role}`, a 12-byte transaction ID, and an integrity mode. `password` is the remote peer's password; USERNAME is `remote:local`. PRIORITY is supplied by the caller for the prospective peer-reflexive candidate and must be 1–2^31−1. `Controlling{high, low}` and `Controlled{high, low}` emit exactly one role attribute; the two U32 words form the big-endian 64-bit tie-breaker without using an oversized Bend Nat. The original `request` API omits USE-CANDIDATE.

`intent_request(transaction, credentials, check, nominate, mode)` is additive.
False intent produces identical ordinary bytes; True includes one empty
USE-CANDIDATE before the integrity fields and FINGERPRINT. A controlled request
with True intent returns `None{}`. `Check` retains its original two fields.
This implements [RFC 8445 section 7.1.2](https://www.rfc-editor.org/rfc/rfc8445.html#section-7.1.2),
not nominated/selected agent state.

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
pairs for the global discard allocation. This formation API records check results;
the valid-list and lifecycle owners below supply valid paths, nomination and
terminal state. It does not send ordinary/triggered checks automatically.

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

`start_intent` additionally takes a nomination Bool after `check`, preserving
the original transaction state and start interface. It signs intent once and
retains those exact bytes through pacing, retries and response-only listening;
it uses the same capacity, identity, deadline and acknowledgement rules.

`stop_retries(state, token)` implements the response-retention part of
[RFC 8445 triggered-check interruption](https://www.rfc-editor.org/rfc/rfc8445.html#section-7.3.1.4).
It changes an active entry to `Listening`, emits `Stopped` once and suppresses
both retries and already queued sends. The final deadline is the current
scheduled wait plus all remaining retry waits, frozen at interruption; delayed
retries already reflected in the schedule stay reflected. Repeated interruption
cannot move that deadline. Default immediate interruption retains responses for
39.5 seconds. The original source, transaction ID, credential key and permitted
algorithms remain required. Authenticated success/error/malformed response results
received before the deadline become `LateResponse{token, response, algorithm}`,
separate from active-check `Finished` outcomes. Invalid traffic stays raw and
cannot extend the window or turn retirement into an integrity failure. At the
deadline, `Retired{token}` releases the entry without reporting pair failure;
late correlated packets are returned raw. Unrelated packets do not route to the
entry, so the next timer tick performs its retirement.

Listening entries still count against capacity and reserve their token and
transaction ID. The session owner must budget retained transactions, keep pending
triggered work queued under capacity pressure, and explicitly discard listeners
on restart/cleanup using `cancel`. `failed` and socket-wide failures retire
listeners without manufacturing active-check failure outcomes. The caller must
bind late response metadata to its original pair, generation and sent role;
none of these notices resets or completes a checklist automatically.

`ice_socket.bend` executes `Send` notices with OS UDP effects, acknowledges the
actual send completion timestamp, and suppresses commands invalidated before
execution. `execute(socket, step)` and `poll(socket, state, cap_ms)` each return
the owned socket and a `Step{state, events}`. Successful sends become `Sent`
notices; send failures terminate only the affected transaction. A receive
failure emits `SocketFailure`, terminates every active transaction and retires
response-only listeners; an
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

`ice_pairs.bend` gives checklists formed by `Check.build` transport references
`Ref{stream, component, base, remote}` that do not depend on priority, foundation
or list position. `lookup` resolves the current pair and index only when the
endpoint match is unique; missing or ambiguous matches return `None`.
`begin` and `finish_check` use these references with the existing state guards
and foundation thawing. Saved references continue to target the same pair after
`reorder(checklists, controlling)` recomputes ranks from advertised candidate
priorities and sorts each stream for a role change. Reordering retains every
candidate and check state; it does not prune, reset initial states or mutate
queues. Reflexive advertised priorities remain distinct from their sending
bases. References belong to one ICE generation and must be discarded on restart.
If distinct remote candidate records alias an endpoint, the owner must resolve
that ambiguity before using the reference; these helpers cannot choose a record
on its behalf. Existing index-based checklist interfaces remain available.

`ice_scheduler.bend` adds pure scheduling and current-attempt ownership for
bounded IPv4 checklists. `create(streams, role, limit, generation)` uses the
existing formation limits and rejects ambiguous endpoint identities. Each stream
has a deduplicated FIFO triggered queue. `trigger(state, reference)` keeps a
Succeeded pair unchanged; it moves Frozen, Waiting, Failed or In-Progress pairs
to Waiting and queues their stable reference. Interrupting In-Progress work
returns its old token and removes only its current scheduler flight. The owner
must call `Tx.stop_retries` and keep the old transaction metadata until a late
response or retirement; the scheduler does not own retained response correlation.

`select(state)` returns `Selected{state, reference, token, role}`, `Idle{state}`
or `Rejected{}`. It advances round robin through streams, choosing the triggered
FIFO head before ordinary work in that stream. Ordinary selection chooses the
highest Waiting rank, with the lowest component breaking a rank tie. When a
stream has no Waiting pairs, it thaws Frozen pairs sequentially only for
foundations with no Waiting or In-Progress pair anywhere in the checklist set.
It skips streams without work within the same scheduling opportunity. All
checklists here are schedulable; the owners below supply valid/nominated pairs
and terminal/PAC state. Idle is not a declaration of ICE success or failure.
These rules follow [RFC 8445 section 6.1.4.2](https://www.rfc-editor.org/rfc/rfc8445.html#section-6.1.4.2).

Selection is speculative: commit the returned scheduler state only when the
paced transaction engine accepts the new check. On `Tx.Later` or `Tx.Rejected`,
retain the original scheduler state so its queue, pair state, cursor and token
are unchanged. The scheduler owns no clocks or sockets and supplies no Ta/RTO
policy; the owner must use negotiated/default Ta, shared send spacing and a
valid ICE RTO policy. Preserve Idle's returned state if selection thawed pairs.
Within a generation, U32 tokens never repeat and exhaustion rejects new work.
Each flight records the role used by that attempt. `complete(state, token,
generation, success)` accepts only a current flight in the matching generation,
then applies the existing completion/foundation-thaw rules. An interrupted old
token cannot complete or fail its replacement, even after priority reordering.
The owner must discard all scheduler and transaction state together on restart.

`nominate(state, reference, generation)` is a separate scheduler transition:
the owner must first choose a proven valid path. It requires the controlling
role and current generation, repeats the original check even when its pair is
Succeeded, deduplicates the triggered FIFO, and returns any interrupted token.
The attempts layer executes response-only interruption and rejects a pair still
awaiting authenticated 487 repair. Incoming `trigger` keeps its original
Succeeded no-op behavior.

`switch_role` recomputes ranks while preserving queue identities and flights'
sent roles. `repair_conflict(state, token, generation, high, low)` is for a
current authenticated 487: it flips the role recorded by that attempt, requires
a different tie-breaker from both its sent and current role, reorders, and
requeues the pair. Host RNG must supply the new tie-breaker; an unrelated or
unauthenticated error cannot authorize this call. A server-side switch must
retain its tie-breaker. Capturing the sent role matters when another incoming
check has already changed the current role.

`insert_triggered(state, stream, local, remote)` inserts only the observed
Host/Relay local-base and remote-source pair, never a cross-product with other
locals. It validates candidate/component syntax, preserves existing pair
metadata for an already known endpoint and rejects missing streams, reflexive
locals or exhausted global pair capacity atomically. The owner must authenticate
the request, verify the local base is registered, bind its remote fragment to
signaled credentials, select known versus peer-reflexive remote metadata and
supply a unique learned foundation before insertion. On capacity rejection it
must retain bounded deferred work. This helper itself does not gather candidates
or authenticate input. Triggered interruption and observed-pair handling follow
[RFC 8445 sections 7.3.1.3 and 7.3.1.4](https://www.rfc-editor.org/rfc/rfc8445.html#section-7.3.1.3).

`ice_session.bend` joins the incoming authenticator, scheduler and transaction
engine for one bounded UDP/IPv4 peer generation. `create(streams, role, secret,
mode, pair_limit, transaction_capacity, generation)` returns a session without
remote credentials. It uses default Ta=50 ms, the existing 16-stream/64-candidate
formation bounds, 1–256 retained pairs/transactions and at most `pair_limit`
deferred incoming items and learned remote candidates. `ice_registry.bend`
retains the original registered bases and signaled remotes even when checklist
pruning leaves no associated pair. It rejects inconsistent metadata for a local
base and remote endpoint aliases, including aliases hidden by pair pruning.
Learned peer-reflexive foundations skip all existing remote foundations in the
generation. Learning and pair insertion commit together; a rejected insertion
cannot leak registry state or consume a learned-candidate slot.

`bind(state, Credentials{local, remote, password})` verifies that the local
fragment matches the local secret, validates credential syntax and binds the
remote password separately from the local password. Binding is immutable within
a generation; repeating identical credentials is allowed, changing any of them
returns `None`. Before an answer, accepted requests get replies immediately and
are retained in a bounded FIFO by observed pair and remote fragment. Duplicates
preserve an actually authenticated nomination request when present. Binding
drains only matching fragments, discarding unmatched work with `Unbound` notices.
A bound fragment mismatch gets the stateless authenticated reply but cannot
change roles, learn candidates or trigger an outgoing check. Full SDP forking,
trickle signaling and credential expiry/restart remain later work.

`receive(state, Ref{stream, component, actual_local_base, observed_peer}, raw,
now)` first validates the registered local base and IPv4 source. Binding requests
use the local secret; only accepted input for the selected peer (or deferred
pre-answer input) applies a server-side role decision. Known remotes retain
signaled metadata; unknown sources learn one peer-reflexive candidate using the
authenticated priority/component and insert only the observed Host/Relay pair.
Raw `Datagram{reference, bytes}` notices preserve both receiving-base and source
metadata for later protocol demultiplexing. They remain untrusted input.
Recognizing relay identities here does not implement TURN; a future relay driver
must supply its authenticated peer source, not the TURN server's UDP address.

`start(state, transaction, retry_policy, now)` waits for credentials and uses the
registered sending base's local preference with the recommended peer-reflexive
type preference 110 to construct PRIORITY. Selection commits only after the
transaction engine accepts it. `Waiting{at}` and `AtCapacity` preserve the queue,
pair state and allocator; invalid configuration/transaction input also consumes
no selection. The caller supplies a fresh 96-bit transaction from host RNG, a
valid ICE RTO/retry policy and monotonic time. The session supplies no adaptive
RTO calculation, alternate priority formula or nondefault Ta negotiation yet.

`ice_attempts.bend` retains every active/listening transaction's stable reference,
generation, sent role and original transaction ID separately from current
scheduler flights. Interrupting a flight stops its retries while preserving its
record and response correlation through the original final deadline. Responses
are correlated by transaction ID and authenticated with that original attempt's
key, algorithm and FINGERPRINT. A valid response at a different registered local
base or peer IP/port emits `NonSymmetric{record, observed, failed}` and immediately
fails only the original current pair, suppressing its retries and queued sends.
It cannot authorize 487 role repair. When the peer IP/port matches the original
destination, its first authenticated algorithm is still selected for subsequent
requests, even though ICE fails the pair. A different peer IP/port cannot select
or overwrite the original destination's policy. An
interrupted old listener is retired with `failed=False` and cannot fail its
replacement. Unauthenticated or unrelated mismatched traffic remains raw and
cannot mark an integrity violation, move a deadline or mutate any attempt. Final
timeout/retirement still wins at its exact boundary. This implements the
transport-symmetry requirement of [RFC 8445 section 7.2.5.2.1](https://www.rfc-editor.org/rfc/rfc8445.html#section-7.2.5.2.1)
without changing the existing low-level STUN source-filtering APIs. The caller
must supply registered receiving stream/component context; an unregistered base
is invalid input. Symmetric late responses and retirement are annotated with the
original record and cannot complete/fail a replacement. Current success/error/
timeout/integrity/transport outcomes update only the current flight; none declares
whole-session success or failure.

An authenticated current 487 leaves a repairable record after the network
transaction finishes. `repair(state, token, generation, high, low)` accepts only
that pending conflict and requires a fresh tie-breaker. An equal RNG result or
wrong generation leaves repair pending without resurrecting the old transaction.
The retry flips the recorded sent role, even if another incoming request already
changed the current role, and preserves FIFO ordering after rank recomputation.
Authenticated responses also pin their first selected integrity algorithm by
remote IP/port. Subsequent requests to that endpoint use only the negotiated
algorithm; already signed in-flight retries retain their original bytes/mode.
A late reply cannot overwrite an established endpoint policy. This follows
[RFC 8489 section 9.1.5](https://www.rfc-editor.org/rfc/rfc8489.html#section-9.1.5).

`tick`, `failed`, `timeout`, `current_send` and `acknowledge` expose the owned
transaction loop. `current_send` suppresses stale directives after interruption
or completion. Call `acknowledge` only after executing the exact current Send
successfully; it updates pacing from actual OS send time. Send notices carry
their retained record so an effects owner routes them from the registered base;
Reply notices carry the receiving reference. The two-socket UDP example shows
this loop, host RNG conflict repair and cleanup using local synthetic fixtures.
It now uses `wire_udp_bind` with explicit IPv4 addresses and obtains each actual
local address/port through `wire_udp_local_address` before forming candidates.
The receiving socket's explicitly bound unicast IP supplies actual base identity;
wildcard addresses are rejected by this fixture. It can bind port `0` and retain
the OS-assigned port for every send/receive and candidate reference. The old
seven-port/configuration arguments remain supported; nine arguments additionally
supply the two bind IPs. The second IP is chosen from bindable local addresses by
the independent Python peer helper, without changing interfaces. This is still a
fixture, not production candidate gathering, relay transport or signaling.

`ice_valid.bend` adds a pure owner around the existing session, preserving the
original `Session.State`, `A.Record` and low-level interfaces. Use
`from_session(Session.create(...), limit)` for a new generation, then its `bind`,
`start`, `receive`, `tick`, `repair`, `current_send`, `acknowledge` and lifecycle
operations. `Step{state, events, valid}` keeps the original session directives
and separate valid-list notices. The UDP fixture now executes this owner.

Before a response removes its transaction, `attempt(session, record)` reads the
actual PRIORITY and USE-CANDIDATE flag from the original signed bytes retained
by `Tx`, including response-only listeners. Record/token/generation/reference/
sent-role/transaction matching guards this metadata. A symmetric authenticated
success resolves the mapped local address against known candidates and omitted
bases; known candidates retain their advertised metadata. A new mapping learns
one local peer-reflexive candidate with the actual request priority and original
sending base, without generating candidate cross-products. Locally learned UDP
peer-reflexive foundations share the base IP and peer/server IP, ignoring ports,
components and streams, and avoid existing local foundation names. These rules
follow [RFC 8445 sections 5.1.1.3 and 7.2.5.3](https://www.rfc-editor.org/rfc/rfc8445.html#section-7.2.5.3).

Valid paths retain stream/component, mapped candidate, its base, remote candidate,
two-word rank and original attempt. They are separate from checklist transport
references, partitioned by stream and sorted by the current role's candidate
priorities. A role change reranks paths without replacing metadata. Duplicate
outcomes retain the existing path; a full list still accepts duplicates. Late
successes can add mapped paths while leaving the replacement flight and checklist
state unchanged. Untrusted, non-symmetric, wrong-transaction, expired and error
responses cannot learn a path. Every new path has `nominated=False`.

A current successful path also completes a unique checklist pair represented by
its mapped local address and remote endpoint, even when that pair differs from
the original check. Matching uses the checked local candidate after reflexive
base substitution; a reflexive mapped address cannot complete its base pair.
The counterpart becomes Succeeded from any prior state, leaves its triggered
queue and current flights, and thaws matching Frozen foundations across the
checklist set. Any redundant active transaction stops retrying but retains its
signed request and response correlation through the original deadline. Its late
success/error or retirement cannot fail the completed pair. If the counterpart
was awaiting 487 repair with no remaining network transaction, validation retires
that obsolete repair record while preserving unrelated repair work. Additional `Stopped`
notices remain in `Step.events`; stale send directives must still be checked
with `current_send`. Late original results can learn paths but never apply this
checklist transition, including when their mapping represents a different active
pair. These transitions follow [RFC 8445 section 7.2.5.3.3](https://www.rfc-editor.org/rfc/rfc8445.html#section-7.2.5.3.3).

The configurable limit is 1–256 paths and independently 1–256 learned local
candidates. Failed admission commits neither a candidate nor a foundation.
`Exhausted` and `InvalidMapping` are explicit notices: a current attempt faults
the owner and suppresses further starts/sends, so the IO owner must close its
sockets; the UDP fixture does so. An old listener's rejected mapping instead
preserves its active replacement and reports the rejection without faulting it.
This is bounded IPv4 valid-list integration, not a complete ICE agent.

`queue_nomination(state, path)` resolves the stored path identity, using its
owned original attempt rather than trusting a copied caller origin record. It
queues the original sending reference, which may differ from the mapped path's
local candidate. `start_intent(state, transaction, policy, target, now)` takes a
Maybe reference and includes USE-CANDIDATE only if the actual selected pair
after deferred work drains matches that target. Other selections remain
ordinary; a controlled target rejects without consuming the speculative queue,
pair state or allocator. Negotiated endpoint integrity and original request
PRIORITY still apply. These are scheduling/request primitives; the owner must
retain selection policy and authenticated controlled-side nomination intent,
apply nominated/selected outcomes and conclude the component. Successful intent
responses currently still produce paths with `nominated=False`.

`ice_nomination.bend` adds nomination evidence around a fresh unbound valid-list
owner. Its six-field `State` owns the valid state, bounded successful-check
associations, qualified incoming intent, retained flight bindings, pair limit and
fault status. Existing `Session.State`, `V.State` and attempt records remain
unchanged. Creation rejects a bound or already running session because importing
it would lose previously materialized intent.

Current authenticated valid results associate both the original sending
reference and any unique Succeeded mapped counterpart with the path they proved.
`path_for(state, reference)` requires the exact stream/component/base/peer,
current generation, Succeeded pair, retained valid identity and healthy owners.
It returns current stored candidate/rank metadata with the association's actual
generating record, even when duplicate insertion retained an older path origin.
Late mappings may enter the valid list but cannot replace these associations.

Applied incoming intent comes from the actual prior pending requests and
Accepted notices, merged by the session's existing rule. It qualifies only
after matching peer credentials, with local Controlled role and an actual
controlling USE-CANDIDATE request. An applied ordinary request clears prior
queued intent for that reference; speculative pacing/capacity failure preserves
it. A fresh triggered send binds the request to its exact generation, reference,
sent role, token and transaction. Retries do not duplicate bindings. Interrupted
listeners retain their original requests separately from replacement flights.
Bindings reserve at most engine capacity plus pair limit, including 487 repair
records that no longer have a network entry.

`Mapped`, `Outcome` and `NonSymmetric` notices carry the actual bound request and
original attempt before its metadata retires. Generation replacement discards
old associations/intent/bindings; that ownership guard does not implement a
complete credential restart. Used alone, these evidence primitives leave every
path `nominated=False`.

`ice_agent.bend` owns nomination and lifecycle for one registered UDP/IPv4
generation. Create it around a fresh `V.State` using `Agent.create(v,
Agent.defaults())`; its separate state preserves existing Session/V/N constructors.
The default automatic policy nominates the highest-ranked currently proven
valid path of each component when `start` is called. Set `Config{39500, False{}}`
for an application policy, then call `nominate(state, reference)` or
`nominate_best(state, stream, component)`. Only one controlling plan per component
can exist; successful nomination concludes that component until restart. A
plan resolves N's current generating record and repeats its original transport
reference, including when its authenticated mapping produced another known base.
`Session.start_intents` binds USE-CANDIDATE to whichever planned reference is
actually selected after pending work drains. Failed pacing/admission preserves
the plan. Signed cached bytes, original sent role and generation qualify success;
an ordinary check or obsolete role cannot nominate. The nominated identity is
the authenticated response's actual valid mapping. Controlled-side accepted
intent nominates its associated already-Succeeded path immediately, or the valid
path produced by its exact triggered request, including retained late listeners.

Component conclusion removes all its checklist pairs, triggered references and
pending work, stops in-progress retries and retains original response deadlines
and correlation. Unrelated components keep running. Authenticated Binding server
processing continues through `Session.reply_only` without restoring checks;
repeated accepted-path nominations succeed and new nomination paths receive a
protected 400. Previously accepted parallel nominations can still finish through
listeners; selection then uses the highest-ranked nominated path. All required
local-candidate components of a stream must be nominated before `selected` returns
a path for that stream. All streams must complete for session completion. An
unrecoverable current nomination removes its chosen valid identity, fails a
related Succeeded mapped counterpart and records component failure. Late errors
cannot fail a replacement. Current 487 remains recoverable through role repair.

Call `local_signaled(state, now)` only after sending local credentials and call
`bind(state, credentials, now)` on receipt of the remote credentials. These gates
start PAC exactly once in either order. The default is 39500 ms, as recommended
by [RFC 8863 section 4](https://www.rfc-editor.org/rfc/rfc8863.html#section-4).
`tick`, other turns and `timeout` include its monotonic boundary: Running cannot
become Failed before expiry even with no remote candidates. Expiry resumes normal
failure criteria; a valid path for every component can still await nomination.
A failed stream fails this owner's session and stops all remaining checks;
application-specific removal/continuation of failed streams is not supplied.
Valid-list exhaustion, invalid authenticated mapping and other quarantined core
faults return a distinct terminal `Faulted{}` owner status, emit a session notice
and stop all retries without declaring ICE failure before PAC. The IO owner must
release its sockets and this aborted state on that notice.
The owner requires registered local candidates to determine required components;
gathering with no local candidate and explicit component configuration are later
work. The Binding server remains active after failure and rejects new nominations.
Nomination/conclusion follows [RFC 8445 sections 7.2.5.3.4, 7.3.1.5 and 8.1](https://www.rfc-editor.org/rfc/rfc8445.html#section-8.1).

`ice_consent.bend` supplies a separate bounded consent owner for one already
selected UDP/IPv4 transport. It follows [RFC 7675 sections 5.1 and 5.2](https://www.rfc-editor.org/rfc/rfc7675.html#section-5.1).
`create(Route{reference, generation, credentials, check, mode}, initial_rto, now)`
starts `Awaiting`, with application transmission denied. This conservative
handoff requires a fresh round trip on the actual selected base; an old
nomination notice or a mapping generated from another base cannot grant a new
30-second window. Route selection and exchanged credentials must come from the
trusted ICE owner. This API does not select candidates or accept signaling's
claim that connectivity succeeded.

Call `start(state, transaction, jitter, now, not_before)`, then execute a `Send`
only if `current_send(state, notice, actual_now)` and the shared socket's dispatch
gate still permit it. `not_before` shares admission with other ICE sends; the
enclosing dispatcher must also recheck its current actual-send gate before IO.
Transaction bytes and jitter belong to trusted OS CSPRNG code and must never be
exposed to or controlled by an untrusted application or signaling server. Jitter
is 0–2000 ms, producing randomized 4–6-second intervals. The example UDP driver
uses three independent host random words for the 96-bit identifier and another
for jitter. Its synthetic debug output is a test interface, not an application
API. A recent 64-ID cache rejects accidental reuse within the active response
windows; it does not replace the CSPRNG requirement for the lifetime of a session.

Each request is signed once and sent once. A successful OS send must call
`acknowledge`; this sets the response deadline and the next probe interval from
actual send time. Duplicate acknowledgements cannot extend either timer or
authorize a second transmission. At most 16 probes, including one queued unsent
probe, are retained. Each retains its signed bytes and original integrity policy.
The first authenticated success pins the future request algorithm; an older
dual-policy reply can renew consent without overwriting that policy. A configured
initial RTT estimate of 500–60000 ms is updated with integer SRTT/RTTVAR samples,
using a 500 ms floor and 60000 ms ceiling. This policy is specific to consent;
adaptive ICE checklist Ta/RTO remains separate work.

`receive(state, actual_reference, generation, bytes, now)` requires the exact
receiving base, peer IP/port and generation before matching and authenticating an
outstanding sent request. A protected success renews consent for 30000 ms from
receipt. Valid older outstanding requests can renew it; consumed, timed-out,
unsent, replayed or unrelated transactions cannot. Other errors and malformed
protected responses consume only that request and do not renew. Protected 403
immediately returns `Revoked` and discards all probes. At the exact consent
deadline, `tick` and `receive` return `Expired` and discard all probes before
processing a response. Neither terminal status can be revived by `start` or a
late success. `close` ends a trusted local owner; it is not a parser for remote
DTLS closure messages. Those require future authenticated DTLS integration.

Every application send, including future DTLS/media sends, must pass
`allowed(state, reference, generation, actual_now)`. This gate checks the entire
transport identity and the deadline even before a timer turn reports expiry.
`timeout` includes probe, interval and consent deadlines. After consent loss the
enclosing owner must retain that result and require changed ICE credentials;
constructing a new consent owner with the lost route's old credentials is
forbidden. The compatible standalone `start` still emits a non-nominating ICE
Binding request. `start_binding` adds authenticated consent-only Binding requests
with USERNAME, integrity and FINGERPRINT; its timing and lifecycle gates are the
same. `ice_transport.bend` supplies the integrated owner described below. The
standalone fixture supplies its selected route directly and does not establish
that integration. Authenticated DTLS closure still needs DTLS integration.

`ice_transport.bend` wraps `ice_agent.bend` with selected-route consent and
full/full credential restart for registered UDP/IPv4 routes. It derives paths
from `Agent.selected`, uses each selected candidate's actual base (which may
be different from the generating check's base), and reads exchanged credentials
and authenticated endpoint integrity policy from the session. New selections
start Awaiting and require a fresh round trip on their selected base. Multiple
stream/component aliases on one physical transport in the same generation share
one consent slot. Application `route` and `allowed` retain exact logical identity,
generation and current-time checks. Selection itself cannot grant consent.

The owner emits one authoritative `Transmit{Packet}` at a time. A trusted IO
adapter rechecks `current_send(state, packet, actual_now)` immediately before
sending, and calls `acknowledge` only after actual successful IO. Requests from
ICE and consent share a 5-ms actual-send gate; ICE retains its separate Ta gate.
While a directive waits for IO, the engine cannot emit a competing request.
An ICE directive's IO lease ends at its current response-window deadline: it
cannot keep the transaction alive indefinitely by suppressing retries. `failed`
releases only the reported directive without advancing successful-send pacing.
Late issued callbacks can advance actual pacing but cannot mutate a replacement
ICE generation or release its pending request. `current_reply` separately guards
unpaced replies at IO time. Nonces and callback records are trusted host inputs;
applications and signaling must never generate, inspect, or acknowledge them.
The JSON fixture exposes deterministic synthetic entropy solely as a test seam.

Nonce admission includes active/listening ICE records, outstanding consent and
recent IDs, plus 64 recently issued request IDs per retained generation. This
keeps recently completed ordinary/nomination IDs reserved when consent begins.
Retries preserve their signed bytes and original ID. This bounded cache does not
replace the lifetime uniqueness supplied by a strong host CSPRNG.

`ice_consent_server.bend` authenticates consent-only requests on selected actual
base/peer tuples without requiring PRIORITY or ICE role attributes. It checks
protected USERNAME and integrity, honors SHA-256 precedence, reports unknown
required protected attributes with signed 420 and a wrong bound remote fragment
with signed 401, and maps the actual peer source. Protected ICE usage attributes
pass to the ICE receiver; trailing unprotected attributes cannot change roles,
trigger checks, or nominate. Incoming consent service never grants outgoing
application consent. Expired/revoked slots remain sealed under those credentials.

`restart(state, streams, new_secret, now)` builds a fresh ICE generation from
candidate configuration, preserving the current full/full role and engine limits.
It clears old checklist/trigger/flight/valid/nomination/deferred state and pending
directives. Local ufrag and password must both change; `bind` separately requires
both remote fields to change. Both endpoints' credential reuse is rejected against
all retained history. History is bounded at 64 generations; further restart is
explicitly rejected. Dispose the owner and use fresh session credentials to start
another session. Lite/full role redetermination is not implemented here.

Only selected old consent/server slots survive restart. Their receipt/expiry
clocks and outstanding probes remain unchanged, and old data remains gated by
continuing consent while replacement ICE runs. A completed replacement stream
retires its old aliases immediately; its new route stays closed to application
data until fresh consent. Protected USERNAME selects old/new credential contexts
on the same socket. Old ICE requests are reply-only and cannot change replacement
roles or queues. The retained old role is the role actually reached before
restart, including post-selection conflicts. Retired historical namespaces are
ignored. Consent responses resolve physical aliases, while ICE response IDs
resolve the original logical attempt without rewriting observed base/source
metadata. A lost old route cannot revive from late success.

Use `tick`, `timeout`, `probe_due`, `probe`, `start`, `receive`, `bind`,
`local_signaled`, `repair` and `nominate` through this owner once it takes over.
Do not mutate its nested Agent/Session independently. A slot limit of 1–256
(default 256) bounds current and retained previous slots together. Exhaustion
or core failure/fault closes the transport owner; local `close` removes pending
requests and closes consent states. The IO owner must dispose the state and
release retained sockets on `Closed` or local cancellation. The UDP fixture
closes and rebinds its actual ephemeral port after every scenario.

Dynamic pair-cap pruning, deferred-item expiry, gathering/adaptive checklist
Ta/RTO, real-browser ICE, IPv6/TURN, Bend TLS/DTLS, SCTP/data channels and media
remain open. Generated-code timing safety is unproven; all new checks use synthetic
credentials. The integrated owner does not satisfy full ICE/WebRTC acceptance.
The 2026-10-01 official RFC 7675/8445 verified-errata refresh returned Internal
Error; no new correction was inferred. Restart and continued consent follow
[RFC 8445 section 9](https://www.rfc-editor.org/rfc/rfc8445.html#section-9) and
[RFC 7675 section 5.1](https://www.rfc-editor.org/rfc/rfc7675.html#section-5.1).
Formation and initial state rules follow [RFC 8445 sections 5.1.2 and 6.1.2](https://www.rfc-editor.org/rfc/rfc8445.html#section-6.1.2).
The [2026-10-01 errata search](https://errata.rfc-editor.org/search/?rfc_number=8445&presentation=records) lists only reported editorial erratum 7526 about a
broken reference link, with no verified protocol correction. That last successful
snapshot remains the evidence: a later official errata refresh for RFCs 8445 and
8863 returned an Internal Error. Individual failed checks do not establish ICE
failure.

`moon run rtc:check --force` checks the RFC 5769 IPv4 Binding response and malformed inputs in Bend, then uses a separate Python UDP responder to verify two random Binding requests, source port mapping, and rejection of wrong transaction IDs and sources. RFC 5769 request and response HMAC and FINGERPRINT values pass on native and Bun JS; changed content, MAC, key, and CRC fail. Both signers reproduce the legacy RFC request byte for byte.

The SHA-256 vector uses [RFC 8489 Appendix B.1 with verified erratum 6268](https://www.rfc-editor.org/rfc/inline-errata/rfc8489.html#appendix-B.1), correcting its message length, adding PASSWORD-ALGORITHM and updating its MAC. Native and Bun run 139 independent stdlib Python comparisons and rejection cases, including the corrected vector, padding/hash boundaries, dual integrity, response policy, ignored attributes after integrity and the maximum 65,532-byte STUN body. This is a STUN format maximum; an IPv4 UDP payload has a smaller transport limit. SHA-256 byte traversals use the crypto package's tail-recursive helpers to avoid JS stack overflow.

Each target also runs 121 byte-exact ICE builder cases covering ordinary and USE-CANDIDATE requests, credential limits, username direction, priority, transaction length and both roles with 64-bit extreme values. A separate Python UDP responder independently checks outgoing request HMACs and attributes, signs responses, and exercises 29 success/rejection/recovery cases plus two exchanges on one retained socket. Tests reject missing/bad integrity or FINGERPRINT, wrong source/transaction/key/algorithm/class, response USERNAME, dual-integrity responses, malformed input and unsigned mapped addresses. They check recovery after invalid packets, randomized transaction IDs, deadline behavior under repeated bad MACs, and bound-port reuse. This proves an authenticated ICE Binding transaction slice on native and Bun, not full ICE or end-to-end WebRTC.

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
clock fixture runs 296 cases per target for exact Ta/RTO gates, large timestamps,
final response boundaries, send acknowledgement, duplicate tokens/transaction
IDs, cancellation, transport failures and interrupted response retention. Cases
cover default 39.5-second retention, repeated stops, capacity and identity
reservation, queued initial/retry suppression, late authenticated success/errors,
invalid replies, deadline boundaries, invalid traffic and mixed socket failure.
Fifteen independent real UDP cases per
target run overlapping checks over one bound socket, including reordered
responses, loss, authentication failures, error 487 reporting, timeouts,
cancellation before/after sending, and byte-exact delivery of interleaved
requests/media/invalid or wrong-source packets. The large raw UDP case is 8 KiB
because macOS defaults `net.inet.udp.maxdgram` to 9216 bytes; format-maximum STUN
checks remain in the authentication suite. These are foundation tests; they do
not complete full checklist scheduling, role handling, nomination or browser ICE.
The interrupted UDP cases verify authenticated late replies, timeout and
bad-traffic retirement without pair failure, queued send suppression, independent
loss/retry of another check on the same socket, and released-port rebinding.

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
This fixture verifies incoming authentication and role decisions; the session,
valid-list and agent fixtures below separately verify their integration.

Pair-reference checks compare role reversal and full-sort bigint ranks with an
independent Python model, including mirror priorities that exchange positions,
checks completed through a saved reference after reordering, success/failure and
guard rejection, reflexive bases, cross-stream foundation thawing, ambiguous
endpoint refusal and randomized candidates. Both targets run the same fixtures.

Scheduler checks compare every pair, queue, cursor, allocator and sent-role
snapshot with an independent Python full-sort/bigint model. Native and Bun run
106 cases covering FIFO priority/deduplication, ordinary round robin, global
foundation blocking/thawing, idle streams, speculative selection without commit,
interrupted old-token isolation, generation guards, U32 exhaustion, sent-role
487 repair after another role switch, one-pair peer-reflexive insertion,
capacity and input rejection, and 60 seeded interleaved schedules of 55 turns.
The JSON adapter is a fixture interface, not signaling or a complete ICE agent.

Session checks use independently signed Python input packets and verify all
outgoing request/reply authentication and fields. Native and Bun each run 129
compiled cases for pre-answer/immutable credential binding, pending nomination
request deduplication, observed-only learned pairs, full-registry alias/base
checks, source/receiving-base/ID guards, speculative pacing/capacity behavior,
interrupted records and late responses, current/pending 487 repair, integrity and
transport outcomes, endpoint algorithm pinning, registry rollback and 30 seeded
signed arrival sets. Tests also cover authenticated non-symmetric failure versus
unauthenticated raw traffic, exact final deadlines, frozen-foundation preservation,
independent active pairs, completed outcomes, late listener retirement, stale sends
and old replies after replacement. Thirteen independent real-UDP cases per target own two actual
local sockets: pre-answer replies, no learned-candidate cross-products,
wrong-local-base and independently bound wrong-source authenticated failure,
bad-MAC raw forwarding with unchanged retry bytes, ordinary overlap/loss,
incoming interruption and late success/non-symmetric retirement without
replacement failure, fresh host-random role-conflict retries,
per-endpoint modes, retained-listener capacity/expiry and both-port cleanup.
Additional cases bind two distinct local IPs at the same port, prove IP-only
non-symmetric failure without replacement/other-pair damage, retain the actual
second-IP source/port and bytes through loss/retry, form candidates from queried
ephemeral ports, and reject wildcard owner inputs. The original seven-argument
fixture path still passes. Failed second bind and invalid session construction
also release opened ports.
Raw notices expose the actual receiving base and peer source. These tests verify
this session/transaction slice, not nominated paths or browser data/media.

The valid-list fixture adds 70 independent signed mapping/priority/foundation/
bigint/role/late/capacity/rejection cases per target. It compares actual request
PRIORITY and every resulting path/rank with Python, including known reflexive
candidates, omitted host bases, shared/different IP foundation keys, collisions,
role changes, duplicate full-list outcomes, invalid late mappings and replacement
isolation. Counterpart cases cover all five pair states, triggered queue removal
while preserving other entries, stale sends, cross-stream foundation thawing,
reflexive base separation, late-result isolation for distinct active pairs, and
obsolete 487 repair cleanup while preserving unrelated repair work.
Nine additional independent live UDP cases per target use the same
explicit-address owner: synthetic mapped addresses after loss/retry, pre-answer
triggered learning, distinct old/replacement mappings, wrong receiving-IP rejection,
authenticated errors, counterpart retry suppression, late success/error,
listener expiry, preserved distinct-pair retransmissions and both-port rebinding.
These mappings are synthetic peer
claims, not proof of a physical NAT or a nominated/browser data path.

The nomination-request fixture adds 23 independent pure cases per target. It
compares exact protected bytes and original sending references for host, local
peer-reflexive, server-reflexive and different-known-host mappings, negotiated
integrity, target mismatches, pacing/capacity rollback, pending 487 repair,
controlled rejection and interrupted-listener metadata. Eleven additional
scheduler cases cover repeat nomination transitions, generation/role gates,
queue deduplication and old-flight isolation. Ten live retained-transaction
UDP cases independently verify protected USE-CANDIDATE bytes in all integrity
modes, loss/retry with identical bytes and bound port, bad MAC/source rejection,
error/timeout, stopped-listener late success/error/expiry, controlled rejection
and socket rebinding. This UDP fixture tests the transaction interface; it does
not choose a valid path or establish nominated/selected ICE agent state.

The nomination-evidence fixture adds 46 independently signed packet cases per
target for current/checklist-counterpart associations, exact lookup, duplicate
origin replacement, late mapping isolation, pre-answer merging and fragment
binding, request-role/integrity qualification, retry/pacing/capacity preservation,
ordinary and nominated replacements, old listener outcomes/expiry, 487 repair,
non-symmetric failure ownership, generation isolation, fresh creation and fault
quarantine. It runs pure owner transitions on native and Bun; it does not add a
live nomination-owner UDP, browser, selected-path or terminal-state proof.

The agent fixture adds 48 independently signed nomination/lifecycle scenarios per
target: actual mapped-path nomination, manual/automatic plans, all integrity modes,
mapped counterpart identity, already-Succeeded and pre-answer controlled intent,
pacing rollback, current failure/487 repair, late listener isolation, multiple
components/streams, legacy parallel nomination, selected paths, response-only
Binding service and PAC gates/exact expiry. Ten independent real UDP scenarios
per target check ordinary-to-nomination repeats with fresh IDs, loss/unchanged
retry bytes and port, invalid MAC, current error/timeout, post-conclusion service,
new-path protected rejection, controlled immediate nomination and port rebinding.
The UDP fixture uses a declared 1200 ms PAC policy and an 800 ms terminal server
grace; pure clocks exercise the default 39500 ms PAC boundary. Mapped addresses
are synthetic authenticated claims. These do not prove NAT, browser ICE, integrated consent,
restart, IPv6/TURN or data/media delivery.

The consent fixture adds 40 independent signed packet/lifecycle scenarios per
target. They cover initial application denial, exact 30-second and response-window
boundaries, 4–6-second intervals, delayed actual-send acknowledgement, single-send
suppression, older overlapping replies, retained integrity policy and first-policy
pinning, malformed/forged/errors/403/replay, receiving-base/source/generation
gates, cancellation, RTT updates, uptime-sized clocks and bounded ID history.
Six real retained-socket UDP scenarios per target check all integrity modes,
wrong-source/transaction/forged revocation, initial loss without retransmission,
fresh random IDs and measured intervals, renewal and actual synthetic application
datagrams, immediate authenticated 403, the actual default 30-second expiry and
port release/rebinding. The test peer responds only to authenticated Bend-built
packets. The fixture supplies a trusted selected route directly; it does not
exercise nomination-to-consent handoff, multiple paths, restart, browser ICE,
physical NAT or DTLS/media. C/JS effects remain unchanged; generated-code timing
safety remains unproven.


The integrated transport fixture adds signed nomination/consent/restart scenarios
on native and Bun. It establishes selection through ordinary checks and regular
nomination, then verifies role-free probes and incoming service, exact identity
and deadlines, bounded send leases, shared pacing/nonce admission, mapped bases,
physical aliases, credential changes/reuse/history limits, overlap/expiry/revocation,
stale callbacks, role repair/preservation and closed/exhausted cleanup. Independent
Python peers verify generated MACs, attributes, CRCs and actual-source mappings.
Seven real UDP scenarios per target exercise the whole nomination-to-consent
handoff, all integrity modes, incoming consent service, first-probe loss,
one-shot randomized requests, actual application gating, protected 403 and
measured default 30-second expiry. During a same-socket restart, the replacement
nomination retransmits while an old consent round trip renews and gates old data;
new selection retires old credentials before a fresh new consent round trip gates
new data. Actual source ports are retained throughout and rebound after exit.
These are local independent peers, not browser/direct/relay/media acceptance.
