# grounds-wire

TCP on bytes for [Bend 2](https://github.com/bendlang/bend). Base's `TCP.send` and `TCP.recv` decode and encode UTF-8, which breaks byte counts and binary protocols; `wire_recv` and `wire_send` move bytes (0..255) as they are.

```python
import ../wire/wire.bend as W

l : Listener <- IO.try(Listener, W.listen(8080))
a : Listener & Result<&1, &1, U32 & String, Socket> <- W.accept(l)
r : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- W.wire_recv(sock, 4096)
w : Socket & Result<&1, &1, U32 & String, Unit> <- W.wire_send(sock, [72, 105])
```

| Function | Does |
|---|---|
| `W.wire_random_bytes(count)` | 0–1048576 bytes from the host RNG, as `Result<List<U32>>`; zero does not call the RNG; failure returns no partial list |
| `W.wire_recv(sock, max)` | up to `max` bytes, once some arrive; `[]` when the peer has closed |
| `W.wire_recv_timeout(sock, max, ms)` | the same, as `Some{bytes}`; `None{}` when nothing comes within `ms` |
| `W.wire_send(sock, bytes)` | every byte; a value past 255 fails with `EINVAL` before any is sent |
| `W.wire_send_timeout(sock, bytes, ms)` | the same, failing `ETIMEDOUT` when the peer takes nothing for `ms` |
| `W.wire_connect_timeout(host, port, ms)` | `connect`, failing `ETIMEDOUT` past `ms`: an address that drops packets would wait for the OS |
| `W.wire_accept_timeout(l, ms)` | `accept`, as `Some{sock}`; `None{}` when no connection comes within `ms` |
| `W.wire_resolve(host)` | a host name to its first IPv4 address, dotted; `connect` takes only addresses |
| `W.wire_udp_bind(host, port)` | binds one IPv4 literal; port `0` requests an ephemeral port; failures close any newly allocated socket |
| `W.wire_udp_local_address(sock)` | returns `(host, port)` from the OS, preserving socket ownership; wildcard sockets report `0.0.0.0` |
| `W.wire_udp_send_to(sock, host, port, bytes, ms)` | sends one binary UDP datagram or fails; invalid bytes fail `EINVAL` before send |
| `W.wire_udp_recv_from_timeout(sock, max, ms)` | `Some{(host, (port, bytes))}` on a datagram, including empty bytes; `None{}` on timeout; oversized datagrams fail `EMSGSIZE` after consumption |
| `W.wire_on_stop()` | from now on SIGTERM and SIGINT set the stop flag instead of ending the process |
| `W.wire_stopping()` | 1 once a stop signal has come, else 0 |
| `W.wire_live(d)` | a process-wide counter: adds `d` (1, 4294967295 for −1, or 0 to read) and returns the count |
| `W.wire_tls_listen_ctx(cert, key)` | loads a PEM certificate chain and matching private key for TLS server handshakes |
| `W.wire_tls_accept(sock, ms)` | accepts TLS on a connected socket within `ms` |
| `W.wire_close(sock)` | sends TLS close_notify when needed, then closes the socket |
| `W.listen(port)`, `W.accept(l)`, `W.connect(host, port)`, `W.close(sock)`, `W.close_listener(l)` | Base's own |

`tls_record.bend` adds a pure Bend protected-record path for
TLS_CHACHA20_POLY1305_SHA256 and TLS_AES_128_GCM_SHA256. It uses `crypto/traffic.bend` affine read/write
owners and Bend HKDF/AEAD; it does not call the OpenSSL TLS effects. Its public
`seal(owner, kind, padding, content)` / `open(owner, record)` return a successor
owner and `Done` / `Fail`. Writers authenticate the five-byte `17 03 03` header
and its uint16 length, and encrypt content + type + zero padding. Readers
authenticate the actual received header before exposing content. The deprecated
legacy version does not choose a protocol version; authenticated alternative
values are tolerated, while modifying those bytes without a new tag fails.

`frame(bytes)` yields `More`, `Bad`, or `Framed{header, body, rest}`. Retain
`More` bytes in the stream owner, append the next chunk, and retry without
consuming a traffic key. For coalesced input, process the first complete record
and retain `rest`; `open` itself accepts exactly one record and rejects extra
bytes. Limits are 16384 content bytes, 16385 total inner bytes and 16401 encrypted
body bytes for either suite's 16-byte tag. Oversized padding is rejected before
length arithmetic or allocation. Empty application content is allowed;
handshake content must be nonempty and alerts must contain exactly one two-byte
message. Encrypted CCS, unknown inner types and authenticated inner plaintext
without a nonzero type are rejected. Every record/protection error retires the
owner. The check passes 154 independent cases on each native/Bun target,
including all split points of a small record, maximum-size and coalesced records,
padding, header/body/tag changes, replay, retirement and old-key KeyUpdate bytes
followed by an explicitly updated key and sequence-zero record. Bend proofs
cover invalid byte input and the largest representable padding argument.

AES callers supply owners from `T.new_aes128_write` / `T.new_aes128_read`;
the record interface and framing remain unchanged. Its evaluator passes 166
cases per native/Bun target: the same 154 record scenarios plus all seven
published protected records in RFC 8448 section 3, grouped into continuous
handshake/application directions, and sending usage-limit/old-key KeyUpdate
boundary checks. Published bytes include the server handshake flight, client
Finished, server ticket, application data and alerts in both directions.
`tls_aes_vectors.json` pins the RFC source hash and participates in the wire
task's input hash. AES sending usage is capped at 2^24 records per epoch;
attempted excess closes the owner, while receiving does not apply that cap.
Explicit updates retain the negotiated algorithm and reset the sequence.

Run package checks through the sequential [build guard](../tools/README.md).
The record gate builds separate native/Bun read and write evaluators to reduce
compiler workload. Each Bend evaluator retains its affine owner across the
entire record/update/failure/retirement scenario; Python only selects and
executes the matching fixture. Shared synthetic formatting and owner diagnostics
live in `tls_record_fixture_support.bend`. The original combined evaluator and
all record test cases remain available. Native record fixtures use
`tools/bend_native.sh` so Bend exits before clang starts.

This is the protected record codec, not a completed TLS connection. Plaintext
handshake/compatibility CCS, transcript and handshake-fragment ownership,
Finished/KeyUpdate phase and record-boundary ordering, certificates/signatures,
alert dispatch, TCP buffering/deadlines and authenticated client/server interop
remain to implement. Existing OpenSSL APIs retain their behavior. Crypto timing
and physical key erasure remain unapproved; the new evaluator uses local
synthetic fixtures. [RFC 9846 sections 5.1–5.4](https://www.rfc-editor.org/info/rfc9846/)
and [current errata](https://www.rfc-editor.org/errata/rfc9846) were reviewed on
2026-10-01; no verified record changes apply. This is a TLS 1.3 codec and cannot
be used as a DTLS record implementation.

On Bun, `wire_on_stop` installs SIGTERM/SIGINT through a small OS-only C bridge.
Bend's synchronous select/trampoline runtime prevents JavaScript signal callbacks
from running while the program is active. The bridge uses a lock-free atomic
flag in its C signal handler; `wire_stopping` polls it without calling JavaScript
from the handler. A C11 compiler (`CC`, otherwise `cc`) is required when enabling
this effect. The bridge is compiled once in a private temporary directory and
loaded with Bun FFI; build files are removed immediately. Its mapping remains
for the process lifetime so installed signal handlers always point to valid code.
Compiler/load/install failures fail explicitly. Native signal effects retain
their existing behavior. `stop_check.py` sends actual SIGTERM and SIGINT before
and after an accepted connection on both targets, requires clean exit within
three seconds and rebinds the listener port after each run. This is OS signal
delivery and cleanup; it does not claim general cancellation of every stack path.

Bulk randomness uses `arc4random_buf` on Darwin, nonblocking `getrandom` on
Linux, and Bun WebCrypto in chunks of at most 65536 bytes. Native work runs
through Bend's existing IO worker; the Linux adapter completes short reads,
retries at most 63 consecutive interruptions and reports the 64th, zero/invalid
reads and OS errors. An unready Linux pool returns `EAGAIN`; no weaker RNG is
substituted. Requests above 1 MiB fail `EINVAL` before allocation. Temporary OS
buffers are cleared before release, including failure; returned Bend values and
runtime heap copies are not thereby erased. Native malloc failure is `ENOMEM`;
Bun allocation and entropy failures are explicit. This is entropy acquisition,
not a nonce/key lifecycle or constant-time guarantee. See
[Linux getrandom](https://man7.org/linux/man-pages/man2/getrandom.2.html),
[Apple arc4random](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/arc4random.3.html)
and [WebCrypto getRandomValues](https://www.w3.org/TR/webcrypto/#Crypto-method-getRandomValues).
The Linux completion loop has controlled short-read/interruption/error tests;
live kernel verification remains pending on this Darwin host.

On 2026-10-01, `bench.bend` and `measure.py` recorded three samples per workload
on macOS 26.2 arm64, Bend 2.0.27/Bun 1.3.13. For one 1 MiB acquisition plus
byte-count/range/checksum traversal, median bulk RNG was 3 ms native (3–4 ms)
and 58 ms Bun (58–59 ms), versus word-at-a-time `IO.random_u32` at 1212 ms
native (1198–1214 ms) and 348 ms Bun (345–359 ms). These are local fixture costs,
not throughput of an entropy source alone, entropy-quality evidence or timing
safety. The millisecond counter rounds small workloads; zero is below resolution.

The same benchmark constructs and scans eight public 1 MiB patterns:

| Representation/workload | Native median | Bun median |
|---|---:|---:|
| Existing `List<U32>` byte boundary | 15 ms | 779 ms |
| Dedicated byte-list constructors | 15 ms | 765 ms |
| `Array<U32>` construction, conversion to list and scan | 72 ms | 1595 ms |

The checksum validator is included in every workload. The array measurement is
an IO serialization workload, not an indexed-access comparison; crypto's existing
limb arrays are not replaced. Retain the byte-list API for the sequential OS
boundary: dedicated constructors supplied no clear measured win and array
serialization was slower. This choice does not solve allocation pressure. Bun's
whole-process peak RSS for these eight-round cases was about 815 MiB for lists,
830 MiB for dedicated constructors and 592 MiB for arrays, including runtime,
construction and validator allocations. Native peaks were about 18/18/30 MiB.
Packed storage and long-session allocation behavior still need measurement
before the integrated data/media path is accepted.

The isolated official Bend 2.0.34 compatibility investigation on 2026-10-02
retains the full 1 MiB RNG contract. Its count/range diagnostic passes at 78.3 MiB.
Instrumented small samples then identify two 32-node word conversions per byte
in the chunk printer's U32 countdown. The draft replaces that counter with Nat
fuel, preserving 4096-byte chunks. Its CLI-only OS write effect also collects
discarded chunks on Bun after writes of at least 8192 characters; host entropy
acquisition is unchanged. Nat fuel with ordinary `IO.write` still fails the
cutoff, so collection remains necessary for this measured candidate.
The full 20-case RNG output matrix and 20-case deterministic exact-byte printer
matrix now pass on native and Bun 1.3.9/1.3.13, including 1 MiB. Largest sampled
individual/group peaks are 94.0/119.8 MiB, under 96/128 MiB evaluator cutoffs.
Bun evaluates with optimizing JIT enabled, `--smol` and a 64 MiB reported-RAM
GC hint; these settings and sampled cutoffs are not hard OS memory quotas.
The Bun matrices take 2.5–2.9 seconds each, including all cases; this is public
CLI formatting evidence, not transport throughput, entropy quality or secret
timing/erasure evidence. The repository remains pinned to 2.0.27; the 2.0.34
upgrade draft and printer are unadopted pending the remaining compatibility and
forced package/root gates. Source hashes, generated targets and reports are in
`/Users/ozeron/.codex/artifacts/grounds/2026-10-02/compiler-compatibility/`, with
the tested source in `natcounter-files/`, current binding manifest in
`validation/natcounter-evidence.json`, and rejected drafts preserved in `history/`.

The independent Python peer also verifies every echoed octet and rebinds each
actual released UDP port. Median aggregate loopback echo throughput (both
directions counted, 200 datagrams per sample) was 8.43/57.21/342.86 MiB/s native
and 6.51/27.33/121.98 MiB/s Bun for 256/1200/8192-byte datagrams respectively.
This includes the peer, retained sockets and byte conversions; it is not a network
capacity result. This Mac's unchanged `net.inet.udp.maxdgram` is 9216. At 16384
bytes the peer's default `sendto` rejects `EMSGSIZE`; the Grounds fixture then
closes on its receive deadline, and the actual port rebinds. The failed first
measurement and final explicit rejection records are retained.

Reproduce with `bend bench.bend -o <native>` / `-o <bun.js>`, likewise
`udp_address.bend`, then `python3 measure.py <evidence-dir> <native> <bun.js>
<native-udp> <bun-udp.js>`. The runner is macOS-specific (`time -l` RSS units),
records exact commands, source digests, samples, ranges and peak RSS, and uses no
speed threshold. Evidence is in
`/Users/ozeron/.codex/artifacts/grounds/2026-10-01/foundations/measurements.json`.

- The TLS server uses OpenSSL 3 at run time, with TLS 1.2 as its minimum, no 0-RTT, and `http/1.1` as its only accepted ALPN offer. After `wire_tls_accept`, the ordinary `wire_recv_timeout` and `wire_send_timeout` effects carry encrypted bytes. Use `wire_close` for both TLS and plain sockets. `BEND_LIBSSL` can name libssl when the default paths do not find it.
- The TLS client uses `wire_tls_connect(sock, host, ms)`, `wire_tls_send_timeout`, `wire_tls_recv_timeout` and `wire_tls_close`. It verifies the certificate chain and host; `GROUNDS_TLS_CA` adds a PEM trust root.
- An effect's name is global in a program: its C id is `CID_WIRE_RECV`, taken from the def's name. So the effects carry the package's name, and there are no `recv`/`send` wrappers: a one-line wrapper is merged into the effect and takes its name.
- The effects follow `bend-kit-wire` on BendHub (`0x096635686408886b7d907f16c4550317`, MIT-0), with `List<U32>` in place of one Char per byte, for both the C and JS targets.
- For UDP, use `wire_udp_bind(host, port)` when local address identity matters, and query `wire_udp_local_address` before advertising a port assigned by the OS. It accepts canonical IPv4 literals and ports 0–65535, without DNS, address reuse options or fallback binding. Errors retain OS errno; an invalid literal/port returns `EINVAL`. Failed bind/nonblocking setup closes the newly allocated socket. Close successful sockets with `Socket.close(sock)`. Base's existing `UDP.bind(port)` remains available for wildcard binding. UDP transport remains IPv4; IPv6 is still pending. The receive limit is checked against the full datagram; the largest supported receive buffer is 65535 bytes.
- An explicitly bound unicast IP identifies the receiving local address for an unconnected UDP socket. A wildcard socket's `getsockname` result is `0.0.0.0`; it does not identify a received packet's destination IP. The new effects call OS `bind`/`getsockname` and keep protocol logic in Bend. Bun loads only `getsockname` from the system library because Base's syscall table lacks it. See Apple's [bind](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/bind.2.html) and [getsockname](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/getsockname.2.html) references.

`moon run wire:check` builds these natively and runs them:
- `loopback.bend`: all 256 byte values go through a connection to itself and back.
- `timeout.bend`: a poll times out, gets bytes, then sees the close.
- `udp.bend`: native and, when Bun is available, JS binary datagrams, including all 256 octets, zero-byte datagrams, timeout, oversize and invalid input.
- `udp_address.bend` with the independent Python peer: 22 cases per native/Bun target covering literal/NUL/port rejection, ephemeral/wildcard reporting, all octets and empty datagrams, two local IPs sharing a port, wrong-destination isolation, errno, 1,500 failed binds with exactly one retained UDP descriptor, and released-port rebinding. The fixture uses a second local IPv4 address selected by an independent OS UDP round trip from a loopback-bound peer; Linux may supply another loopback IP, while this Mac uses its existing reachable local interface. Bindable VPN/tunnel addresses without bidirectional loopback reachability are rejected. No interface configuration is changed. These checks run on Darwin arm64; Linux branches are implemented but not verified on this host.
- `stop.bend`: accepts one connection, then SIGTERM ends its loop.
- `resolve.bend`: resolves localhost, an address, and a name that does not exist.
- `tls.bend`: a client GET, wrong host and untrusted certificate against the Python TLS server.
- `tls_server.bend`: two verified Python clients use the Bend TLS server; its plain send and receive effects carry the encrypted traffic.

### Published handshake oracle fixtures

`tls_handshake_vectors.json` contains exact RFC 8448 section 3 (1-RTT) and
section 5 (HelloRetryRequest) handshake messages and KDF/Finished fields.
`tls_handshake_vectors.py` reproduces them offline from the SHA-pinned RFC text:

```sh
python3 tls_handshake_vectors.py --source /path/to/rfc8448.txt --output tls_handshake_vectors.json
python3 tls_handshake_vectors.py --check tls_handshake_vectors.json
```

The independent Python oracle checks 17 message lengths, six HKDF extracts,
22 expansions, 18 transcript-hash contexts, four Finished authenticators and
one retry transcript rewrite. These are fixture checks, not Bend handshake
execution; no handshake implementation is accepted by their success. Source
line numbers permit comparison with the original publication. The historical
RSA certificate in this trace is not an accepted modern trust/key-size fixture.
Resumption/exporter fields retained from the trace do not add those features to
the selected HTTPS profile. Existing protected-record fixtures remain unchanged.

### Bend handshake transcript

`tls_transcript.bend` owns a streaming SHA-256 transcript. `start` creates an
empty owner; `append` consumes it and admits one complete encoded handshake
message; `snapshot` returns the continuing owner and its current hash; `finish`
consumes the owner. The transcript excludes record headers. The first message
must be ClientHello. A recognized HelloRetryRequest immediately after that
ClientHello replaces it with the synthetic message_hash encoding. Later or
repeated retries and a peer-supplied message_hash reject. All invalid admission
consumes the owner, so callers cannot continue a failed transcript.

This layer checks byte validity, exact uint24 framing and a cumulative 1 MiB
admitted-input limit. It does not parse message bodies, reassemble records,
validate complete handshake ordering/roles, authenticate a peer or decide which
post-handshake messages belong in a transcript. Those decisions belong to the
handshake owner. The count retains original admitted bytes across retry; the
synthetic replacement is a fixed-size internal hash input. Snapshots duplicate
public hash state, not traffic/private keys, and retain no whole-transcript list.

Focused pinned native/Bun checks cover published 1-RTT/retry traces, continuing
snapshots, byte/hash-block boundaries, invalid framing, retry misuse, failed-owner
reuse and exact/cumulative size bounds: 84 ordinary outputs plus six stress
outputs per target. Six framing declarations check through the frontend, and
the ownership checker accepts append/snapshot while rejecting copying and
repeated finalization. These checks are included in `check.sh`; package and
full-stack acceptance status remain in `STACK_PROGRESS.md`.

The wire gate declares thirteen ordered resource phases in `check_phases.json`:
native/Bun extensions, handshake streams, schedules and foundations, native transport, Bun UDP, native/Bun
stop handling, and legacy native TLS. Run the full fresh package through
`tools/build_guard.py --phases wire/check_phases.json` around
`moon --concurrency 1 run wire:check --force`, with the plan's 1 GiB memory and
120-second per-phase limits. Missing Bun produces explicit optional-phase skips;
such a run cannot establish Bun acceptance. Phase declarations preserve all
pre-existing commands and do not remove coverage or extend a phase deadline.

### Bend handshake schedule and Finished

`tls_schedule.bend` composes the existing Bend HKDF/HMAC/TLS-label primitives for
the selected SHA-256 certificate/ECDHE profile with no PSK. `start(shared,
hello_hash)` accepts exactly 32 valid bytes for each input and returns an affine
`Handshake`: directional handshake traffic secrets, a `ToApplication` owner
and one `FinishedKey` for each peer. `application(next, server_finished_hash)`
consumes the next-stage owner and derives the two application traffic secrets.
`finished(key, transcript_hash)` or `verify_finished(key, transcript_hash, tag)`
consumes that peer's Finished key. The verifier accumulates every admitted tag
byte before its equality decision; generated-code timing remains unreviewed.

The key-agreement owner must validate the peer point/shared result. The handshake
owner must supply the correct transcript snapshots, validate certificates and
message order, map client/server directions into record owners, and gate
application data on authentication. This schedule alone does none of those.
Its all-zero component-input oracle case verifies KDF mathematics, not admission
of an invalid peer key. Synthetic diagnostics expose intermediate secrets only
for tests; they are not a connection interface. Logical owner consumption is not
physical erasure, and the runtime/key-lifecycle review remains open.

The independent checker compares 798 outputs from 182 commands on each target:
published 1-RTT/retry traces, 64 seeded random schedules, invalid widths/non-octets,
every tag/transcript-byte mutation, and wrong-key rejection. Six admission/tag
checks pass the frontend. Ownership tests accept the two supported consuming
operations and reject copying, repeated use and cross-stage misuse. The package
adds separate native/Bun schedule phases, bringing the manifest to nine without
changing any existing command or phase. Current complete-package acceptance is
recorded in `STACK_PROGRESS.md`.


### Bend handshake record reassembly

`tls_handshake_stream.bend` accepts one plaintext or authenticated, decrypted
handshake-record payload per `feed` call. A TCP read must first pass through the
record layer. Its affine decoder returns complete header-plus-body encodings in
wire order, retaining a partial header/body across records. Input must contain
valid octets, be nonempty and at most 16 KiB per record; cumulative admission is
bounded at 1 MiB. Oversized uint24 declarations reject before body accumulation.
The decoder consumes input linearly without rescanning the accumulated prefix.

ClientHello, ServerHello, EndOfEarlyData, Finished and KeyUpdate must end at a
record boundary. `boundary` requires a complete-message boundary before a
record-type or key transition; `finish` rejects truncated input. Any error
consumes the owner and returns no messages from the failing record. The caller
still owns message-body parsing, role/order, record authentication and epoch
selection. Unknown message kinds pass framing only; this is not admission of
unsupported TLS messages or features.

An independent buffered Python reference checks 936 regular scenarios per target,
including published RFC 8448 messages split byte-by-byte, every split of its
ClientHello and server flight, coalescing, random fragments, malformed lengths,
record alignment and terminal-state behavior. Three further scenarios verify
exact/cumulative 1 MiB admission and overflow on native and Bun. Six closed
frontend checks and affine ownership rejection accompany these tests. Dedicated
native/Bun package phases retain every pre-existing check and deadline.


### TLS extension-vector framing

`tls_extensions.bend` parses an exact uint16-length-prefixed extension vector.
It returns ordered `{kind, data}` records, preserving unknown types and opaque
bodies. Non-octets, length mismatches, truncated headers/bodies, trailing bytes
and duplicate types reject the entire vector. The parser admits the full 65,535
byte payload range and uses a consuming fixed type bitset to avoid quadratic
duplicate scans. The body-consuming loop has an explicit extension-count budget.

This is a shared framing boundary for Hello and other handshake-message codecs.
It does not decide permitted message locations, request/response binding,
required extensions, PSK ordering or extension-specific grammars. Callers must
apply those rules before negotiation/authentication; unknown ClientHello offers
must not be rejected just because their type is unimplemented.

Independent checks cover 1,756 ordinary and ten stress cases per native/Bun
target, including published RFC 8448 vectors and their truncations, every uint16
type, maximum body/vector sizes, duplicates across bitset boundaries and distant
duplicates. Diagnostic output is reconstructed from parsed fields. Seven closed
frontend checks also pass. Complete package acceptance is tracked separately in
STACK_PROGRESS.md; focused passes do not establish a live TLS handshake.
