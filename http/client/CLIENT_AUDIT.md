# HTTP/1.1 client audit (M6 item 1)

Scope: the native Bend TLS client path, `bend_client.bend` (C) and
`bend_pool.bend` (Pool), over the shared framing in `../wire/http1.bend`
(H1). The baseline is `45b1014` (2026-11-07). Line numbers in the
"Baseline" column refer to that revision. RFC 9110 and RFC 9112 set the
expectations for a practical client, not a browser.

Status: **present**, **partial** or **missing** at the baseline. The last
column says what M6 did. "Review fix" marks what changed after the
independent review of `22128d7..4ea30b7` (2026-11-07); see the section of
that name at the end.

## Request building

| Area | Baseline | Where (45b1014) | M6 |
| --- | --- | --- | --- |
| Host from the URL authority, port only when given | present | `url.bend:96` `url.auth`; H1 `http1.bend:1363` | — |
| Content-Length for a body, and for POST/PUT/PATCH with none | present | H1 `http1.bend:1217`, `:1371`; law `body_length` | — |
| Caller cannot set Host, Content-Length, Transfer-Encoding, Connection | present | `bend_client.bend:282` (Host); H1 `http1.bend:755`, `:779` | — |
| CR, LF, NUL in a header name or value dropped | present | H1 `http1.bend:763`, `:779`; law `request_safe` | — |
| Header **name** must be a token; value free of other CTLs | **missing** | `bend_client.bend:282` keeps `Transfer-Encoding ` (trailing space) or `X:Y` names, and values with `\x01` or DEL | fixed: `policy.bend` `header.ok`, applied in `hs.clean` |
| Method must be a token | present | `url.bend:43` `verb.check`; law `method_clean` | — |
| Target/authority free of CR, LF, NUL, space | present | `url.bend:52`, `:155`; laws `url_target`, `url_authority` | — |
| URL fragment never sent | **missing** | `url.bend:52` keeps `#frag` in the target | fixed: `policy.frag.cut` before `Ur.url` (requests and redirects) |
| `Transfer-Encoding: chunked` upload (streamed request body) | **missing** | bodies are in-memory `B.Bytes` with Content-Length | deferred (see below) |
| `Expect: 100-continue` | partial | never sent by the client; a caller's header is passed through and the body is sent at once, which RFC 9110 §10.1.1 allows; a 100 is skipped | — |
| `Accept-Encoding` | present (not advertised) | no default header | — (compression deferred) |
| Default `User-Agent` | missing | none sent; callers add one with `with` | review fix: `user-agent: grounds-bend` unless the caller sets one (any case); `with_user_agent(c, s)`, `without_user_agent(c)` |

## Response parsing and framing

| Area | Baseline | Where (45b1014) | M6 |
| --- | --- | --- | --- |
| Status line `HTTP/d.d SP ddd SP reason` | partial | H1 `http1.bend:978`: any three digits (000–999) accepted; `HTTP/1.1 200` with no SP is refused (strict, kept) | fixed: a final status must be 200–599, else `BadResponse` (`policy.final`) |
| CRLF only, bare CR/LF refused; head size limit | present | H1 `http1.bend:51` (`max_head_bytes`, 16 KiB) | — |
| Header syntax: token name, no space before colon, value without CTL | present | H1 `http1.bend:205`, `:229` | — |
| obs-fold rejected | present | H1 `http1.bend:220` (`ObsFold`) | — |
| Content-Length: digits only; differing duplicates refused | present | H1 `http1.bend:252`–`:283` | review fix: a list of one value (`5, 5`, OWS allowed) is that length (RFC 9110 §8.6, RFC 9112 §6.3); identical repeated fields were already accepted; a conflict, empty element or non-digit is refused |
| CL and TE both present | **partial** | H1 `http1.bend:1268`: TE framing wins, but the connection stayed reusable | fixed: TE wins and the connection is never reused (RFC 9112 §6.3 ¶3) |
| TE other than a single final `chunked` | present (refused) | H1 `http1.bend:1249` (`Unsupported` → `BadResponse`) | — |
| TE in an HTTP/1.0 response | partial | decoded as chunked; HTTP/1.0 is never reused | — |
| Chunk size: hex only, bounded by `max_body_bytes` | present | H1 `http1.bend:468`, `:509` | — |
| Chunk extensions and trailers read and dropped, framing budget 64 KiB | present | H1 `http1.bend:480`, `:524`, `:1318` | — |
| Close-delimited body; TLS needs `close_notify`, bare EOF is truncation | present | `bend_client.bend:504`; `bend_transport.bend:165` | — |
| Truncated CL/chunked body → `Closed` | present | `bend_client.bend:504` | — |
| 1xx skipped (up to 8) | partial | `bend_client.bend:696`, `:714`: a 9th 1xx was returned as the final reply | fixed: not final → `BadResponse` |
| 101 without an Upgrade request | **partial** | `bend_client.bend:696` returns 101 as a reply with `reuse` true, so a pool could reuse a switched connection | fixed: `BadResponse`, connection closed |
| HEAD/204/304 (and 1xx) have no body | present | H1 `http1.bend:1092` | — |
| Bytes after a complete body → connection not reused | present | `bend_client.bend:434` (`done.meta`) | — |
| Body size limit (`max_body_bytes`, 8 MiB) | present | H1 `http1.bend:1268` (CL refused before reading); `bend_client.bend:533` | — |

## Streaming

| Area | Baseline | Where (45b1014) | M6 |
| --- | --- | --- | --- |
| Download streamed to a callback, never buffered | present | `bend_client.bend:1494` `stream`, `Pool.stream`; per-read deadline, no body limit | live 4 MiB chunked test with client RSS bound |
| Non-2xx streamed body kept up to 1 MiB for `Status` | present | `bend_client.bend:1434` | — |
| `stream`/`events` follow redirects | missing (documented) | `bend_client.bend:1494` | not changed |
| Upload streaming | missing | — | deferred |

## Redirects

| Area | Baseline | Where (45b1014) | M6 |
| --- | --- | --- | --- |
| 301/302/303/307/308 followed, max hops (`redirects`, 5), then `Redirects` | present | `bend_client.bend:1048`, `:1208` | — |
| 303 → GET (not HEAD); 301/302 POST → GET; 307/308 keep method and body | present | `bend_client.bend:1191` | — |
| Body dropped only when the method becomes GET | **partial** | `bend_client.bend:1146` dropped a DELETE/OPTIONS body on 307/308 | fixed |
| Content headers dropped when the method becomes GET (RFC 9110 §15.4) | **missing** | `bend_client.bend:1196` kept Content-Type etc. on the GET | fixed: `policy.content` |
| Authorization and Cookie dropped cross-origin | present | `bend_client.bend:1160` | also `Proxy-Authorization` (live test added in the review fix, kept on the same origin) |
| ...but kept on a same-origin absolute Location | **partial** | `bend_client.bend:1203` stripped them for every absolute URL | fixed: kept when scheme, host (ASCII case-insensitive) and port match |
| https → http downgrade refused (3xx returned) | present | `bend_client.bend:1123` | — |
| Location `/abs-path` | present | `bend_client.bend:1137` | dot segments now removed |
| Location `//host/path` (network-path) | **missing** | `bend_client.bend:1137` returned the 3xx | fixed: resolved with the current scheme; review fix: dot segments removed, query kept |
| Location `https://host/a/../b` (absolute) | partial | followed with the path as given | review fix: dot segments removed, query kept |
| Location `rel/path`, `../x`, `?q` (RFC 3986 §5) | **missing** | `bend_client.bend:1137` returned the 3xx | fixed: `policy.resolve` |
| Location fragment | **missing** | sent as part of the target | fixed: dropped |
| Uppercase scheme `HTTPS://` | missing | `url.bend:182` | fixed for Location (scheme folded); request URLs unchanged |
| Each new origin re-verified (SNI, SAN) | present | M5; `tests/bend_tls_check.py` `redirect-host-reverified` | — |

## Keep-alive and pooling

| Area | Baseline | Where (45b1014) | M6 |
| --- | --- | --- | --- |
| Pool per origin (scheme, host, port), size bound, eviction | present | `bend_pool.bend:85`, `:137`; `bend_client.bend:1505` | — |
| Waiting for a connection of a full pool | **partial** | `bend_pool.bend:166`: `Chan.recv` with no deadline | review fix: `Chan.try_recv` until the request's deadline, then `Timeout`; review fix 2: a waiter that gives up leaves the waiting count (1,025 expired waits used to deadlock later returns) |
| Idle timeout (`idle_ms`, 4 s) | present | `bend_pool.bend:68` | live test |
| `Connection: close`, HTTP/1.0, close-delimited → not reused | present | H1 `http1.bend:1268` | live test |
| Stale kept connection retried once, idempotent only | present | `bend_pool.bend:266`; `bend_transport.bend:165` | live POST test |
| Server `Keep-Alive: timeout=` honoured | missing | — | not changed (client `idle_ms` bounds it) |
| One-shot calls close after each response | present | `bend_client.bend:1010` | — |

## Deadlines

| Area | Baseline | Where (45b1014) | M6 |
| --- | --- | --- | --- |
| One total deadline over connect, TLS, send, read, redirects and retries | **partial** (first audit said present) | `bend_client.bend:1296`, `:303`, `:483`; but a pooled request waited for a connection without one (`bend_pool.bend:166`) and a retry slept its full backoff past it (`bend_client.bend:1136`) | review fix: pool waits end at the deadline; a retry whose backoff would reach it is not made and the last outcome is returned at once; no try, retry or redirect starts past it |
| Separate connect + TLS handshake deadline | **missing** | `bend_client.bend:268` used the total | added: `with_connect_timeout(c, ms)` |
| Per-read (idle) deadline for head and body | **missing** | only the total | added: `with_read_timeout(c, ms)`; review fix: it also bounded request writes (a slow upload failed) and was ignored by stream/events; now reads only, everywhere |
| DNS resolution bounded | partial | `wire_resolve` is a blocking `getaddrinfo` without a timeout; the deadline is checked right after it | M6 item 3: fixed, `wire_resolve_timeout` (see IPv6 below); a lookup past the connect deadline is `Timeout` |
| stream/events: per-read deadline | present | `bend_client.bend:1478` | connect deadline also applies; review fix: `read_ms` applies too (the smaller wins), one-shot and pooled |

## Optional

| Area | Baseline | M6 |
| --- | --- | --- |
| gzip/deflate Content-Encoding | missing; not advertised, so servers send identity; an unrequested coded body is returned as-is with its header | deferred |
| HTTP CONNECT proxy for HTTPS | missing | deferred |
| Session resumption, HTTP/2 | missing | excluded (TLS profile, M6 exclusions) |

## Deferred, with rationale

- **Chunked upload / streamed request bodies.** Every request body is an
  in-memory `B.Bytes`, and the proven `body_length`/`writes_count` laws tie
  Content-Length to those bytes. Streaming would need a pull callback
  threaded through the affine TLS owner, the pool and the retry and
  redirect drivers, where a consumed body cannot be replayed. It would add
  a new compile-heavy path to `bend_client.bend` for a use that bounded
  bodies (8 MiB default, `with_max_body`) already cover.
- **gzip/deflate.** Needs an inflate implementation in Bend, with
  window/bomb limits and its own tests. The client never sends
  `Accept-Encoding`, so a compliant server answers with identity.
- **CONNECT proxies.** Needs proxy configuration, a CONNECT exchange
  before TLS, proxy authentication and its own error mapping. No M6 target
  needs a proxy.
- **DNS timeout.** Done in M6 item 3 (IPv6, below): `wire_resolve_timeout`
  waits for the lookup only until the deadline.

## Tests added in M6

- `test.bend`: 46 policy cases (header validity, final statuses, private
  and content headers, method rewriting, 14 Location resolutions, a
  fragment cut, origin comparison).
- `../wire/test.bend`: 17 framing cases (CL+TE in either order, TE lists,
  differing or listed lengths, obs-fold, space before colon, bare LF, head
  limit, bad, oversized, signed and truncated chunks, extensions and
  trailers).
- `tests/bend_m6_check.py`: 74 live scenarios (100 after the review fix) through the native client
  over Bend TLS 1.3, against two independent Python `ssl` peers (two
  origins). The groups are framing 42, redirects 13, pool 6, deadlines 8
  and stream 5. Pool cases count the peer's TCP connections. Deadline
  cases check the elapsed time the client reports. The stream group
  checks Adler-32 for each piece of a 4 MiB chunked and Content-Length
  body, and checks that the client's peak RSS grows by less than the body
  size (measured: +0.05 MiB, against +94 MiB when the body is buffered).

## Review fix (2026-11-07)

An independent review of `22128d7..4ea30b7` found four P2 issues in this
client; all four were reproduced red on macwork before the fix.

- Streams and events ignored `read_ms`, and `read_ms` bounded request
  writes. `lim.at` (reads) and `lim.send` (writes) now differ: a read
  takes `read_ms` within the total deadline (streaming: within
  `timeout_ms` per read); a write takes only the total deadline
  (streaming: `timeout_ms`). Before: a 1 s stall under `read_ms` 300 was
  read through (`ok` at 1.1 s); a 2 MiB upload read slowly failed at
  440 ms.
- Pool waits and retry backoff ignored the total deadline. Before: a GET
  with a 400 ms total waited 2.1 s for a pool of one; three 5 s backoffs
  under an 800 ms total took 15.1 s. Now 0.41 s and 0.08 s. (A waiter
  that gave up stayed counted in `waiting`; that was wrong, see review
  fix 2.)
- Network-path and absolute Locations kept dot segments
  (`//other/a/../b` sent `/a/../b`). `policy.bend` `net` removes them
  after the authority and keeps the query.
- Interop: Content-Length lists of one value are accepted, and a default
  User-Agent is sent (rows above). `HTTP/1.1 200` without the SP stays
  refused.
- Unchanged: the legacy (Bun) client in `client.bend`/`pool.bend`.

Tests: 14 policy unit cases (8 Locations, 6 User-Agent), 11 framing unit
cases (and `rh_cl_list` inverted) with the law `body_length_read`, and 26
live scenarios. Live totals are framing 53, redirects 16, pool 6,
deadlines 20 and stream 5 (100, was 74).

## Review fix 2 (2026-11-08)

An independent review of `4ea30b7..e7e40ae` found one P1 and three P2
issues; each was reproduced red on macwork before its fix.

- P1, system trust (`crypto/pem_bundle.bend`): `TRUSTED CERTIFICATE`
  blocks were skipped undecoded, so a plain root stayed trusted when the
  same bundle's TRUSTED copy rejected serverAuth. Their `X509_CERT_AUX`
  trust settings are now parsed and honoured, failing closed (rules in
  TLS_PROFILE.md version 3). Before, the pinned github.com chain verified
  against a bundle whose TRUSTED copies of its roots reject serverAuth
  (OpenSSL 3.6 refuses it when those copies come first); now it is
  refused in either order.
- P2, bundle framing: an AlgorithmIdentifier with two parameters (`NULL,
  NULL` after an unknown OID) loaded; now at most one element may follow
  the OID (SPKI and TBS signature).
- P2, pool (`bend_pool.bend`): a waiter that gave up stayed counted in
  `waiting`, so every later return sent a wake for it into the 1,024-slot
  channel. After 1,025 expired waits the next return blocked in
  `Chan.send` (`bend: deadlock: every computation waits on a channel`;
  with other tasks alive, later requests hang past their deadlines). A
  waiter that gives up now decrements `waiting` under the lock; if it was
  0, a wake was already sent for it and it takes that wake. The channel
  never holds more wakes than there are waiters.
- P2, bundle files (`bend_transport.bend`): `from_bundle_file` and the
  system loader parsed one `read(2)`. A FIFO or pipe in `SSL_CERT_FILE`
  gave its first chunk only; the rest (more roots, or trailing garbage)
  was ignored. Both now read to end of file, at most 2 MiB in all, else
  `bundle-limit`.

Tests: 35 system admission rows and a changed one (33 red before), 2
explicit rows (1 red; the signature form was already refused by
`C.anchor`), 12 FIFO cases (9 red), the live scenario `pool-waiters`
(1,200 expired waiters, then 1,100 returns and two GETs; red: deadlock),
and the new phase `bend_system_bundle_chain` (6 github.com cases beside
OpenSSL; 4 red). Live pool total 7 (was 6).

## IPv6 (M6 item 3, 2026-11-07)

| Area | Before | M6 item 3 |
| --- | --- | --- |
| IPv6 TCP connect | missing: `wire_connect_timeout` took IPv4 only (`io_sys_addr`) | native: IPv4 or IPv6 literal (`gw_addr`, `inet_pton`, no `%zone`); Bun: IPv4 only |
| AAAA resolution | missing: `wire_resolve` asked for `AF_INET` and kept the first | `wire_resolve_timeout(host, ms)`: every address, A and AAAA, in the resolver's (RFC 6724) order, at most 32; Bun: blocking `getent ahosts`, ms not applied |
| Bracketed URL literals | missing: `[` was `BadUrl` | `url.bend`: RFC 5952 canonical host, bracketed authority; zone IDs (`%25`), IPvFuture and dotted IPv4 tails refused |
| IPv6 IP-SAN identity | x509 already matched 16-byte iPAddress SANs; the client built only IPv4 references | `bend_transport.identity`: a v6 literal is `X.Ip{16 bytes}`, no SNI |
| Address fallback | one address | `wire/dial.bend`: sequential, ordered, per-attempt budget (below) |
| Server bind on IPv6 | Base `TCP.listen` is IPv4 only | `wire_listen_on(host, port)`: IPv4 or IPv6 literal, `IPV6_V6ONLY` (native) |

Connection policy (Bend, `wire/dial.bend` and `wire/ip.bend`):

- A literal is connected to directly, without a lookup.
- A name is looked up with a deadline (the connect phase's: `connect_ms`
  if set, else the total). getaddrinfo cannot be cancelled, so the lookup
  runs on a detached thread that writes to a pipe; the event loop parks on
  the pipe with the deadline. Past it the caller gets `ETIMEDOUT` (client:
  `Timeout`) and the thread finishes and frees its record on its own; it
  does not hold the process open. At most 64 unfinished lookups
  (`EAGAIN` beyond). A failed lookup is `NoHost` as before.
- Order: the resolver's order, scoped link-local addresses dropped, then
  families alternate starting with the first address's (RFC 8305 section
  4); at most 8 addresses.
- Attempts are sequential, not raced (RFC 8305 Happy Eyeballs is
  deferred). Each attempt but the last gets `max(left / n, min(left, 250
  ms))` of the time left, n being the addresses still to try; the last gets
  all of it. A refused or unreachable address (fast RST or ICMP) moves on at
  once; a silent one costs its share, so one black-holed family cannot use
  up the whole connect deadline. Only TCP failures move on; a TLS failure
  on a connected address is the answer (no retry on another address).
- Why no race: a Bend IO computation has one continuation per pending
  effect, and `IO.fork`/`IO.within` cannot cancel the loser, so a lost
  connect would hold a socket and keep the program alive until its own
  deadline. A race needs a new multi-socket effect (start nonblocking
  connects, wait on all, close the losers), with the stagger policy in
  Bend. That is a larger surface than M6 needs; on dual-stack loopback and
  for hosts whose broken family fails fast, sequential order behaves the
  same.

Tests: `wire/ip_test.bend` (54: text/bytes, canonical text, order and
budget), `wire/ipv6_check.py` (12 native transport cases: bytes over
`::1`, IPv4 refused on the same port, A+AAAA for localhost, dialing an
IPv6-only and an IPv4-only listener by name, refused fallback to nothing,
zone IDs refused by the effects, and a lookup cut at 300 ms while multicast
DNS would take 5 s), `test.bend` (22 URL/redirect cases) and
`tests/bend_m6_check.py --mode ipv6` (17 live scenarios against Python TLS
peers on `::1` and `127.0.0.1` with a synthetic IPv6 IP-SAN leaf).

Limits: no Happy Eyeballs racing; no zone IDs; IPv4-embedded IPv6 text is
refused (the bytes are fine when written in hex); the Bun lookup blocks;
UDP stays IPv4; the legacy client (`client.bend`) still resolves IPv4 only,
so an IPv6 URL there fails `NoHost`.
