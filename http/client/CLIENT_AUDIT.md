# HTTP/1.1 client audit (M6 item 1)

Scope: the native Bend TLS client path, `bend_client.bend` (C) and
`bend_pool.bend` (Pool), over the shared framing in `../wire/http1.bend`
(H1). The baseline is `45b1014` (2026-11-07). Line numbers in the
"Baseline" column refer to that revision. RFC 9110 and RFC 9112 set the
expectations for a practical client, not a browser.

Status: **present**, **partial** or **missing** at the baseline. The last
column says what M6 did.

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
| Default `User-Agent` | missing | none sent; callers add one with `with` | not changed (would alter every request's bytes) |

## Response parsing and framing

| Area | Baseline | Where (45b1014) | M6 |
| --- | --- | --- | --- |
| Status line `HTTP/d.d SP ddd SP reason` | partial | H1 `http1.bend:978`: any three digits (000–999) accepted; `HTTP/1.1 200` with no SP is refused (strict, kept) | fixed: a final status must be 200–599, else `BadResponse` (`policy.final`) |
| CRLF only, bare CR/LF refused; head size limit | present | H1 `http1.bend:51` (`max_head_bytes`, 16 KiB) | — |
| Header syntax: token name, no space before colon, value without CTL | present | H1 `http1.bend:205`, `:229` | — |
| obs-fold rejected | present | H1 `http1.bend:220` (`ObsFold`) | — |
| Content-Length: digits only; differing duplicates refused | present | H1 `http1.bend:252`–`:283` | — |
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
| Authorization and Cookie dropped cross-origin | present | `bend_client.bend:1160` | also `Proxy-Authorization` |
| ...but kept on a same-origin absolute Location | **partial** | `bend_client.bend:1203` stripped them for every absolute URL | fixed: kept when scheme, host (ASCII case-insensitive) and port match |
| https → http downgrade refused (3xx returned) | present | `bend_client.bend:1123` | — |
| Location `/abs-path` | present | `bend_client.bend:1137` | dot segments now removed |
| Location `//host/path` (network-path) | **missing** | `bend_client.bend:1137` returned the 3xx | fixed: resolved with the current scheme |
| Location `rel/path`, `../x`, `?q` (RFC 3986 §5) | **missing** | `bend_client.bend:1137` returned the 3xx | fixed: `policy.resolve` |
| Location fragment | **missing** | sent as part of the target | fixed: dropped |
| Uppercase scheme `HTTPS://` | missing | `url.bend:182` | fixed for Location (scheme folded); request URLs unchanged |
| Each new origin re-verified (SNI, SAN) | present | M5; `tests/bend_tls_check.py` `redirect-host-reverified` | — |

## Keep-alive and pooling

| Area | Baseline | Where (45b1014) | M6 |
| --- | --- | --- | --- |
| Pool per origin (scheme, host, port), size bound, eviction | present | `bend_pool.bend:85`, `:137`; `bend_client.bend:1505` | — |
| Idle timeout (`idle_ms`, 4 s) | present | `bend_pool.bend:68` | live test |
| `Connection: close`, HTTP/1.0, close-delimited → not reused | present | H1 `http1.bend:1268` | live test |
| Stale kept connection retried once, idempotent only | present | `bend_pool.bend:266`; `bend_transport.bend:165` | live POST test |
| Server `Keep-Alive: timeout=` honoured | missing | — | not changed (client `idle_ms` bounds it) |
| One-shot calls close after each response | present | `bend_client.bend:1010` | — |

## Deadlines

| Area | Baseline | Where (45b1014) | M6 |
| --- | --- | --- | --- |
| One total deadline over connect, TLS, send, read, redirects and retries | present | `bend_client.bend:1296`, `:303`, `:483` | — |
| Separate connect + TLS handshake deadline | **missing** | `bend_client.bend:268` used the total | added: `with_connect_timeout(c, ms)` |
| Per-read (idle) deadline for head and body | **missing** | only the total | added: `with_read_timeout(c, ms)` |
| DNS resolution bounded | partial | `wire_resolve` is a blocking `getaddrinfo` without a timeout; the deadline is checked right after it | not changed (needs a wire effect) |
| stream/events: per-read deadline | present | `bend_client.bend:1478` | connect deadline also applies |

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
- **DNS timeout.** `wire_resolve` is a `wire` effect. Bounding it needs a C/JS
  effect change outside the client.

## Tests added in M6

- `test.bend`: 46 policy cases (header validity, final statuses, private
  and content headers, method rewriting, 14 Location resolutions, a
  fragment cut, origin comparison).
- `../wire/test.bend`: 17 framing cases (CL+TE in either order, TE lists,
  differing or listed lengths, obs-fold, space before colon, bare LF, head
  limit, bad, oversized, signed and truncated chunks, extensions and
  trailers).
- `tests/bend_m6_check.py`: 74 live scenarios through the native client
  over Bend TLS 1.3, against two independent Python `ssl` peers (two
  origins). The groups are framing 42, redirects 13, pool 6, deadlines 8
  and stream 5. Pool cases count the peer's TCP connections. Deadline
  cases check the elapsed time the client reports. The stream group
  checks Adler-32 for each piece of a 4 MiB chunked and Content-Length
  body, and checks that the client's peak RSS grows by less than the body
  size (measured: +0.05 MiB, against +94 MiB when the body is buffered).

