# Changelog

## 0.2.0

Needs Bend 2.0.38 (`mise.toml` pins it); 0.1.0 needs 2.0.27. Bend 2.0.38 halves most compile peaks.

Breaking:
- `io`: read arguments with `Io.args()`. Since Bend 2.0.32 `IO.args()` starts with the program's name; `Io.args()` drops it.
- `wire`: `listen(port)` listens on `0.0.0.0`, now that Bend's `TCP.listen` takes a host.
- `http/client`: the plain-text body constructor is `Plain`, not `Text`. `Kv`, `Verb`, `Url`, `url(s)` and `form.enc` are in `url.bend`. `UBad{}` has no payload; a request still reports it as `BadUrl`.
- `http/client` pool: the `Plan` constructor `Wait` is `Await`.
- `http/core`: `sign` and `verify` are in `cookie_sign.bend`, not `cookie.bend`.
- `crypto`: the constructor of `x509_name_match`'s `Key` is `NameKey`; the traffic state `Ready` is `ChachaReady`.
- `rtc`: `Outcome` and `Context` are in `ice_outcome.bend`. In `ice_consent` and `ice_transactions`, `Ready` is `Now`.
- `http/router` laws: `Pair` is `SegPair`.

Bend 2.0.38 defines `Ready`, `Text`, `Wait`, `Exit`, `Poll`, `Look`, `Scroll` and `Pair` itself, so grounds no longer can.

Also:
- Native effects (`wire`, `random`, `cookie`) use Bend's new effect API.
- `tools/bend_native_parts.py` and `json/scripts/cold.py` read Bend 2.0.38's C.
- `json` checks build each program once; pretty printing is one pass.
