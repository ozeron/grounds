<p align="center"><img src="assets/grounds.svg" width="160" alt="grounds: coffee grounds pouring onto a mound"></p>

# grounds

A monorepo of [Bend 2](https://github.com/bendlang/bend) packages, built with [moon](https://moonrepo.dev).

| Package | Does |
|---|---|
| [`json`](json/) | JSON parser and printer, proven to round-trip; to be published as `grounds-json` |
| [`utf8`](utf8/) | strict UTF-8 decoding of raw bytes |
| [`io`](io/) | whole-file reads, as text or raw bytes |
| [`wire`](wire/) | TCP on bytes: byte-exact send and receive |
| [`http1`](http1/) | HTTP/1.1 on the wire: request parsing, response writing (RFC 9112) |
| [`http`](http/) | HTTP messages: methods, status, headers, query, request, response (scaffold; HTTP/1.1, server, router and JSON next) |

```sh
mise install              # the pinned bend and moon
moon run :check           # every package's checks
moon run json:check       # every test, law and conformance case of json
moon run json:bench       # json against Go, jq, Python, Node and Bun
```

Each package is a moon project (`<package>/moon.yml`); `.moon/workspace.yml` lists them.

The logo is drawn by `assets/logo.py` (seeded, so it redraws the same).
