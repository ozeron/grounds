<p align="center"><img src="assets/grounds.svg" width="160" alt="grounds: coffee grounds pouring onto a mound"></p>

# grounds

A monorepo of [Bend 2](https://github.com/bendlang/bend) packages, built with [moon](https://moonrepo.dev).

| Package | Does |
|---|---|
| [`json`](json/) | JSON parser and printer, proven to round-trip; to be published as `grounds-json` |
| [`utf8`](utf8/) | strict UTF-8 decoding of raw bytes |
| [`io`](io/) | whole-file reads, as text or raw bytes |
| [`wire`](wire/) | TCP on bytes: byte-exact send and receive |
| [`http/core`](http/core/) | HTTP messages: methods, status, headers, query, request, response |
| [`http/wire`](http/wire/) | HTTP/1.1 on the wire: request parsing, response writing (RFC 9112) |
| [`http/server`](http/server/) | `serve(handler, config)`: an HTTP/1.1 server with keep-alive, timeouts and middleware |
| [`http/router`](http/router/) | routes as data: a request matched to your route value and its captures |
| [`http/json`](http/json/) | JSON request bodies and responses; `examples/todo.bend` is a JSON API |

## Use from BendHub

Version 0.1.0 of every package is one bundle, `0x64e1b9e0466cf913fa57e70aeb11c176`. Import each module from it by its path in this repo:

```python
import 0x64e1b9e0466cf913fa57e70aeb11c176/json/json.bend as J
import 0x64e1b9e0466cf913fa57e70aeb11c176/http_json/http_json.bend as HJ
import 0x64e1b9e0466cf913fa57e70aeb11c176/http_server/server.bend as Server
```

Take every module from the same bundle. A module's identity is its bundle's hash plus its path, so `http/status.bend` from one bundle is a different type from the same file in another.

## Develop

```sh
mise install              # the pinned bend and moon
moon run :check           # every package's checks
moon run json:check       # every test, law and conformance case of json
moon run json:bench       # json against Go, jq, Python, Node and Bun
```

Each package is a moon project (`<package>/moon.yml`); `.moon/workspace.yml` lists them.

The logo is drawn by `assets/logo.py` (seeded, so it redraws the same).
