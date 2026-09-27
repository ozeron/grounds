<p align="center"><img src="assets/grounds.svg" width="160" alt="grounds: coffee grounds pouring onto a mound"></p>

# grounds

A monorepo of [Bend 2](https://github.com/bendlang/bend) packages: JSON, UTF-8, TCP and HTTP/1.1. Each package proves its guarantees in `LAWS.bend` and has its own README.

| Package | Does |
|---|---|
| [`json`](json/) | JSON parse, print, path reads; proven to round-trip |
| [`utf8`](utf8/) | strict UTF-8 decoding |
| [`io`](io/) | whole-file reads |
| [`wire`](wire/) | TCP on raw bytes |
| [`http/core`](http/core/) | HTTP messages: methods, status, headers, requests, responses |
| [`http/wire`](http/wire/) | HTTP/1.1 parsing and writing |
| [`http/server`](http/server/) | `serve(handler, config)`, timeouts, middleware |
| [`http/router`](http/router/) | routes as data |
| [`http/json`](http/json/) | JSON bodies and a todo API example |

```sh
mise install        # pinned bend and moon
moon run :check     # every package's tests, laws and examples
```

From BendHub, 0.1.0 is one bundle, `0x64e1b9e0466cf913fa57e70aeb11c176` (tag `grounds/v0.1.0`). Take every module from that one bundle.
