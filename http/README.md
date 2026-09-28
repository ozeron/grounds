# grounds-http

An HTTP/1.1 stack for [Bend 2](https://github.com/bendlang/bend), in layers. Each is its own package with its own README and laws.

| Package | Does |
|---|---|
| [`core`](core/) | messages: methods, status, headers, query, request, response (RFC 9110) |
| [`wire`](wire/) | HTTP/1.1 parsing and writing (RFC 9112); proven against smuggling and response splitting |
| [`server`](server/) | `serve(handler, config)`: keep-alive, timeouts, streaming, graceful stop, health, middleware |
| [`client`](client/) | requests to other services: JSON, forms, streams, server-sent events and a pool |
| [`router`](router/) | routes as data, matched to your own route type |
| [`json`](json/) | JSON bodies; `examples/todo.bend` is a JSON API |

A hello server is `server/examples/hello.bend`, 13 lines.
