# grounds-redis

A Redis client for [Bend 2](https://github.com/bendlang/bend), speaking RESP2 over `grounds-wire` sockets. The spec is in [docs/resp.md](docs/resp.md).

```python
import ../redis/redis.bend as Redis
import ../redis/resp.bend as R

s : Socket <- IO.try(Socket, Redis.connect("127.0.0.1", 6379))
m : Redis.Reply() <- Redis.set(s, "k", "v")      # (socket, Done{Simple{"OK"}})
```

- **`command(sock, args)`** sends one command and reads until its whole reply has come. It gives back the socket and `Done{reply}`, or `Fail{why}`. `ping`, `get`, `set`, `del` and `incr` build the arguments for you.
- **`Reply`** is `Simple`, `Error`, `Int{neg, n}`, `Bulk{bytes}`, `RNil` or `Arr{items}`. Bulk strings are bytes, since Redis values are binary. `R.text(reply)` decodes one as UTF-8, and `R.show(reply)` prints it the way redis-cli does.
- **`resp.bend`** is pure: `encode(args)` builds a command, and `parse(bytes)` reads one reply and hands back the bytes after it. Nested arrays use a stack of their own, so no depth overflows.

`moon run redis:check` runs `test.bend` (24 cases) and the cold check. It also runs `examples/demo.bend` when a Redis is listening on 127.0.0.1:6379, e.g. `podman run -d -p 6379:6379 redis:7-alpine`.

Laws come next: [docs/LAWS.md](docs/LAWS.md) lists them, with the spec sections they come from. The plan is in [docs/TODO.md](docs/TODO.md).
