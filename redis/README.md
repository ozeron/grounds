# grounds-redis

A Redis client for [Bend 2](https://github.com/bendlang/bend): RESP2 and RESP3, pipelining, AUTH and SELECT, a pool, and timeouts and limits on everything. The spec is in [docs/resp.md](docs/resp.md).

```python
import ../redis/redis.bend as Redis

cfg = Redis.with_password(Redis.config("127.0.0.1", 6379), "s3cret")
r : Result<&1, &1, Redis.Down, Redis.Client()> <- Redis.open(cfg)
g : Redis.Got(Redis.Res(Maybe<&2, String>)) <- Redis.get(c, "k")   # Done{(c, Done{Some{"v"}})}
```

## Failing safely

- **Down closes the client.** Every call hands the client back with its answer, or fails with `Down`: `Timeout`, `Closed`, `TooLarge`, `Protocol`, `Io` or `Rejected`. A client that failed is closed and not handed back, so a connection left half-read can never be used again.
- **An error reply is not Down.** `-ERR …` is an answer: typed calls give `Fail{"ERR …"}`, and the client stays open.
- **Nothing waits forever.** `timeout_ms` (default 5 s) bounds each send and each whole reply. A server that stalls, trickles or stops reading is `Timeout`.
- **Nothing grows unbounded.** `max_reply` (default 64 MiB) caps each reply's bytes. A declared bulk length or aggregate count past it is refused before a byte of it is read.
- **Numbers stay text.** Integer replies keep their digits: the runtime aborts on a Nat past 2^48 − 1, and a reply may hold any number of digits. `Redis.as_int` reads them when they fit.

## API

| Call | Does |
|---|---|
| `open(cfg)` | connect, then `HELLO 3` or `AUTH`, and `SELECT`, as `cfg` says |
| `config(host, port)`, `with_password`, `with_user`, `with_db`, `with_resp3`, `with_timeout`, `with_max_reply` | the config |
| `command(c, args)`, `command_bytes(c, args)` | one command, its raw `R.Reply`; arguments as text or as bytes |
| `pipeline(c, cmds)` | many commands in one write, their replies in order |
| `get`, `get_bytes`, `set`, `set_bytes`, `set_ex`, `del`, `exists`, `incr`, `incr_by`, `expire`, `ttl`, `ping` | typed: `Got(Res(A))`, where `Res` is the value or the error reply |
| `call(A, c, args, as_…)` | any command, its reply read by `as_ok`, `as_text`, `as_bytes`, `as_int`, `as_nat`, `as_bool` or `as_list` |
| `pool(cfg, n)`, `with(A, p, f)`, `run(retries, p, args)`, `pool.close(p, n)` | a pool shared by tasks. A client that failed is replaced on its next use. `run` resends on a new connection: only for commands safe to repeat |

- Bytes after a reply are kept for the next one, so replies that come together, or pipelined, come apart right.
- RESP3 pushes (client tracking, pub/sub) are skipped while waiting for a reply. Attributes are dropped.
- `resp.bend` is pure: `encode`, `parse` (resumable: `More` carries where to go on, and how many bytes are missing at least) and `write`.

## Guarantees

`LAWS.bend`, proven in `PROOF.bend` (lemmas in `proof/`):
- **No argument can inject a command.** A command reads back as the array of bulk strings it was built from, for any bytes in any argument. A CR LF, or a whole command, inside an argument stays inside it.
- **Bulk strings are framed by their length.** Any bytes come back as they are, and what follows is kept.
- **A bulk string cut short is `More`, never a reply.**
- **Null is not the empty string.** `$-1` is nil, and `$0` is `""`.

[docs/LAWS.md](docs/LAWS.md) says which spec laws are proven, and how the others are checked.

## Checks

`moon run redis:check` (about 20 s):
1. `test.bend`: 57 cases of RESP2, RESP3, partial input and the writer.
2. `PROOF.bend`: the laws.
3. The cold check.
4. `tests/faults.bend` against `tests/fake.py`, a server that misbehaves in 12 ways: stalls, closes mid-reply, floods, sends garbage, trickles, never reads, sends pushes, sends byte by byte, sends two replies in one write, and closes after every reply. Each fault must end in its `Down` within its time bound. The pool must reconnect.
5. `tests/fuzz.bend` against `tests/fuzz.py`: 2000 random valid and mutated replies, sent in random chunks. The client must parse each exactly as a reference parser does, byte for byte, or go down when it does.
6. With a Redis on 6379: `examples/demo.bend`, and `tests/live.bend`. The live tests cover binary and 5 MB values, a 1000-command pipeline, SELECT, RESP3 maps, the cap, and 40 tasks × 250 INCR through a pool of 8. With one on 6380 (password `s3cret`): `tests/auth.bend`.

```sh
podman run -d -p 6379:6379 redis:7-alpine
podman run -d -p 6380:6379 redis:7-alpine redis-server --requirepass s3cret
```
