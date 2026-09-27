# grounds-redis

A Redis client for [Bend 2](https://github.com/bendlang/bend): RESP2 and RESP3, pipelining, AUTH and SELECT, a pool, and timeouts and limits on everything. The spec is in [docs/resp.md](docs/resp.md).

```python
import ../redis/redis.bend as Redis

cfg = Redis.with_password(Redis.config("127.0.0.1", 6379), "s3cret")
# open, GET, close: Done{Done{Some{"v"}}}
r : Result<&1, &1, Redis.Down, Redis.Res(Maybe<&2, String>)> <- Redis.session(Redis.Res(Maybe<&2, String>), cfg, c => Redis.get(c, "k"))
```

## Failing safely

- **Connections are always closed, if you use `session` or a `Pool`.** `session(A, cfg, f)` opens a client, runs `f`, and closes it on every path; `Pool.with` does the same for pooled clients. The type system cannot enforce it: a Bend value may always be dropped, so a client from `open` that is dropped without `close` keeps its socket until the process ends. Use `open` and `close` by hand only when a client must outlive one function.
- **Down closes the client.** Every call hands the client back with its answer, or fails with `Down`: `Timeout`, `Closed`, `TooLarge`, `Protocol`, `Io` or `Rejected`. A client that failed is closed and not handed back, so a connection left half-read can never be used again.
- **An error reply is not Down.** `-ERR …` is an answer: typed calls give `Fail{"ERR …"}`, and the client stays open.
- **Nothing waits forever.** `timeout_ms` (default 5 s) bounds the connect, each send and each whole reply. An address that drops packets, or a server that stalls, trickles or stops reading, is `Timeout`.
- **Nothing grows unbounded.** `max_reply` (default 8 MiB) caps each reply's bytes, bytes left from the last read included. A declared bulk length or aggregate count that cannot fit with its header (16 bytes) is refused before a byte of it is read. A reply takes about 20 bytes of memory per byte while it is read: 8 MiB is about 160 MiB, per client.
- **No reply is read twice.** A reply that comes in pieces resumes where it stopped, lines included, so a long reply costs its length, not its length squared.
- **Numbers stay text.** Integer replies keep their digits: the runtime aborts on a Nat past 2^48 − 1, and a reply may hold any number of digits. `Redis.as_int` reads them when they fit.

## API

| Call | Does |
|---|---|
| `session(A, cfg, f)` | open a client, run `f`, close it whatever happens: the way to use one |
| `open(cfg)`, `close(c)` | connect, then `HELLO 3` or `AUTH`, and `SELECT`, as `cfg` says; and close |
| `config(host, port)`, `with_password`, `with_user`, `with_db`, `with_resp3`, `with_timeout`, `with_max_reply` | the config |
| `command(c, args)`, `command_bytes(c, args)` | one command, its raw `R.Reply`; arguments as text or as bytes |
| `pipeline(c, cmds)` | many commands in one write, their replies in order |
| `get`, `get_bytes`, `set`, `set_bytes`, `set_ex`, `del`, `exists`, `incr`, `incr_by`, `expire`, `ttl`, `ping` | typed: `Got(Res(A))`, where `Res` is the value or the error reply |
| `call(A, c, args, as_…)` | any command, its reply read by `as_ok`, `as_text`, `as_bytes`, `as_int`, `as_nat`, `as_bool` or `as_list` (`None` for the null array) |
| `pool(cfg, n)`, `with(A, p, f)`, `run(retries, p, args)`, `pool.close(p)` | a pool shared by tasks. A client that failed is replaced on its next use. `run` resends, and reports the last failure; after `Closed` or `Io` it uses a new connection, as the other pooled ones may be as stale. Only for commands safe to repeat. `pool.close` waits for clients in use to come back |

- Bytes after a reply are kept for the next one, so replies that come together, or pipelined, come apart right.
- `command_bytes` with a value past 255 sends nothing and answers with an error reply; the client stays open.
- Simple strings and errors that are not UTF-8 keep every byte, as Latin-1 chars.
- RESP3 pushes (client tracking, pub/sub) are skipped while waiting for a reply. Attributes are dropped.
- `resp.bend` is pure: `encode`, `parse` (resumable: `More` carries where to go on, and how many bytes are missing at least) and `write`.

## Guarantees

`LAWS.bend`, proven in `PROOF.bend` (lemmas in `proof/`):
- **No argument can inject a command.** A command reads back as the array of bulk strings it was built from, for any bytes in any argument of up to the limit (and fewer than 10^10) bytes. A CR LF, or a whole command, inside an argument stays inside it. `parse_encode` states it for `encode` on Strings, read as `parse` reads it.
- **Bulk strings are framed by their length.** Any bytes come back as they are, and what follows is kept.
- **A bulk string cut short, anywhere, is `More`, never a reply:** after the `$`, in its length, at the CR, in its bytes, or before or inside its final CR LF.
- **Null is not the empty string.** `$-1` is nil, and `$0` is `""`.

The laws are about this parser reading this encoder. The framing is RESP's, so they stand for any parser that reads RESP as the spec says, Redis's included. They take the parser's fuel as a parameter: `parse` runs with 2^32 − 1 steps, three per argument, and the checker cannot unfold a literal that large.

[docs/LAWS.md](docs/LAWS.md) says which spec laws are proven, and how the others are checked.

## Checks

`moon run redis:check` (about 20 s):
1. `test.bend`: 68 cases of RESP2, RESP3, partial input and the writer.
2. `PROOF.bend`: the laws.
3. The cold check.
4. `tests/faults.bend` against `tests/fake.py`, a server that misbehaves in 15 ways: it stalls, closes mid-reply, floods past the cap (the default one too), sends garbage, trickles, never reads, sends pushes (between pipelined replies too), sends byte by byte, sends two replies in one write, closes after every reply, sends replies at the cap, and closes at once while 20 MB go to it. Each fault must end in its `Down` within its time bound. A pool must reconnect, and fail fast when its server is down. A connect to an address that drops packets must time out.
5. `tests/fuzz.bend` against `tests/fuzz.py`: 2000 random valid and mutated replies (`FUZZ_N`, `SEED`), sent in random chunks. The client must parse each exactly as a reference parser does, byte for byte, or go down when it does.
6. With a Redis on 6379: `examples/demo.bend`, and `tests/live.bend`. The live tests cover binary and 5 MB values, a 1000-command pipeline, SELECT, RESP3 maps, the cap, 40 tasks × 250 INCR through a pool of 8, and that 200 sessions leave no connection open. With one on 6380 (password `s3cret`): `tests/auth.bend`.

```sh
podman run -d -p 6379:6379 redis:7-alpine
podman run -d -p 6380:6379 redis:7-alpine redis-server --requirepass s3cret
```
