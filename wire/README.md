# grounds-wire

TCP on bytes for [Bend 2](https://github.com/bendlang/bend). Base's `TCP.send` and `TCP.recv` decode and encode UTF-8, which breaks byte counts and binary protocols; `wire_recv` and `wire_send` move bytes (0..255) as they are.

```python
import ../wire/wire.bend as W

l : Listener <- IO.try(Listener, W.listen(8080))
a : Listener & Result<&1, &1, U32 & String, Socket> <- W.accept(l)
r : Socket & Result<&1, &1, U32 & String, List<&2, U32>> <- W.wire_recv(sock, 4096)
w : Socket & Result<&1, &1, U32 & String, Unit> <- W.wire_send(sock, [72, 105])
```

| Function | Does |
|---|---|
| `W.wire_recv(sock, max)` | up to `max` bytes, once some arrive; `[]` when the peer has closed |
| `W.wire_recv_timeout(sock, max, ms)` | the same, as `Some{bytes}`; `None{}` when nothing comes within `ms` |
| `W.wire_send(sock, bytes)` | every byte; a value past 255 fails with `EINVAL` before any is sent |
| `W.wire_send_timeout(sock, bytes, ms)` | the same, failing `ETIMEDOUT` when the peer takes nothing for `ms` |
| `W.wire_connect_timeout(host, port, ms)` | `connect`, failing `ETIMEDOUT` past `ms`: an address that drops packets would wait for the OS |
| `W.wire_accept_timeout(l, ms)` | `accept`, as `Some{sock}`; `None{}` when no connection comes within `ms` |
| `W.wire_resolve(host)` | a host name to its first IPv4 address, dotted; `connect` takes only addresses |
| `W.wire_on_stop()` | from now on SIGTERM and SIGINT set the stop flag instead of ending the process |
| `W.wire_stopping()` | 1 once a stop signal has come, else 0 |
| `W.wire_live(d)` | a process-wide counter: adds `d` (1, 4294967295 for −1, or 0 to read) and returns the count |
| `W.wire_tls_listen_ctx(cert, key)` | loads a PEM certificate chain and matching private key for TLS server handshakes |
| `W.wire_tls_accept(sock, ms)` | accepts TLS on a connected socket within `ms` |
| `W.wire_close(sock)` | sends TLS close_notify when needed, then closes the socket |
| `W.listen(port)`, `W.accept(l)`, `W.connect(host, port)`, `W.close(sock)`, `W.close_listener(l)` | Base's own |

- The TLS server uses OpenSSL 3 at run time, with TLS 1.2 as its minimum, no 0-RTT, and `http/1.1` as its only accepted ALPN offer. After `wire_tls_accept`, the ordinary `wire_recv_timeout` and `wire_send_timeout` effects carry encrypted bytes. Use `wire_close` for both TLS and plain sockets. `BEND_LIBSSL` can name libssl when the default paths do not find it.
- The TLS client uses `wire_tls_connect(sock, host, ms)`, `wire_tls_send_timeout`, `wire_tls_recv_timeout` and `wire_tls_close`. It verifies the certificate chain and host; `GROUNDS_TLS_CA` adds a PEM trust root.
- An effect's name is global in a program: its C id is `CID_WIRE_RECV`, taken from the def's name. So the effects carry the package's name, and there are no `recv`/`send` wrappers: a one-line wrapper is merged into the effect and takes its name.
- The effects follow `bend-kit-wire` on BendHub (`0x096635686408886b7d907f16c4550317`, MIT-0), with `List<U32>` in place of one Char per byte, for both the C and JS targets.

`moon run wire:check` builds these natively and runs them:
- `loopback.bend`: all 256 byte values go through a connection to itself and back.
- `timeout.bend`: a poll times out, gets bytes, then sees the close.
- `stop.bend`: accepts one connection, then SIGTERM ends its loop.
- `resolve.bend`: resolves localhost, an address, and a name that does not exist.
- `tls.bend`: a client GET, wrong host and untrusted certificate against the Python TLS server.
- `tls_server.bend`: two verified Python clients use the Bend TLS server; its plain send and receive effects carry the encrypted traffic.
