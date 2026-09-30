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
| `W.wire_udp_bind(host, port)` | binds one IPv4 literal; port `0` requests an ephemeral port; failures close any newly allocated socket |
| `W.wire_udp_local_address(sock)` | returns `(host, port)` from the OS, preserving socket ownership; wildcard sockets report `0.0.0.0` |
| `W.wire_udp_send_to(sock, host, port, bytes, ms)` | sends one binary UDP datagram or fails; invalid bytes fail `EINVAL` before send |
| `W.wire_udp_recv_from_timeout(sock, max, ms)` | `Some{(host, (port, bytes))}` on a datagram, including empty bytes; `None{}` on timeout; oversized datagrams fail `EMSGSIZE` after consumption |
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
- For UDP, use `wire_udp_bind(host, port)` when local address identity matters, and query `wire_udp_local_address` before advertising a port assigned by the OS. It accepts canonical IPv4 literals and ports 0–65535, without DNS, address reuse options or fallback binding. Errors retain OS errno; an invalid literal/port returns `EINVAL`. Failed bind/nonblocking setup closes the newly allocated socket. Close successful sockets with `Socket.close(sock)`. Base's existing `UDP.bind(port)` remains available for wildcard binding. UDP transport remains IPv4; IPv6 is still pending. The receive limit is checked against the full datagram; the largest supported receive buffer is 65535 bytes.
- An explicitly bound unicast IP identifies the receiving local address for an unconnected UDP socket. A wildcard socket's `getsockname` result is `0.0.0.0`; it does not identify a received packet's destination IP. The new effects call OS `bind`/`getsockname` and keep protocol logic in Bend. Bun loads only `getsockname` from the system library because Base's syscall table lacks it. See Apple's [bind](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/bind.2.html) and [getsockname](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/getsockname.2.html) references.

`moon run wire:check` builds these natively and runs them:
- `loopback.bend`: all 256 byte values go through a connection to itself and back.
- `timeout.bend`: a poll times out, gets bytes, then sees the close.
- `udp.bend`: native and, when Bun is available, JS binary datagrams, including all 256 octets, zero-byte datagrams, timeout, oversize and invalid input.
- `udp_address.bend` with the independent Python peer: 22 cases per native/Bun target covering literal/NUL/port rejection, ephemeral/wildcard reporting, all octets and empty datagrams, two local IPs sharing a port, wrong-destination isolation, errno, 1,500 failed binds with exactly one retained UDP descriptor, and released-port rebinding. The fixture uses a second bindable local IPv4 address selected by the independent OS helper; Linux may supply another loopback IP, while this Mac uses its existing local interface. No interface configuration is changed. These checks run on Darwin arm64; Linux branches are implemented but not verified on this host.
- `stop.bend`: accepts one connection, then SIGTERM ends its loop.
- `resolve.bend`: resolves localhost, an address, and a name that does not exist.
- `tls.bend`: a client GET, wrong host and untrusted certificate against the Python TLS server.
- `tls_server.bend`: two verified Python clients use the Bend TLS server; its plain send and receive effects carry the encrypted traffic.
