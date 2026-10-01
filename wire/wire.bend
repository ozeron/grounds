import Base

# Host RNG bytes, 0..1048576 inclusive. Zero does not call the host RNG.
# Failure returns no partial bytes; there is no deterministic fallback.
def wire_random_bytes(count: U32) -> IO(Result<&1, &1, U32 & String, List<&2, U32>>):
  import "./effs/random.c"
  import "./effs/random.js"

# grounds-wire: TCP on bytes. Base's TCP.send and TCP.recv decode and
# encode UTF-8, which breaks byte counts and binary protocols; these move
# bytes (0..255) as they are, one List cell each. Listening, accepting,
# connecting and closing are Base's own.
#
#   import ../wire/wire.bend as W
#
# The effects follow bend-kit-wire (BendHub 0x0966356864…, MIT-0), with
# List<U32> in place of one Char per byte.

# An effect's name is global in a program (its C id is CID_WIRE_RECV), so
# these carry the package's name. A one-line wrapper would be merged into
# the effect and take its name, so there is none.

# up to max bytes, once some arrive; [] when the peer has closed
def wire_recv(sock: Socket, max: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, List<&2, U32>>):
  import "./effs/wire.c"
  import "./effs/wire.js"

# as wire_recv, but None{} when nothing arrives within ms milliseconds
def wire_recv_timeout(sock: Socket, max: U32, ms: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, Maybe<&1, List<&2, U32>>>):
  import "./effs/wire.c"
  import "./effs/wire.js"

# every byte; a value past 255 fails with EINVAL before any is sent
def wire_send(sock: Socket, data: List<&2, U32>) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  import "./effs/wire.c"
  import "./effs/wire.js"

# as wire_send, but fails ETIMEDOUT when the peer takes nothing for ms
# milliseconds
def wire_send_timeout(sock: Socket, data: List<&2, U32>, ms: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  import "./effs/wire.c"
  import "./effs/wire.js"

def listen(port: U32) -> IO(Result<&1, &1, U32 & String, Listener>):
  TCP.listen(port)

def accept(l: Listener) -> IO(Listener & Result<&1, &1, U32 & String, Socket>):
  TCP.accept(l)

def connect(host: String, port: U32) -> IO(Result<&1, &1, U32 & String, Socket>):
  TCP.connect(host, port)

# as connect, but fails ETIMEDOUT when the connection is not made within ms
# milliseconds: an address that drops packets would wait for the OS
def wire_connect_timeout(host: String, port: U32, ms: U32) -> IO(Result<&1, &1, U32 & String, Socket>):
  import "./effs/wire.c"
  import "./effs/wire.js"

# as accept, but None{} when no connection comes within ms milliseconds
def wire_accept_timeout(l: Listener, ms: U32) -> IO(Listener & Result<&1, &1, U32 & String, Maybe<&1, Socket>>):
  import "./effs/wire.c"
  import "./effs/wire.js"

def close_listener(l: Listener) -> IO(Unit):
  Listener.close(l)

# from now on, SIGTERM and SIGINT set the stop flag instead of ending the
# process
def wire_on_stop() -> IO(Unit):
  import "./effs/wire.c"
  import "./effs/wire.js"

# 1 once SIGTERM or SIGINT came after wire_on_stop, else 0
def wire_stopping() -> IO(U32):
  import "./effs/wire.c"
  import "./effs/wire.js"

# a process-wide count: adds d (1; 4294967295 for -1; 0 to read), gives the
# new count
def wire_live(d: U32) -> IO(U32):
  import "./effs/wire.c"
  import "./effs/wire.js"

# a host name to its first IPv4 address, dotted, for connect; "localhost"
# gives "127.0.0.1", and an address comes back as it is
def wire_resolve(host: String) -> IO(Result<&1, &1, U32 & String, String>):
  import "./effs/wire.c"
  import "./effs/wire.js"

# TLS on a connected socket (OpenSSL 3, loaded at run time; BEND_LIBSSL
# overrides its path). The handshake sends host as SNI and checks the
# chain and host name; GROUNDS_TLS_CA names a PEM file to trust as well.
# The client socket then uses wire_tls_* until wire_tls_close
def wire_tls_connect(sock: Socket, host: String, ms: U32) -> IO(Socket & Result<&1, &1, U32 & String, Unit>):
  import "./effs/wire.c"
  import "./effs/wire.js"

def wire_tls_send_timeout(sock: Socket, data: List<&2, U32>, ms: U32) -> IO(Socket & Result<&1, &1, U32 & String, Unit>):
  import "./effs/wire.c"
  import "./effs/wire.js"

# Some{bytes}; Some{[]} once the peer sends close_notify; None{} past ms. A
# bare EOF fails ECONNRESET: a body read to the close could have been cut
def wire_tls_recv_timeout(sock: Socket, max: U32, ms: U32) -> IO(Socket & Result<&1, &1, U32 & String, Maybe<&1, List<&2, U32>>>):
  import "./effs/wire.c"
  import "./effs/wire.js"

# sends close_notify, frees the session and closes the socket
def wire_tls_close(sock: Socket) -> IO(Unit):
  import "./effs/wire.c"
  import "./effs/wire.js"

# the server side: the certificate chain and private key (PEM files) every
# wire_tls_accept then uses, loaded and matched now. TLS 1.2 is the floor,
# with no compression, renegotiation or 0-RTT; ALPN is http/1.1 only
def wire_tls_listen_ctx(cert: String, key: String) -> IO(Result<&1, &1, U32 & String, Unit>):
  import "./effs/wire.c"
  import "./effs/wire.js"

# the server's handshake on an accepted socket, within ms. After it, the
# socket's bytes go through TLS, by the plain wire_send_timeout and
# wire_recv_timeout too, until wire_close
def wire_tls_accept(sock: Socket, ms: U32) -> IO(Socket & Result<&1, &1, U32 & String, Unit>):
  import "./effs/wire.c"
  import "./effs/wire.js"

# closes a socket, ending its TLS session first if it has one
def wire_close(sock: Socket) -> IO(Unit):
  import "./effs/wire.c"
  import "./effs/wire.js"

def close(sock: Socket) -> IO(Unit):
  Socket.close(sock)

# IPv4 literal and port 0..65535; 0 lets the OS assign an ephemeral port.
# No DNS, address reuse or fallback to a wildcard bind. Socket.close owns cleanup.
def wire_udp_bind(host: String, port: U32) -> IO(Result<&1, &1, U32 & String, Socket>):
  import "./effs/wire.c"
  import "./effs/wire.js"

# Returns the bound IPv4 address/port, preserving socket ownership on failure.
# A wildcard socket reports 0.0.0.0, not the destination IP of a received packet.
def wire_udp_local_address(sock: Socket) -> IO(Socket & Result<&1, &1, U32 & String, String & U32>):
  import "./effs/wire.c"
  import "./effs/wire.js"

# Binary UDP for datagram protocols. UDP.bind and Socket.close come from Base;
# Base's UDP.send_to/recv_from use String and cannot preserve arbitrary bytes.
# Sending is atomic. Invalid octets fail EINVAL before the datagram is sent.
def wire_udp_send_to(sock: Socket, host: String, port: U32, data: List<&2, U32>, ms: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  import "./effs/wire.c"
  import "./effs/wire.js"

# None{} means timeout; Some{(host, (port, bytes))} includes an empty datagram.
# A datagram larger than max is consumed and fails EMSGSIZE (no truncation).
def wire_udp_recv_from_timeout(sock: Socket, max: U32, ms: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, Maybe<&1, String & U32 & List<&2, U32>>>):
  import "./effs/wire.c"
  import "./effs/wire.js"
