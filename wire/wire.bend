import Base

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

def close(sock: Socket) -> IO(Unit):
  Socket.close(sock)
