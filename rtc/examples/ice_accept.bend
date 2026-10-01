import Base
import ./ice_accept_output.bend as Shared
import ../ice_incoming.bend as Incoming
import ../ice_binding.bend as Ice
import ../stun_auth.bend as Auth
import ../stun.bend as Stun
import ../ice_candidates.bend as C
import ../../io/io.bend as Io
import ../../crypto/bytes.bend as B

def flag(value: Bool) -> String:
  Shared.flag(value)

def role(value: Ice.Role) -> String:
  Shared.role(value)

def mode(value: Auth.Mode) -> String:
  Shared.mode(value)

def show(decision: Incoming.Decision) -> IO(Unit):
  match decision:
    case Incoming.Accepted{reply, Incoming.Request{_, remote, priority, peer, nominate, algorithm}, local, switched}:
      do IO<Unit>:
        x : Unit <- IO.print("accept:" ++ remote ++ ":" ++ U32.show(priority) ++ ":" ++ role(peer) ++ ":" ++ flag(nominate) ++ ":" ++ mode(algorithm) ++ ":" ++ role(local) ++ ":" ++ flag(switched))
        IO.print(B.hex(reply))
    case Incoming.Rejected{reply, code, authenticated}:
      do IO<Unit>:
        x : Unit <- IO.print("reject:" ++ U32.show(code) ++ ":" ++ flag(authenticated))
        IO.print(B.hex(reply))
    case Incoming.Ignored{}: IO.print("ignore")
    case Incoming.InvalidInput{}: IO.print("invalid")

def configured(local: Ice.Role, secret: Incoming.Secret, source: Stun.IPv4, path: String) -> IO(Unit):
  do IO<Unit>:
    bytes : List<&2, U32> <- Io.read_bytes(path)
    show(Incoming.receive(bytes, secret, local, source))

def with_role(name: String, high: U32, low: U32, secret: Incoming.Secret, source: Stun.IPv4, path: String) -> IO(Unit):
  match name:
    case "controlling": configured(Ice.Controlling{high, low}, secret, source, path)
    case "controlled": configured(Ice.Controlled{high, low}, secret, source, path)
    case _: IO.die(Unit, 2, "unknown role")

def numbers(high: Maybe<&2, U32>, low: Maybe<&2, U32>, a: Maybe<&2, U32>, b: Maybe<&2, U32>,
            c: Maybe<&2, U32>, d: Maybe<&2, U32>, p: Maybe<&2, U32>,
            name: String, secret: Incoming.Secret, path: String) -> IO(Unit):
  match high low a b c d p:
    case Some{h} Some{l} Some{a} Some{b} Some{c} Some{d} Some{p}:
      with_role(name, h, l, secret, Stun.IPv4{a, b, c, d, p}, path)
    case _ _ _ _ _ _ _: IO.die(Unit, 2, "invalid fixture number")

def show_address(address: Maybe<&2, Stun.IPv4>) -> IO(Unit):
  match address:
    case None{}: IO.print("invalid")
    case Some{+a}: IO.print(C.host(a) ++ "/" ++ U32.show(C.port(a)))

def read_address(port: Maybe<&2, U32>, host: String) -> IO(Unit):
  match port:
    case None{}: IO.print("invalid")
    case Some{p}: show_address(C.address_read(host, p))

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case ["address", host, port]: read_address(U32.read(port), host)
    case [ufrag, password, name, high, low, a, b, c, d, port, path]:
      numbers(U32.read(high), U32.read(low), U32.read(a), U32.read(b), U32.read(c), U32.read(d), U32.read(port),
        name, Incoming.Secret{ufrag, password}, path)
    case _: IO.die(Unit, 2, "usage: ice_accept <ufrag> <password> <role> <high> <low> <a> <b> <c> <d> <port> <file>")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
