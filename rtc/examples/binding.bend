import Base
import ../stun_client.bend as Client
import ../stun.bend as Stun

def show(reply: Maybe<&2, Stun.IPv4>) -> IO(Unit):
  match reply:
    case Some{Stun.IPv4{+a, +b, +c, +d, +port}}:
      IO.print(U32.show(a) ++ "." ++ U32.show(b) ++ "." ++ U32.show(c) ++ "." ++ U32.show(d) ++ ":" ++ U32.show(port))
    case None{}:
      IO.die(Unit, 1, "STUN Binding response missing or invalid")

def main() -> IO(Unit):
  do IO<Unit>:
    reply : Maybe<&2, Stun.IPv4> <- Client.request("127.0.0.1", 47835, 1000)
    show(reply)
