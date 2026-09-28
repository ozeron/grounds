import Base
import ../stun.bend as Stun
import ../../crypto/bytes.bend as B

def attributes(left: Nat, acc: List<&2, U32>) -> List<&2, U32>:
  match left:
    case 0n:
      acc
    case 1n+p:
      attributes(p, Con{0, Con{1, Con{0, Con{0, acc}}}})

def report(result: Maybe<&2, Stun.Packet>) -> IO(Unit):
  match result:
    case Some{_}:
      IO.print("STUN: maximum 65532-byte attribute section parsed")
    case None{}:
      IO.die(Unit, 1, "STUN maximum-size packet rejected")

def main() -> IO(Unit):
  report(Stun.parse(B.append([0, 1, 255, 252, 33, 18, 164, 66,
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12], attributes(16383n, []))))
