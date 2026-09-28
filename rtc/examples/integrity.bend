import Base
import ../stun_integrity.bend as Integrity
import ../integrity_test.bend as Test
import ../test.bend as StunTest

def checked(request: Bool, response: Bool, changed: Bool) -> IO(Unit):
  match request response changed:
    case True{} True{} False{}:
      IO.print("STUN: RFC 5769 request and response MESSAGE-INTEGRITY verified; tampering rejected")
    case _ _ _:
      IO.die(Unit, 1, "STUN MESSAGE-INTEGRITY mismatch")

def main() -> IO(Unit):
  checked(Integrity.verify(Test.request(), Test.key()),
    Integrity.verify(StunTest.rfc_ipv4(), Test.key()),
    Integrity.verify(Test.alter(Test.request(), 80n, 0), Test.key()))
