import Base
import ../stun_fingerprint.bend as Fingerprint
import ../integrity_test.bend as Test
import ../test.bend as StunTest

def checked(request: Bool, response: Bool, changed: Bool) -> IO(Unit):
  match request response changed:
    case True{} True{} False{}:
      IO.print("STUN: RFC 5769 request and response FINGERPRINT verified; tampering rejected")
    case _ _ _:
      IO.die(Unit, 1, "STUN FINGERPRINT mismatch")

def main() -> IO(Unit):
  checked(Fingerprint.verify(Test.request()), Fingerprint.verify(StunTest.rfc_ipv4()),
    Fingerprint.verify(Test.alter(Test.request(), 107n, 0)))
