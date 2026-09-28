import Base
import ../stun_sign.bend as Sign
import ../stun_integrity.bend as Integrity
import ../stun_fingerprint.bend as Fingerprint
import ../sign_test.bend as Test
import ../integrity_test.bend as Vector
import ../stun.bend as Stun

def results(equal: Bool, integrity: Bool, fingerprint: Bool) -> IO(Unit):
  match equal integrity fingerprint:
    case True{} True{} True{}:
      IO.print("STUN: Bend signed RFC 5769 request matches bytes, HMAC, and CRC")
    case _ _ _:
      IO.die(Unit, 1, "STUN signed request mismatch")

def checked(signed: Maybe<&2, List<&2, U32>>) -> IO(Unit):
  match signed:
    case Some{+bytes}:
      results(Stun.same(bytes, Vector.request(), True{}),
        Integrity.verify(bytes, Vector.key()), Fingerprint.verify(bytes))
    case None{}:
      IO.die(Unit, 1, "STUN request signing failed")

def main() -> IO(Unit):
  checked(Sign.sign(Test.unsigned(), Vector.key()))
