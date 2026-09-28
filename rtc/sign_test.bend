import Base
import ./stun_sign.bend as Sign
import ./stun_integrity.bend as Integrity
import ./stun.bend as Stun
import ./integrity_test.bend as Test
import ../crypto/bytes.bend as B

def unsigned.taken(t: Stun.Taken) -> List<&2, U32>:
  match t:
    case Stun.Took{front, _}:
      Integrity.adjusted(front, 56n)
    case Stun.Short{}:
      []

def unsigned() -> List<&2, U32>:
  unsigned.taken(Stun.take(Test.request(), 76n, []))

def matches_rfc_request() -> {Sign.sign(unsigned(), Test.key()) ==
  Some{Test.request()} : Maybe<&2, List<&2, U32>>}:
  {==}

def rejects_already_signed() -> {Sign.sign(Test.request(), Test.key()) ==
  None{} : Maybe<&2, List<&2, U32>>}:
  {==}

def rejects_bad_key() -> {Sign.sign(unsigned(), [256]) ==
  None{} : Maybe<&2, List<&2, U32>>}:
  {==}

def rejects_malformed_input() -> {Sign.sign(B.append(unsigned(), [0]), Test.key()) ==
  None{} : Maybe<&2, List<&2, U32>>}:
  {==}
