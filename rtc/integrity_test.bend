import Base
import ./stun_integrity.bend as Integrity
import ./test.bend as StunTest
import ../utf8/utf8.bend as U

# RFC 5769 section 2.1, including MESSAGE-INTEGRITY and FINGERPRINT.
def request() -> List<&2, U32>:
  [0, 1, 0, 88, 33, 18, 164, 66, 183, 231, 167, 1, 188, 52, 214, 134,
   250, 135, 223, 174, 128, 34, 0, 16, 83, 84, 85, 78, 32, 116, 101, 115,
   116, 32, 99, 108, 105, 101, 110, 116, 0, 36, 0, 4, 110, 0, 1, 255,
   128, 41, 0, 8, 147, 47, 249, 177, 81, 38, 59, 54, 0, 6, 0, 9,
   101, 118, 116, 106, 58, 104, 54, 118, 89, 32, 32, 32, 0, 8, 0, 20,
   154, 234, 167, 12, 191, 216, 203, 86, 120, 30, 242, 181, 178, 211, 242, 73,
   193, 181, 113, 162, 128, 40, 0, 4, 229, 122, 59, 207]

def key() -> List<&2, U32>:
  U.encode("VOkJxbRl1RmTxUk/WvJxBt")

def alter(xs: List<&2, U32>, at: Nat, +new: U32) -> List<&2, U32>:
  match xs:
    case Nil{}:
      []
    case Con{byte, tail}:
      match at:
        case 0n:
          Con{new, tail}
        case 1n+p:
          Con{byte, alter(tail, p, new)}

def rfc_integrity() -> {Integrity.verify(request(), key()) == True{} : Bool}:
  {==}

def rfc_response_integrity() -> {Integrity.verify(StunTest.rfc_ipv4(), key()) == True{} : Bool}:
  {==}

def changed_content_fails() -> {Integrity.verify(alter(request(), 30n, 0), key()) == False{} : Bool}:
  {==}

def changed_mac_fails() -> {Integrity.verify(alter(request(), 80n, 0), key()) == False{} : Bool}:
  {==}

def wrong_key_fails() -> {Integrity.verify(request(), U.encode("wrong password")) == False{} : Bool}:
  {==}

def sha256_attribute_cannot_downgrade() -> {Integrity.verify(alter(request(), 77n, 28), key()) == False{} : Bool}:
  {==}

def fingerprint_is_outside_mac() -> {Integrity.verify(alter(request(), 107n, 0), key()) == True{} : Bool}:
  {==}
