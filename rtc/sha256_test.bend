import Base
import ./stun_auth.bend as Auth
import ./stun.bend as Stun
import ./stun_integrity.bend as Legacy
import ./integrity_test.bend as Test
import ./sign_test.bend as SignTest

# RFC 8489 Appendix B.1 corrected by verified erratum 6268.
# Prepared SHA-256 long-term credential key; no key derivation in RTC.
def request() -> List<&2, U32>:
  [0, 1, 0, 144, 33, 18, 164, 66, 120, 173, 52, 51, 198, 173, 114, 192,
   41, 218, 65, 46, 0, 30, 0, 32, 74, 60, 243, 143, 239, 105, 146, 189,
   169, 82, 198, 120, 4, 23, 218, 15, 36, 129, 148, 21, 86, 158, 96, 178,
   5, 196, 110, 65, 64, 127, 23, 4, 0, 21, 0, 41, 111, 98, 77, 97,
   116, 74, 111, 115, 50, 65, 65, 65, 67, 102, 47, 47, 52, 57, 57, 107,
   57, 53, 52, 100, 54, 79, 76, 51, 52, 111, 76, 57, 70, 83, 84, 118,
   121, 54, 52, 115, 65, 0, 0, 0, 0, 20, 0, 11, 101, 120, 97, 109,
   112, 108, 101, 46, 111, 114, 103, 0, 0, 29, 0, 4, 0, 2, 0, 0,
   0, 28, 0, 32, 181, 199, 191, 0, 91, 108, 82, 162, 28, 81, 197, 232,
   146, 248, 25, 36, 19, 98, 150, 203, 146, 124, 67, 20, 147, 9, 39, 140,
   198, 81, 142, 101]

def key() -> List<&2, U32>:
  [221, 41, 90, 97, 59, 144, 88, 195, 194, 61, 109, 199, 22, 91, 218, 7,
   35, 4, 217, 137, 201, 208, 175, 58, 140, 126, 24, 75, 79, 155, 180, 161]

def rfc_sha256() -> {Auth.verify(request(), key(), Auth.Sha256{}) == True{} : Bool}:
  {==}

def unsigned_taken(t: Stun.Taken) -> List<&2, U32>:
  match t:
    case Stun.Took{front, _}:
      Legacy.adjusted(front, 108n)
    case Stun.Short{}:
      []

def unsigned() -> List<&2, U32>:
  unsigned_taken(Stun.take(request(), 128n, []))

def rfc_signing() -> {Auth.seal(unsigned(), key(), Auth.Sha256{}) ==
  Some{request()} : Maybe<&2, List<&2, U32>>}:
  {==}

def legacy_compatibility() -> {Auth.sign(SignTest.unsigned(), Test.key(), Auth.Legacy{}) ==
  Some{Test.request()} : Maybe<&2, List<&2, U32>>}:
  {==}

def rejects_bad_key_byte() -> {Auth.seal(unsigned(), [256], Auth.Sha256{}) ==
  None{} : Maybe<&2, List<&2, U32>>}:
  {==}

def rejects_bad_verification_key_byte() -> {Auth.verify(request(), [256], Auth.Sha256{}) == False{} : Bool}:
  {==}

def rejects_bad_packet_byte() -> {Auth.verify(Test.alter(request(), 8n, 256), key(), Auth.Sha256{}) == False{} : Bool}:
  {==}

def rejects_old_rfc_length() -> {Auth.verify(Test.alter(request(), 3n, 156), key(), Auth.Sha256{}) == False{} : Bool}:
  {==}

def rejects_truncated_integrity() -> {Auth.verify(Test.alter(request(), 131n, 16), key(), Auth.Sha256{}) == False{} : Bool}:
  {==}
