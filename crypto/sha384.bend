import Base
import ./sha512.bend as S
import ./bytes.bend as B

# SHA-384 uses its own IV, then truncates SHA-512 compression to 384 bits.
def truncate(value: Maybe<&2, List<&2, U32>>) -> Maybe<&2, List<&2, U32>>:
  match value:
    case None{}: None{}
    case Some{bytes}: Some{List.take(&2, U32, bytes, 48n)}

def valid(bytes: List<&2, U32>) -> Bool:
  B.valid(bytes)

def hex(bytes: List<&2, U32>) -> String:
  B.hex(bytes)

def digest(+bytes: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  truncate(S.digest.checked(B.valid(bytes), S.initial384(), bytes))

def digest_hex(bytes: List<&2, U32>) -> Maybe<&2, String>:
  S.digest_hex.got(digest(bytes))
