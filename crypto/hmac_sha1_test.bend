import Base
import ./hmac_sha1.bend as Hmac

def rejects_bad_key() -> {Hmac.digest([256], [1, 2, 3]) == None{} : Maybe<&2, List<&2, U32>>}:
  {==}

def rejects_bad_message() -> {Hmac.digest([1, 2, 3], [0, 255, 256]) == None{} : Maybe<&2, List<&2, U32>>}:
  {==}
