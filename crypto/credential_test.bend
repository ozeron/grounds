import Base
import ./credential.bend as C
import ./private_key.bend as K

def rejects_malformed_leaf() -> {C.from_key([48, 0], K.P256{[], []}) == None{} : Maybe<&1, C.Credential>}:
  {==}
