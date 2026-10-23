import Base
import ./pem.bend as P

def canonical_zero_octet() -> {P.base64([65, 65, 61, 61], []) == Some{[0]} : Maybe<&1, List<&2, U32>>}:
  {==}

def rejects_padding_alias() -> {P.base64([65, 66, 61, 61], []) == None{} : Maybe<&1, List<&2, U32>>}:
  {==}

def rejects_padding_followed_by_data() -> {P.base64([65, 65, 61, 61, 65, 65, 65, 65], []) == None{} : Maybe<&1, List<&2, U32>>}:
  {==}

def rejects_nonbyte() -> {P.decode([256]) == Fail{P.Malformed{}} : Result<&2, &1, P.Error, P.Block>}:
  {==}
