import Base
import ./der.bend as D

# Explicit SHA-2 RSA/ECDSA and P-256/P-384 algorithm admission.
# This parses AlgorithmIdentifier only, not certificates, SPKI key bits or trust.
type Signature is Data:
  RsaPss256{}
  RsaV15256{}
  Ecdsa256{}
  RsaPss384{salt: U32}
  RsaPss512{salt: U32}
  RsaV15384{}
  RsaV15512{}
  Ecdsa384{}

type Key is Data:
  Rsa{}
  PssAny{}
  Pss256{minimum_salt: U32}
  P256{}
  P384{}
  Pss384{minimum_salt: U32}
  Pss512{minimum_salt: U32}

type Identifier is Data:
  Identifier{oid: List<&2, U32>, parameters: List<&2, U32>}

def identifier.oid(element: Maybe<&1, D.Element>) -> Maybe<&1, Identifier>:
  match element:
    case Some{D.Element{6, oid, rest, _}}:
      Some{Identifier{oid, rest}}
    case _:
      None{}

def identifier.body(body: Maybe<&1, List<&2, U32>>) -> Maybe<&1, Identifier>:
  match body:
    case Some{bytes}:
      identifier.oid(D.read(bytes))
    case _:
      None{}

def identifier(bytes: List<&2, U32>) -> Maybe<&1, Identifier>:
  identifier.body(D.complete(48, bytes))

def null_or_absent(parameters: List<&2, U32>) -> Bool:
  match parameters:
    case Nil{}:
      True{}
    case [5, 0]:
      True{}
    case _:
      False{}

# Classify exact OID octets before matching algorithm/parameter combinations.
# Keeping this independent avoids repeating deep list patterns in owner matches.
def oid.rsa(last: U32) -> U32:
  match last:
    case 1:
      1
    case 8:
      8
    case 10:
      10
    case 11:
      11
    case 12:
      12
    case 13:
      13
    case _:
      0

def oid.kind(bytes: List<&2, U32>) -> U32:
  match bytes:
    case [42, 134, 72, 134, 247, 13, 1, 1, last]:
      oid.rsa(last)
    case [42, 134, 72, 206, 61, 4, 3, 2]:
      20
    case [42, 134, 72, 206, 61, 4, 3, 3]:
      22
    case [42, 134, 72, 206, 61, 2, 1]:
      21
    case [96, 134, 72, 1, 101, 3, 4, 2, 1]:
      30
    case [96, 134, 72, 1, 101, 3, 4, 2, 2]:
      31
    case [96, 134, 72, 1, 101, 3, 4, 2, 3]:
      32
    case _:
      0

def hash.got(kind: U32, value: Maybe<&1, Identifier>) -> Bool:
  match value:
    case Some{Identifier{oid, parameters}}:
      Bool.and(U32.is_eq(oid.kind(oid), kind), null_or_absent(parameters))
    case _: False{}

def hash(kind: U32, bytes: List<&2, U32>) -> Bool:
  hash.got(kind, identifier(bytes))

def sha256(bytes: List<&2, U32>) -> Bool:
  hash(30, bytes)

def mgf.got(kind: U32, value: Maybe<&1, Identifier>) -> Bool:
  match value:
    case Some{Identifier{oid, parameters}}:
      Bool.and(U32.is_eq(oid.kind(oid), 8), hash(kind, parameters))
    case _: False{}

def mgf(kind: U32, bytes: List<&2, U32>) -> Bool:
  mgf.got(kind, identifier(bytes))

def mgf256(bytes: List<&2, U32>) -> Bool:
  mgf(30, bytes)

def pss.finish(+hash_kind: U32, +salt_max: U32, salt: U32, rest: List<&2, U32>) -> Maybe<&1, U32>:
  match rest:
    case Nil{}:
      Some{salt}
    # RFC 4055 requires validators to recognize explicit trailerField=1.
    case [163, 3, 2, 1, 1]:
      Some{salt}
    case _:
      None{}

def pss.salt_value(+hash_kind: U32, +salt_max: U32, valid: Bool, salt: U32, rest: List<&2, U32>) -> Maybe<&1, U32>:
  match valid:
    case False{}:
      None{}
    case True{}:
      pss.finish(hash_kind, salt_max, salt, rest)

def pss.salt_integer(+hash_kind: U32, +salt_max: U32, value: Maybe<&1, List<&2, U32>>, rest: List<&2, U32>) -> Maybe<&1, U32>:
  match value:
    case Some{[+salt]}:
      pss.salt_value(hash_kind, salt_max, Bool.and(U32.is_lt(salt, 128), U32.is_le(salt, salt_max)), salt, rest)
    case Some{[0, +salt]}:
      pss.salt_value(hash_kind, salt_max, Bool.and(U32.is_ge(salt, 128), U32.is_le(salt, salt_max)), salt, rest)
    case Some{[+high, +low]}:
      +salt = U32.add(U32.mul(high, 256), low)
      pss.salt_value(hash_kind, salt_max, Bool.and(U32.is_ge(high, 1), U32.is_le(salt, salt_max)), salt, rest)
    case _:
      None{}

def pss.salt(+hash_kind: U32, +salt_max: U32, element: Maybe<&1, D.Element>) -> Maybe<&1, U32>:
  match element:
    case Some{D.Element{162, body, rest, _}}:
      pss.salt_integer(hash_kind, salt_max, D.complete(2, body), rest)
    case Some{D.Element{163, [2, 1, 1], Nil{}, _}}:
      Some{20}
    case _:
      None{}

def pss.after_mgf(+hash_kind: U32, +salt_max: U32, valid: Bool, rest: List<&2, U32>) -> Maybe<&1, U32>:
  match valid rest:
    case False{} _:
      None{}
    case True{} Nil{}:
      Some{20}
    case True{} rest:
      pss.salt(hash_kind, salt_max, D.read(rest))

def pss.mgf(+hash_kind: U32, +salt_max: U32, element: Maybe<&1, D.Element>) -> Maybe<&1, U32>:
  match element:
    case Some{D.Element{161, body, rest, _}}:
      pss.after_mgf(hash_kind, salt_max, mgf(hash_kind, body), rest)
    case _:
      None{}

def pss.after_hash(+hash_kind: U32, +salt_max: U32, valid: Bool, rest: List<&2, U32>) -> Maybe<&1, U32>:
  match valid:
    case False{}:
      None{}
    case True{}:
      pss.mgf(hash_kind, salt_max, D.read(rest))

def pss.hash(+hash_kind: U32, +salt_max: U32, element: Maybe<&1, D.Element>) -> Maybe<&1, U32>:
  match element:
    case Some{D.Element{160, body, rest, _}}:
      pss.after_hash(hash_kind, salt_max, hash(hash_kind, body), rest)
    case _:
      None{}

def pss.body(+hash_kind: U32, +salt_max: U32, body: Maybe<&1, List<&2, U32>>) -> Maybe<&1, U32>:
  match body:
    case Some{bytes}:
      pss.hash(hash_kind, salt_max, D.read(bytes))
    case _:
      None{}

# Present parameters bind the selected SHA-2/MGF1 pair and bounded salt,
# trailer=1. Missing hash/MGF imply SHA-1 and are unsupported, not SHA-256.
def pss_for(+hash_kind: U32, +salt_max: U32, parameters: List<&2, U32>) -> Maybe<&1, U32>:
  pss.body(hash_kind, salt_max, D.complete(48, parameters))

def pss(parameters: List<&2, U32>) -> Maybe<&1, U32>:
  pss_for(30, 32, parameters)

def hash_kind.valid(valid: Bool, kind: U32) -> U32:
  match valid:
    case True{}: kind
    case False{}: 0

def hash_kind.identifier(value: Maybe<&1, Identifier>) -> U32:
  match value:
    case Some{Identifier{oid, parameters}}:
      hash_kind.valid(null_or_absent(parameters), oid.kind(oid))
    case _: 0

def pss_kind.element(value: Maybe<&1, D.Element>) -> U32:
  match value:
    case Some{D.Element{160, body, _, _}}: hash_kind.identifier(identifier(body))
    case _: 0

def pss_kind.body(value: Maybe<&1, List<&2, U32>>) -> U32:
  match value:
    case Some{body}: pss_kind.element(D.read(body))
    case _: 0

def pss_kind(parameters: List<&2, U32>) -> U32:
  pss_kind.body(D.complete(48, parameters))

def salt_limit(kind: U32) -> U32:
  match kind:
    case 30: 32
    case 31: 512
    case 32: 512
    case _: 0

def signature.pss_result(kind: U32, parameters: Maybe<&1, U32>) -> Maybe<&1, Signature>:
  match kind parameters:
    case 30 Some{32}: Some{RsaPss256{}}
    case 31 Some{salt}: Some{RsaPss384{salt}}
    case 32 Some{salt}: Some{RsaPss512{salt}}
    case _ _: None{}

def signature.pss_kind(+kind: U32, parameters: List<&2, U32>) -> Maybe<&1, Signature>:
  signature.pss_result(kind, pss_for(kind, salt_limit(kind), parameters))

def signature.pss(+parameters: List<&2, U32>) -> Maybe<&1, Signature>:
  signature.pss_kind(pss_kind(parameters), parameters)

def signature.v15(valid: Bool) -> Maybe<&1, Signature>:
  match valid:
    case True{}:
      Some{RsaV15256{}}
    case False{}:
      None{}

def signature.v15_new(valid: Bool, signature: Signature) -> Maybe<&1, Signature>:
  match valid:
    case True{}: Some{signature}
    case False{}: None{}

def signature.kind(kind: U32, parameters: List<&2, U32>) -> Maybe<&1, Signature>:
  match kind parameters:
    case 10 parameters:
      signature.pss(parameters)
    case 11 parameters:
      signature.v15(null_or_absent(parameters))
    case 12 parameters:
      signature.v15_new(null_or_absent(parameters), RsaV15384{})
    case 13 parameters:
      signature.v15_new(null_or_absent(parameters), RsaV15512{})
    case 20 Nil{}:
      Some{Ecdsa256{}}
    case 22 Nil{}:
      Some{Ecdsa384{}}
    case _ _:
      None{}

def signature.got(value: Maybe<&1, Identifier>) -> Maybe<&1, Signature>:
  match value:
    case Some{Identifier{oid, parameters}}:
      signature.kind(oid.kind(oid), parameters)
    case _:
      None{}

def signature(bytes: List<&2, U32>) -> Maybe<&1, Signature>:
  signature.got(identifier(bytes))

def key.pss_got(kind: U32, parameters: Maybe<&1, U32>) -> Maybe<&1, Key>:
  match kind parameters:
    case 30 Some{salt}: Some{Pss256{salt}}
    case 31 Some{salt}: Some{Pss384{salt}}
    case 32 Some{salt}: Some{Pss512{salt}}
    case _ _: None{}

def key.pss_kind(+kind: U32, parameters: List<&2, U32>) -> Maybe<&1, Key>:
  key.pss_got(kind, pss_for(kind, salt_limit(kind), parameters))

def key.pss(+parameters: List<&2, U32>) -> Maybe<&1, Key>:
  match parameters:
    case Nil{}: Some{PssAny{}}
    case parameters: key.pss_kind(pss_kind(parameters), parameters)

def key.rsa(parameters: List<&2, U32>) -> Maybe<&1, Key>:
  match parameters:
    case [5, 0]:
      Some{Rsa{}}
    case _:
      None{}

def key.ec(parameters: List<&2, U32>) -> Maybe<&1, Key>:
  match parameters:
    case [6, 8, 42, 134, 72, 206, 61, 3, 1, 7]:
      Some{P256{}}
    case [6, 5, 43, 129, 4, 0, 34]:
      Some{P384{}}
    case _:
      None{}

def key.kind(kind: U32, parameters: List<&2, U32>) -> Maybe<&1, Key>:
  match kind:
    case 1:
      key.rsa(parameters)
    case 10:
      key.pss(parameters)
    case 21:
      key.ec(parameters)
    case _:
      None{}

def key.got(value: Maybe<&1, Identifier>) -> Maybe<&1, Key>:
  match value:
    case Some{Identifier{oid, parameters}}:
      key.kind(oid.kind(oid), parameters)
    case _:
      None{}

def key(bytes: List<&2, U32>) -> Maybe<&1, Key>:
  key.got(identifier(bytes))

# Algorithm compatibility only. Key bits/usage, signatures and trust still need
# independent checks. PSS keys never authorize PKCS#1 v1.5 operations.
def compatible(key: Key, signature: Signature) -> Bool:
  match key signature:
    case Rsa{} RsaPss256{}:
      True{}
    case Rsa{} RsaV15256{}:
      True{}
    case PssAny{} RsaPss256{}:
      True{}
    case Pss256{minimum} RsaPss256{}:
      U32.is_le(minimum, 32)
    case P256{} Ecdsa256{}:
      True{}
    case Rsa{} RsaPss384{_}: True{}
    case Rsa{} RsaPss512{_}: True{}
    case Rsa{} RsaV15384{}: True{}
    case Rsa{} RsaV15512{}: True{}
    case PssAny{} RsaPss384{_}: True{}
    case PssAny{} RsaPss512{_}: True{}
    case Pss384{minimum} RsaPss384{salt}: U32.is_le(minimum, salt)
    case Pss512{minimum} RsaPss512{salt}: U32.is_le(minimum, salt)
    case P256{} Ecdsa384{}: True{}
    case P384{} Ecdsa384{}: True{}
    case _ _: False{}
