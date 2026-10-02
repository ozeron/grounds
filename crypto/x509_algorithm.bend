import Base
import ./der.bend as D

# SHA-256 signature / P-256 key algorithm admission for the Bend TLS path.
# This parses AlgorithmIdentifier only, not certificates, SPKI key bits or trust.
type Signature is Data:
  RsaPss256{}
  RsaV15256{}
  Ecdsa256{}

type Key is Data:
  Rsa{}
  PssAny{}
  Pss256{minimum_salt: U32}
  P256{}

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
    case _:
      0

def oid.kind(bytes: List<&2, U32>) -> U32:
  match bytes:
    case [42, 134, 72, 134, 247, 13, 1, 1, last]:
      oid.rsa(last)
    case [42, 134, 72, 206, 61, 4, 3, 2]:
      20
    case [42, 134, 72, 206, 61, 2, 1]:
      21
    case [96, 134, 72, 1, 101, 3, 4, 2, 1]:
      30
    case _:
      0

def sha256.got(value: Maybe<&1, Identifier>) -> Bool:
  match value:
    case Some{Identifier{oid, parameters}}:
      Bool.and(U32.is_eq(oid.kind(oid), 30), null_or_absent(parameters))
    case _:
      False{}

def sha256(bytes: List<&2, U32>) -> Bool:
  sha256.got(identifier(bytes))

def mgf256.got(value: Maybe<&1, Identifier>) -> Bool:
  match value:
    case Some{Identifier{oid, parameters}}:
      Bool.and(U32.is_eq(oid.kind(oid), 8), sha256(parameters))
    case _:
      False{}

def mgf256(bytes: List<&2, U32>) -> Bool:
  mgf256.got(identifier(bytes))

def pss.finish(salt: U32, rest: List<&2, U32>) -> Maybe<&1, U32>:
  match rest:
    case Nil{}:
      Some{salt}
    # RFC 4055 requires validators to recognize explicit trailerField=1.
    case [163, 3, 2, 1, 1]:
      Some{salt}
    case _:
      None{}

def pss.salt_value(valid: Bool, salt: U32, rest: List<&2, U32>) -> Maybe<&1, U32>:
  match valid:
    case False{}:
      None{}
    case True{}:
      pss.finish(salt, rest)

def pss.salt_integer(value: Maybe<&1, List<&2, U32>>, rest: List<&2, U32>) -> Maybe<&1, U32>:
  match value:
    case Some{[+salt]}:
      pss.salt_value(U32.is_le(salt, 32), salt, rest)
    case _:
      None{}

def pss.salt(element: Maybe<&1, D.Element>) -> Maybe<&1, U32>:
  match element:
    case Some{D.Element{162, body, rest, _}}:
      pss.salt_integer(D.complete(2, body), rest)
    case Some{D.Element{163, [2, 1, 1], Nil{}, _}}:
      Some{20}
    case _:
      None{}

def pss.after_mgf(valid: Bool, rest: List<&2, U32>) -> Maybe<&1, U32>:
  match valid rest:
    case False{} _:
      None{}
    case True{} Nil{}:
      Some{20}
    case True{} rest:
      pss.salt(D.read(rest))

def pss.mgf(element: Maybe<&1, D.Element>) -> Maybe<&1, U32>:
  match element:
    case Some{D.Element{161, body, rest, _}}:
      pss.after_mgf(mgf256(body), rest)
    case _:
      None{}

def pss.after_hash(valid: Bool, rest: List<&2, U32>) -> Maybe<&1, U32>:
  match valid:
    case False{}:
      None{}
    case True{}:
      pss.mgf(D.read(rest))

def pss.hash(element: Maybe<&1, D.Element>) -> Maybe<&1, U32>:
  match element:
    case Some{D.Element{160, body, rest, _}}:
      pss.after_hash(sha256(body), rest)
    case _:
      None{}

def pss.body(body: Maybe<&1, List<&2, U32>>) -> Maybe<&1, U32>:
  match body:
    case Some{bytes}:
      pss.hash(D.read(bytes))
    case _:
      None{}

# Present parameters bind SHA-256/MGF1-SHA-256, minimum/exact salt <=32,
# trailer=1. Missing hash/MGF imply SHA-1 and are unsupported, not SHA-256.
def pss(parameters: List<&2, U32>) -> Maybe<&1, U32>:
  pss.body(D.complete(48, parameters))

def signature.pss(parameters: Maybe<&1, U32>) -> Maybe<&1, Signature>:
  match parameters:
    case Some{32}:
      Some{RsaPss256{}}
    case _:
      None{}

def signature.v15(valid: Bool) -> Maybe<&1, Signature>:
  match valid:
    case True{}:
      Some{RsaV15256{}}
    case False{}:
      None{}

def signature.kind(kind: U32, parameters: List<&2, U32>) -> Maybe<&1, Signature>:
  match kind parameters:
    case 10 parameters:
      signature.pss(pss(parameters))
    case 11 parameters:
      signature.v15(null_or_absent(parameters))
    case 20 Nil{}:
      Some{Ecdsa256{}}
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

def key.pss_got(parameters: Maybe<&1, U32>) -> Maybe<&1, Key>:
  match parameters:
    case Some{salt}:
      Some{Pss256{salt}}
    case _:
      None{}

def key.pss(parameters: List<&2, U32>) -> Maybe<&1, Key>:
  match parameters:
    case Nil{}:
      Some{PssAny{}}
    case parameters:
      key.pss_got(pss(parameters))

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
    case _ _:
      False{}
