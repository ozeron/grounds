import Base
import ./bytes.bend as B
import ./der.bend as D
import ./pem.bend as M
import ./p256.bend as P
import ./rsa_private.bend as R
import ./x509_public_key.bend as K
import ./x509_algorithm.bend as A
import ./rsa_encoding.bend as E

# Affine owner: callers must explicitly consume the imported key. Input byte
# lists are duplicable representations; this is not a physical-erasure promise.
type Private is Type:
  P256{scalar: List<&2, U32>, public: List<&2, U32>}
  Rsa{private: R.Private}

type Field is Type:
  Field{tag: U32, body: List<&2, U32>}

def same(a: List<&2, U32>, b: List<&2, U32>) -> Bool:
  E.equal(a, b)

def checked(valid: Bool, key: Private) -> Maybe<&1, Private>:
  match valid:
    case True{}:
      Some{key}
    case False{}:
      None{}

def ec.derived(scalar: List<&2, U32>, expected: Maybe<&2, List<&2, U32>>, result: Maybe<&1, List<&2, U32>>) -> Maybe<&1, Private>:
  match expected result:
    case Some{expected} Some{+public}:
      checked(same(public, expected), P256{scalar, public})
    case None{} Some{public}:
      Some{P256{scalar, public}}
    case _ _:
      None{}

def ec.scalar(+scalar: List<&2, U32>, expected: Maybe<&2, List<&2, U32>>) -> Maybe<&1, Private>:
  ec.derived(scalar, expected, P.public_key(scalar))

def ec.public.bits(scalar: List<&2, U32>, bits: Maybe<&1, List<&2, U32>>) -> Maybe<&1, Private>:
  match bits:
    case Some{Con{0, public}}:
      ec.scalar(scalar, Some{public})
    case _:
      None{}

def ec.public.element(scalar: List<&2, U32>, body: Maybe<&1, List<&2, U32>>) -> Maybe<&1, Private>:
  match body:
    case Some{bytes}:
      ec.public.bits(scalar, D.complete(3, bytes))
    case _:
      None{}

def ec.public(scalar: List<&2, U32>, rest: List<&2, U32>) -> Maybe<&1, Private>:
  match rest:
    case Nil{}:
      ec.scalar(scalar, None{})
    case rest:
      ec.public.element(scalar, D.complete(161, rest))

def ec.curve(scalar: List<&2, U32>, element: Maybe<&1, D.Element>) -> Maybe<&1, Private>:
  match element:
    case Some{D.Element{160, [6, 8, 42, 134, 72, 206, 61, 3, 1, 7], rest, _}}:
      ec.public(scalar, rest)
    case _:
      None{}

def ec.inherited(inherited: Bool, scalar: List<&2, U32>, rest: List<&2, U32>) -> Maybe<&1, Private>:
  match inherited:
    case True{}:
      ec.public(scalar, rest)
    case False{}:
      None{}

def ec.options(inherited: Bool, scalar: List<&2, U32>, rest: List<&2, U32>) -> Maybe<&1, Private>:
  match rest:
    case Con{160, tail}:
      ec.curve(scalar, D.read(Con{160, tail}))
    case rest:
      ec.inherited(inherited, scalar, rest)

def ec.octet(inherited: Bool, element: Maybe<&1, D.Element>) -> Maybe<&1, Private>:
  match element:
    case Some{D.Element{4, scalar, rest, _}}:
      ec.options(inherited, scalar, rest)
    case _:
      None{}

def ec.body(inherited: Bool, body: Maybe<&1, List<&2, U32>>) -> Maybe<&1, Private>:
  match body:
    case Some{Con{2, Con{1, Con{1, rest}}}}:
      ec.octet(inherited, D.read(rest))
    case _:
      None{}

# SEC1 standalone keys must carry namedCurve secp256r1. In PKCS#8 the outer
# exact AlgorithmIdentifier supplies it; any inner parameters must agree.
def sec1(inherited: Bool, bytes: List<&2, U32>) -> Maybe<&1, Private>:
  ec.body(inherited, D.complete(48, bytes))

def rsa.validated(result: Maybe<&1, R.Private>) -> Maybe<&1, Private>:
  match result:
    case Some{private}:
      Some{Rsa{private}}
    case None{}:
      None{}

def rsa.normalized(n: Maybe<&1, List<&2, U32>>, e: Maybe<&1, List<&2, U32>>, d: Maybe<&1, List<&2, U32>>, p: Maybe<&1, List<&2, U32>>, q: Maybe<&1, List<&2, U32>>, dp: Maybe<&1, List<&2, U32>>, dq: Maybe<&1, List<&2, U32>>, qi: Maybe<&1, List<&2, U32>>) -> Maybe<&1, Private>:
  match n e d p q dp dq qi:
    case Some{n} Some{e} Some{d} Some{p} Some{q} Some{dp} Some{dq} Some{qi}:
      rsa.validated(R.validate(R.Private{n, e, d, p, q, dp, dq, qi}))
    case _ _ _ _ _ _ _ _:
      None{}

def rsa.fields(fields: List<&1, Field>, rest: List<&2, U32>) -> Maybe<&1, Private>:
  match fields rest:
    case Con{Field{2, qi}, Con{Field{2, dq}, Con{Field{2, dp}, Con{Field{2, q}, Con{Field{2, p}, Con{Field{2, d}, Con{Field{2, e}, Con{Field{2, n}, Nil{}}}}}}}}} Nil{}:
      rsa.normalized(K.positive(n), K.positive(e), K.positive(d), K.positive(p), K.positive(q), K.positive(dp), K.positive(dq), K.positive(qi))
    case _ _:
      None{}

def rsa.walk.element(fields: List<&1, Field>, element: Maybe<&1, D.Element>, next: List<&1, Field> -> List<&2, U32> -> Maybe<&1, Private>) -> Maybe<&1, Private>:
  match element:
    case Some{D.Element{tag, body, rest, _}}:
      next(Con{Field{tag, body}, fields}, rest)
    case _:
      None{}

def rsa.walk(left: Nat, fields: List<&1, Field>, bytes: List<&2, U32>) -> Maybe<&1, Private>:
  match left:
    case 0n:
      rsa.fields(fields, bytes)
    case 1n+p:
      rsa.walk.element(fields, D.read(bytes), f => b => rsa.walk(p, f, b))

def rsa.body(body: Maybe<&1, List<&2, U32>>) -> Maybe<&1, Private>:
  match body:
    case Some{Con{2, Con{1, Con{0, rest}}}}:
      rsa.walk(8n, [], rest)
    case _:
      None{}

# PKCS#1 version zero only. Multi-prime RSA is explicitly outside the profile.
def pkcs1(bytes: List<&2, U32>) -> Maybe<&1, Private>:
  rsa.body(D.complete(48, bytes))

def pkcs8.key(algorithm: Maybe<&1, A.Key>, value: Maybe<&1, List<&2, U32>>) -> Maybe<&1, Private>:
  match algorithm value:
    case Some{A.P256{}} Some{bytes}:
      sec1(True{}, bytes)
    case Some{A.Rsa{}} Some{bytes}:
      pkcs1(bytes)
    case _ _:
      None{}

def pkcs8.algorithm(element: Maybe<&1, D.Element>) -> Maybe<&1, Private>:
  match element:
    case Some{D.Element{48, _, rest, encoded}}:
      pkcs8.key(A.key(encoded), D.complete(4, rest))
    case _:
      None{}

def pkcs8.body(body: Maybe<&1, List<&2, U32>>) -> Maybe<&1, Private>:
  match body:
    case Some{Con{2, Con{1, Con{0, rest}}}}:
      pkcs8.algorithm(D.read(rest))
    case _:
      None{}

# RFC 5208 PrivateKeyInfo version zero, with no attributes or trailing fields.
# EncryptedPrivateKeyInfo is rejected; callers get the explicit Encrypted
# error for the corresponding PEM label or legacy Proc-Type header.
def pkcs8(bytes: List<&2, U32>) -> Maybe<&1, Private>:
  pkcs8.body(D.complete(48, bytes))

def from_block(block: M.Block) -> Maybe<&1, Private>:
  match block:
    case M.Block{M.Pkcs8{}, bytes}:
      pkcs8(bytes)
    case M.Block{M.Sec1{}, bytes}:
      sec1(False{}, bytes)
    case M.Block{M.Pkcs1{}, bytes}:
      pkcs1(bytes)
    case _:
      None{}

def pem.decoded(result: Maybe<&1, Private>) -> Result<&2, &1, M.Error, Private>:
  match result:
    case Some{key}:
      Done{key}
    case None{}:
      Fail{M.Malformed{}}

def pem.result(result: Result<&2, &1, M.Error, M.Block>) -> Result<&2, &1, M.Error, Private>:
  match result:
    case Fail{error}:
      Fail{error}
    case Done{block}:
      pem.decoded(from_block(block))

def pem(bytes: List<&2, U32>) -> Result<&2, &1, M.Error, Private>:
  pem.result(M.decode(bytes))
