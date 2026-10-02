import Base
import ./bytes.bend as B
import ./der.bend as D
import ./x509_algorithm.bend as A

# Raw certificate field extraction for signature verification. Names, time
# values, subject keys and extension semantics still require their validators.
type Tbs is Type:
  Tbs{header: Header, identity: Identity, tail: Tail}

type Certificate is Type:
  Certificate{tbs: Tbs, algorithm: A.Signature, signature: List<&2, U32>}

type Header is Type:
  Header{encoded: List<&2, U32>, version: U32, serial: List<&2, U32>, algorithm: List<&2, U32>}

type Identity is Type:
  Identity{issuer: List<&2, U32>, validity: List<&2, U32>,
    subject: List<&2, U32>, spki: List<&2, U32>}

type Tail is Type:
  Tail{issuer_id: Maybe<&2, List<&2, U32>>, subject_id: Maybe<&2, List<&2, U32>>,
    extensions: Maybe<&2, List<&2, U32>>}

type Block is Type:
  Block{tag: U32, body: List<&2, U32>, encoded: List<&2, U32>}

type Fields is Type:
  Fields{items: List<&1, Block>, rest: List<&2, U32>}

def last(bytes: List<&2, U32>, previous: U32) -> U32:
  match bytes:
    case Nil{}:
      previous
    case Con{byte, rest}:
      last(rest, byte)

def bit_string.padding(valid: Bool, +unused: U32, +payload: List<&2, U32>) -> Bool:
  match valid:
    case False{}:
      False{}
    case True{}:
      U32.is_eq(U32.and(last(payload, 0), U32.sub(U32.shln(1, U32.to_nat(unused)), 1)), 0)

def bit_string(bytes: List<&2, U32>) -> Bool:
  match bytes:
    case Con{0, Nil{}}:
      True{}
    case Con{+unused, +payload}:
      bit_string.padding(Bool.and(U32.is_le(unused, 7), Nat.is_gt(B.length(payload), 0n)), unused, payload)
    case _:
      False{}

# Canonical signed INTEGER framing. Preserve even zero/negative serials for
# the later certificate profile validator; signature validity is separate.
def integer(bytes: List<&2, U32>) -> Bool:
  match bytes:
    case Con{+first, Con{+second, _}}:
      Bool.and(Bool.not(Bool.and(U32.is_eq(first, 0), U32.is_lt(second, 128))),
        Bool.not(Bool.and(U32.is_eq(first, 255), U32.is_ge(second, 128))))
    case Con{_, Nil{}}:
      True{}
    case Nil{}:
      False{}

def extension.body(valid: Bool, issuer: Maybe<&2, List<&2, U32>>, subject: Maybe<&2, List<&2, U32>>,
                   encoded: List<&2, U32>, body: Maybe<&1, List<&2, U32>>) -> Maybe<&1, Tail>:
  match valid body:
    case True{} Some{Con{_, _}}:
      Some{Tail{issuer, subject, Some{encoded}}}
    case _ _:
      None{}

def extension.element(version: U32, issuer: Maybe<&2, List<&2, U32>>, subject: Maybe<&2, List<&2, U32>>,
                      element: Maybe<&1, D.Element>) -> Maybe<&1, Tail>:
  match element:
    case Some{D.Element{163, +body, Nil{}, _}}:
      extension.body(U32.is_eq(version, 2), issuer, subject, body, D.complete(48, body))
    case _:
      None{}

def extension(version: U32, issuer: Maybe<&2, List<&2, U32>>, subject: Maybe<&2, List<&2, U32>>,
              bytes: List<&2, U32>) -> Maybe<&1, Tail>:
  match bytes:
    case Nil{}:
      Some{Tail{issuer, subject, None{}}}
    case bytes:
      extension.element(version, issuer, subject, D.read(bytes))

def subject_id.checked(valid: Bool, version: U32, issuer: Maybe<&2, List<&2, U32>>,
                       body: List<&2, U32>, rest: List<&2, U32>) -> Maybe<&1, Tail>:
  match valid:
    case True{}:
      extension(version, issuer, Some{body}, rest)
    case False{}:
      None{}

def subject_id.element(+version: U32, issuer: Maybe<&2, List<&2, U32>>, element: Maybe<&1, D.Element>) -> Maybe<&1, Tail>:
  match element:
    case Some{D.Element{130, +body, rest, _}}:
      subject_id.checked(Bool.and(U32.is_ge(version, 1), bit_string(body)), version, issuer, body, rest)
    case _:
      None{}

def subject_id(version: U32, issuer: Maybe<&2, List<&2, U32>>, bytes: List<&2, U32>) -> Maybe<&1, Tail>:
  match bytes:
    case Con{130, _}:
      subject_id.element(version, issuer, D.read(bytes))
    case bytes:
      extension(version, issuer, None{}, bytes)

def issuer_id.checked(valid: Bool, version: U32, body: List<&2, U32>, rest: List<&2, U32>) -> Maybe<&1, Tail>:
  match valid:
    case True{}:
      subject_id(version, Some{body}, rest)
    case False{}:
      None{}

def issuer_id.element(+version: U32, element: Maybe<&1, D.Element>) -> Maybe<&1, Tail>:
  match element:
    case Some{D.Element{129, +body, rest, _}}:
      issuer_id.checked(Bool.and(U32.is_ge(version, 1), bit_string(body)), version, body, rest)
    case _:
      None{}

def issuer_id(version: U32, bytes: List<&2, U32>) -> Maybe<&1, Tail>:
  match bytes:
    case Con{129, _}:
      issuer_id.element(version, D.read(bytes))
    case bytes:
      subject_id(version, None{}, bytes)

def time_tag(+tag: U32) -> Bool:
  Bool.or(U32.is_eq(tag, 23), U32.is_eq(tag, 24))

def validity.second(first_valid: Bool, element: Maybe<&1, D.Element>) -> Bool:
  match element:
    case Some{D.Element{tag, _, Nil{}, _}}:
      Bool.and(first_valid, time_tag(tag))
    case _:
      False{}

def validity.first(element: Maybe<&1, D.Element>) -> Bool:
  match element:
    case Some{D.Element{tag, _, rest, _}}:
      validity.second(time_tag(tag), D.read(rest))
    case _:
      False{}

def validity.body(body: Maybe<&1, List<&2, U32>>) -> Bool:
  match body:
    case Some{bytes}:
      validity.first(D.read(bytes))
    case _:
      False{}

def assembled(valid: Bool, header: Header, identity: Identity, tail: Maybe<&1, Tail>) -> Maybe<&1, Tbs>:
  match valid tail:
    case True{} Some{tail}:
      Some{Tbs{header, identity, tail}}
    case _ _:
      None{}

# One bounded walk retains bodies and original encodings. Validation consumes
# the six mandatory fields in their ASN.1 order after the walk completes.
def fields.got(items: List<&1, Block>, element: Maybe<&1, D.Element>,
               next: List<&1, Block> -> List<&2, U32> -> Maybe<&1, Fields>) -> Maybe<&1, Fields>:
  match element:
    case Some{D.Element{tag, body, rest, encoded}}:
      next(Con{Block{tag, body, encoded}, items}, rest)
    case _:
      None{}

def fields(left: Nat, collected: List<&1, Block>, bytes: List<&2, U32>) -> Maybe<&1, Fields>:
  match left:
    case 0n:
      Some{Fields{collected, bytes}}
    case 1n+p:
      fields.got(collected, D.read(bytes), f => b => fields(p, f, b))

def fields.complete(encoded: List<&2, U32>, +version: U32, blocks: Maybe<&1, Fields>) -> Maybe<&1, Tbs>:
  match blocks:
    case Some{Fields{Con{Block{48, _, spki}, Con{Block{48, _, subject}, Con{Block{48, validity_body, validity}, Con{Block{48, _, issuer}, Con{Block{48, _, algorithm}, Con{Block{2, +serial, _}, Nil{}}}}}}}, rest}}:
      assembled(Bool.and(integer(serial), validity.first(D.read(validity_body))),
        Header{encoded, version, serial, algorithm}, Identity{issuer, validity, subject, spki}, issuer_id(version, rest))
    case _:
      None{}

def version(encoded: List<&2, U32>, +bytes: List<&2, U32>, first: Maybe<&1, D.Element>) -> Maybe<&1, Tbs>:
  match first:
    case Some{D.Element{160, [2, 1, 1], rest, _}}:
      fields.complete(encoded, 1, fields(6n, [], rest))
    case Some{D.Element{160, [2, 1, 2], rest, _}}:
      fields.complete(encoded, 2, fields(6n, [], rest))
    case _:
      fields.complete(encoded, 0, fields(6n, [], bytes))

def same_algorithm(first: A.Signature, second: A.Signature) -> Bool:
  match first second:
    case A.RsaPss256{} A.RsaPss256{}:
      True{}
    case A.RsaV15256{} A.RsaV15256{}:
      True{}
    case A.Ecdsa256{} A.Ecdsa256{}:
      True{}
    case _ _:
      False{}

def inner_algorithm(value: Maybe<&1, A.Signature>, outer: A.Signature) -> Bool:
  match value:
    case Some{inner}:
      same_algorithm(inner, outer)
    case _:
      False{}

def signature.checked(valid: Bool, tbs: Tbs, algorithm: A.Signature, signature: List<&2, U32>) -> Maybe<&1, Certificate>:
  match valid:
    case True{}:
      Some{Certificate{tbs, algorithm, signature}}
    case False{}:
      None{}

def signature(tbs: Tbs, +algorithm: A.Signature, value: Maybe<&1, List<&2, U32>>) -> Maybe<&1, Certificate>:
  match tbs value:
    case Tbs{Header{encoded, version, serial, +inner}, identity, tail} Some{Con{0, Con{byte, rest}}}:
      signature.checked(inner_algorithm(A.signature(inner), algorithm),
        Tbs{Header{encoded, version, serial, inner}, identity, tail},
        algorithm, Con{byte, rest})
    case _ _:
      None{}

def outer.got(tbs: Maybe<&1, Tbs>, algorithm: Maybe<&1, A.Signature>, rest: List<&2, U32>) -> Maybe<&1, Certificate>:
  match tbs algorithm:
    case Some{tbs} Some{algorithm}:
      signature(tbs, algorithm, D.complete(3, rest))
    case _ _:
      None{}

def outer.element(tbs: Maybe<&1, Tbs>, element: Maybe<&1, D.Element>) -> Maybe<&1, Certificate>:
  match element:
    case Some{D.Element{48, _, rest, encoded}}:
      outer.got(tbs, A.signature(encoded), rest)
    case _:
      None{}

def tbs(element: Maybe<&1, D.Element>) -> Maybe<&1, Certificate>:
  match element:
    case Some{D.Element{48, +body, rest, encoded}}:
      outer.element(version(encoded, body, D.read(body)), D.read(rest))
    case _:
      None{}

def body(value: Maybe<&1, List<&2, U32>>) -> Maybe<&1, Certificate>:
  match value:
    case Some{bytes}:
      tbs(D.read(bytes))
    case _:
      None{}

def decode(bytes: List<&2, U32>) -> Maybe<&1, Certificate>:
  body(D.complete(48, bytes))
