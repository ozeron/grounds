import Base
import ./sha1.bend as Sha1
import ./bytes.bend as B

# HMAC-SHA1 for STUN MESSAGE-INTEGRITY interoperability. It is not a new
# credential or signature scheme; callers must supply the protocol key.
type Pads is Data:
  Pads{inner: List<&2, U32>, outer: List<&2, U32>}

def pads.cons(+i: U32, +o: U32, rest: Pads) -> Pads:
  match rest:
    case Pads{inner, outer}:
      Pads{Con{i, inner}, Con{o, outer}}

def pads(left: Nat, key: List<&2, U32>) -> Pads:
  match left key:
    case 0n _:
      Pads{[], []}
    case 1n+p Con{+b, tail}:
      pads.cons(U32.xor(b, 54), U32.xor(b, 92), pads(p, tail))
    case 1n+p Nil{}:
      pads.cons(54, 92, pads(p, []))

def normalized(long: Bool, key: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match long:
    case True{}:
      Sha1.digest(key)
    case False{}:
      Some{key}

def outer(opad: List<&2, U32>, inner_hash: Maybe<&2, List<&2, U32>>) -> Maybe<&2, List<&2, U32>>:
  match inner_hash:
    case None{}:
      None{}
    case Some{bytes}:
      Sha1.digest(B.append(opad, bytes))

def padded(p: Pads, msg: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match p:
    case Pads{ipad, opad}:
      outer(opad, Sha1.digest(B.append(ipad, msg)))

def with_key(norm: Maybe<&2, List<&2, U32>>, msg: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match norm:
    case None{}:
      None{}
    case Some{key}:
      padded(pads(64n, key), msg)

def checked(ok: Bool, +key: List<&2, U32>, msg: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match ok:
    case False{}:
      None{}
    case True{}:
      with_key(normalized(Nat.is_gt(B.length(key), 64n), key), msg)

def digest(+key: List<&2, U32>, +msg: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  checked(Bool.and(B.valid(key), B.valid(msg)), key, msg)
