import Base
import ./bytes.bend as B
import ./der.bend as D
import ./oid.bend as O
import ../utf8/utf8.bend as U

# Shared Name/RDN/attribute schema validation. No attribute collection, normalized
# comparison or chain authorization. Unknown types and Teletex remain deferred.
type Rule is Data:
  Rule{kind: U32, minimum: U32, maximum: U32}

type Scan is Type:
  Scan{rest: List<&2, U32>, previous: List<&2, U32>, supported: Bool}

def range(+value: U32, low: U32, high: U32) -> Bool:
  Bool.and(U32.is_ge(value, low), U32.is_le(value, high))

def printable(+byte: U32) -> Bool:
  match byte:
    case 32: True{}
    case 39: True{}
    case 40: True{}
    case 41: True{}
    case 43: True{}
    case 44: True{}
    case 45: True{}
    case 46: True{}
    case 47: True{}
    case 58: True{}
    case 61: True{}
    case 63: True{}
    case byte: Bool.or(range(byte, 48, 57), Bool.or(range(byte, 65, 90), range(byte, 97, 122)))

def scalar(+code: U32) -> Bool:
  Bool.and(U32.is_le(code, 1114111), Bool.not(range(code, 55296, 57343)))

def count.checked(valid: Bool, count: U32) -> Maybe<&1, U32>:
  match valid:
    case True{}: Some{count}
    case False{}: None{}

def single(bytes: List<&2, U32>, +ia5: Bool, count: U32, valid: Bool) -> Maybe<&1, U32>:
  match bytes:
    case Nil{}: count.checked(valid, count)
    case Con{+byte, rest}:
      single(rest, ia5, U32.add(count, 1), Bool.and(valid,
        Bool.pick(Bool, ia5, U32.is_lt(byte, 128), printable(byte))))

def bmp(bytes: List<&2, U32>, count: U32, valid: Bool) -> Maybe<&1, U32>:
  match bytes:
    case Nil{}: count.checked(valid, count)
    case Con{high, Con{low, rest}}:
      bmp(rest, U32.add(count, 1), Bool.and(valid, scalar(U32.add(U32.mul(high, 256), low))))
    case _: None{}

def universal(bytes: List<&2, U32>, count: U32, valid: Bool) -> Maybe<&1, U32>:
  match bytes:
    case Nil{}: count.checked(valid, count)
    case Con{a, Con{b, Con{c, Con{d, rest}}}}:
      universal(rest, U32.add(count, 1), Bool.and(valid,
        scalar(U32.add(U32.mul(a, 16777216), U32.add(U32.mul(b, 65536), U32.add(U32.mul(c, 256), d))))))
    case _: None{}

# Reuse the strict UTF-8 transition owner without retaining an output string.
def utf8(bytes: List<&2, U32>, state: U.U8) -> Maybe<&1, U32>:
  match bytes state:
    case Nil{} U.U8{need, _, _, _, at, _}: count.checked(U32.is_eq(need, 0), at)
    case Con{byte, rest} U.U8{need, code, low, high, at, _}:
      utf8(rest, U.u8.step(U.U8{need, code, low, high, at, ""}, byte))
    case _ _: None{}

def text(tag: U32, bytes: List<&2, U32>) -> Maybe<&1, U32>:
  match tag:
    case 12: utf8(bytes, U.U8{0, 0, 128, 191, 0, ""})
    case 19: single(bytes, False{}, 0, True{})
    case 22: single(bytes, True{}, 0, True{})
    case 28: universal(bytes, 0, True{})
    case 30: bmp(bytes, 0, True{})
    case _: None{}

def standard(attribute: U32) -> Rule:
  match attribute:
    case 3: Rule{1, 1, 64}
    case 4: Rule{1, 1, 32768}
    case 5: Rule{2, 1, 64}
    case 6: Rule{2, 2, 2}
    case 7: Rule{1, 1, 128}
    case 8: Rule{1, 1, 128}
    case 10: Rule{1, 1, 64}
    case 11: Rule{1, 1, 64}
    case 12: Rule{1, 1, 64}
    case 41: Rule{1, 1, 32768}
    case 42: Rule{1, 1, 32768}
    case 43: Rule{1, 1, 32768}
    case 44: Rule{1, 1, 32768}
    case 46: Rule{2, 0, 65535}
    case 65: Rule{1, 1, 128}
    case _: Rule{0, 0, 0}

def rule(oid: List<&2, U32>) -> Rule:
  match oid:
    case Con{85, Con{4, Con{attribute, Nil{}}}}: standard(attribute)
    case [9,146,38,137,147,242,44,100,1,25]: Rule{3, 0, 65535}
    case [42,134,72,134,247,13,1,9,1]: Rule{3, 1, 255}
    case _: Rule{0, 0, 0}

def permitted(valid: Bool, processed: Bool) -> Maybe<&1, Bool>:
  match valid:
    case True{}: Some{processed}
    case False{}: None{}

# Counts cannot exceed the DER owner's 65535-octet input bound.
def bounds(count: Maybe<&1, U32>, minimum: U32, maximum: U32) -> Maybe<&1, Bool>:
  match count:
    case Some{+count}: permitted(range(count, minimum, maximum), True{})
    case None{}: None{}

def directory(tag: U32, bytes: List<&2, U32>, minimum: U32, maximum: U32) -> Maybe<&1, Bool>:
  match tag:
    # T.61 has multibyte/combining forms; octet count cannot prove SIZE bounds.
    case 20: permitted(Nat.is_gt(B.length(bytes), 0n), False{})
    case 22: None{}
    case tag: bounds(text(tag, bytes), minimum, maximum)

def value(rule: Rule, tag: U32, bytes: List<&2, U32>) -> Maybe<&1, Bool>:
  match rule tag:
    case Rule{0, _, _} _: Some{False{}}
    case Rule{1, minimum, maximum} tag: directory(tag, bytes, minimum, maximum)
    case Rule{2, minimum, maximum} 19: bounds(text(19, bytes), minimum, maximum)
    case Rule{3, minimum, maximum} 22: bounds(text(22, bytes), minimum, maximum)
    case _ _: None{}

# X.690 11.6: compare complete unsigned DER encodings within each SET OF.
# RDN sequence order is significant and is never sorted here.
def order.next(+relation: U32, +x: U32, +y: U32) -> U32:
  Bool.pick(U32, U32.is_eq(relation, 0),
    Bool.pick(U32, U32.is_eq(x, y), 0, Bool.pick(U32, U32.is_lt(x, y), 1, 2)), relation)

def order(a: List<&2, U32>, b: List<&2, U32>, relation: U32) -> Bool:
  match a b:
    case Nil{} _: U32.is_ne(relation, 2)
    case Con{_, _} Nil{}: U32.is_eq(relation, 1)
    case Con{x, xs} Con{y, ys}: order(xs, ys, order.next(relation, x, y))

def combined(issuer: Maybe<&1, Bool>, subject: Maybe<&1, Bool>) -> Maybe<&1, Bool>:
  match issuer subject:
    case Some{a} Some{b}: Some{Bool.and(a, b)}
    case _ _: None{}

def attribute.value(+oid: List<&2, U32>, element: Maybe<&1, D.Element>) -> Maybe<&1, Bool>:
  match element:
    case Some{D.Element{tag, bytes, Nil{}, _}}:
      combined(permitted(O.contents(oid), True{}), value(rule(oid), tag, bytes))
    case _: None{}

def attribute.oid(element: Maybe<&1, D.Element>) -> Maybe<&1, Bool>:
  match element:
    case Some{D.Element{6, oid, rest, _}}: attribute.value(oid, D.read(rest))
    case _: None{}

def scan.checked(valid: Bool, processed: Maybe<&1, Bool>, supported: Bool, rest: List<&2, U32>, encoded: List<&2, U32>) -> Maybe<&1, Scan>:
  match valid processed:
    case True{} Some{value}: Some{Scan{rest, encoded, Bool.and(supported, value)}}
    case _ _: None{}

def scan.step(state: Scan, element: Maybe<&1, D.Element>) -> Maybe<&1, Scan>:
  match state element:
    case Scan{_, previous, supported} Some{D.Element{48, bytes, rest, +encoded}}:
      scan.checked(order(previous, encoded, 0), attribute.oid(D.read(bytes)), supported, rest, encoded)
    case _ _: None{}

def scan(left: Nat, state: Maybe<&1, Scan>) -> Maybe<&1, Bool>:
  match left state:
    case _ Some{Scan{Nil{}, _, supported}}: Some{supported}
    case 1n+p Some{Scan{+bytes, previous, supported}}:
      scan(p, scan.step(Scan{bytes, previous, supported}, D.read(bytes)))
    case _ _: None{}

def rdn(element: Maybe<&1, D.Element>) -> Maybe<&1, Scan>:
  match element:
    case Some{D.Element{49, Con{first, tail}, rest, _}}:
      scan.checked(True{}, scan(65535n, Some{Scan{Con{first, tail}, [], True{}}}), True{}, rest, [])
    case _: None{}

def rdns.next(supported: Bool, next: Maybe<&1, Scan>) -> Maybe<&1, Scan>:
  match next:
    case Some{Scan{rest, _, processed}}: Some{Scan{rest, [], Bool.and(supported, processed)}}
    case None{}: None{}

def rdns(left: Nat, state: Maybe<&1, Scan>) -> Maybe<&1, Bool>:
  match left state:
    case _ Some{Scan{Nil{}, _, supported}}: Some{supported}
    case 1n+p Some{Scan{bytes, _, supported}}:
      rdns(p, rdns.next(supported, rdn(D.read(bytes))))
    case _ _: None{}

def body(bytes: Maybe<&1, List<&2, U32>>, allow_empty: Bool) -> Maybe<&1, Bool>:
  match bytes:
    case Some{Nil{}}: permitted(allow_empty, True{})
    case Some{Con{first, tail}}: rdns(65535n, Some{Scan{Con{first, tail}, [], True{}}})
    case None{}: None{}

def inspect(bytes: List<&2, U32>, allow_empty: Bool) -> Maybe<&1, Bool>:
  body(D.complete(48, bytes), allow_empty)

def pair.walk(names: List<&2, List<&2, U32>>, allow_empty: Bool, state: Maybe<&1, Bool>) -> Maybe<&1, Bool>:
  match names state:
    case Nil{} state: state
    case Con{bytes, rest} Some{supported}:
      pair.walk(rest, True{}, combined(Some{supported}, inspect(bytes, allow_empty)))
    case _ None{}: None{}

def pair(issuer: List<&2, U32>, subject: List<&2, U32>) -> Maybe<&1, Bool>:
  pair.walk([issuer, subject], False{}, Some{True{}})
