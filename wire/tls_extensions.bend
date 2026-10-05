import Base
import ../crypto/bytes.bend as B

# Exact uint16-length-prefixed TLS extension vector (RFC 9846 4.3).
# Preserve unknown types and opaque bodies; message context, offered-extension
# binding and type-specific grammar are caller-owned. Duplicate types reject.

type Extension is Data:
  Extension{kind: U32, data: List<&2, U32>}

type Parts is Data:
  Parts{first: List<&2, U32>, rest: List<&2, U32>}

type Item is Data:
  Item{extension: Extension, rest: List<&2, U32>}

def number(high: U32, low: U32) -> U32:
  U32.add(U32.mul(high, 256), low)

def take(left: Nat, bytes: List<&2, U32>, reversed: List<&2, U32>) -> Maybe<&2, Parts>:
  match left bytes:
    case 0n _: Some{Parts{List.reverse(&2, U32, reversed), bytes}}
    case 1n+count Con{byte, rest}: take(count, rest, Con{byte, reversed})
    case _ _: None{}

def item_parts(kind: U32, value: Maybe<&2, Parts>) -> Maybe<&2, Item>:
  match value:
    case None{}: None{}
    case Some{Parts{body, rest}}: Some{Item{Extension{kind, body}, rest}}

def item(bytes: List<&2, U32>) -> Maybe<&2, Item>:
  match bytes:
    case Con{high, Con{low, Con{size_high, Con{size_low, rest}}}}:
      item_parts(number(high, low), take(U32.to_nat(number(size_high, size_low)), rest, []))
    case _: None{}

# One bit per possible uint16 extension type: fixed 8 KiB of U32 payload.
# Consuming the bitset avoids quadratic duplicate scans for empty extensions.
def mark_checked(unseen: Bool, index: U32, mask: U32, words: Array<U32>, word: U32) -> Maybe<&1, Array<U32>>:
  match unseen:
    case False{}: None{}
    case True{}: Some{Array.set(U32, words, index, U32.or(word, mask))}

def mark_word(index: U32, +mask: U32, value: Array<U32> & U32) -> Maybe<&1, Array<U32>>:
  (words, +word) = value
  mark_checked(U32.is_eq(U32.and(word, mask), 0), index, mask, words, word)

def mark(+kind: U32, words: Array<U32>) -> Maybe<&1, Array<U32>>:
  +index = U32.shrn(kind, 5n)
  mark_word(index, U32.shln(1, U32.to_nat(U32.and(kind, 31))), Array.get(U32, words, index))

type Next is Type:
  Next{extension: Extension, rest: List<&2, U32>, words: Array<U32>}

def prepared(extension: Extension, rest: List<&2, U32>, words: Maybe<&1, Array<U32>>) -> Maybe<&1, Next>:
  match words:
    case None{}: None{}
    case Some{seen}: Some{Next{extension, rest, seen}}

def prepare_item(value: Maybe<&2, Item>, words: Array<U32>) -> Maybe<&1, Next>:
  match value:
    case None{}: None{}
    case Some{Item{Extension{+kind, body}, rest}}:
      prepared(Extension{kind, body}, rest, mark(kind, words))

def prepare(bytes: List<&2, U32>, words: Array<U32>) -> Maybe<&1, Next>:
  prepare_item(item(bytes), words)

def entries(budget: Nat, value: Maybe<&1, Next>, reversed: List<&2, Extension>) -> Maybe<&2, List<&2, Extension>>:
  match budget value:
    case _ None{}: None{}
    case 0n _: None{}
    case 1n+left Some{Next{extension, rest, words}}:
      match rest:
        case Nil{}: Some{List.reverse(&2, Extension, Con{extension, reversed})}
        case Con{byte, tail}: entries(left, prepare(Con{byte, tail}, words), Con{extension, reversed})

def sized(valid: Bool, size: Nat, body: List<&2, U32>) -> Maybe<&2, List<&2, Extension>>:
  match valid body:
    case False{} _: None{}
    case True{} Nil{}: Some{[]}
    case True{} Con{byte, rest}:
      entries(Nat.div(size, 4n), prepare(Con{byte, rest}, Array.new(U32, 11n, 0)), [])

def framed(bytes: List<&2, U32>) -> Maybe<&2, List<&2, Extension>>:
  match bytes:
    case Con{high, Con{low, +body}}:
      +size = U32.to_nat(number(high, low))
      sized(Nat.is_eq(size, B.length(body)), size, body)
    case _: None{}

def admitted(valid: Bool, bytes: List<&2, U32>) -> Maybe<&2, List<&2, Extension>>:
  match valid:
    case False{}: None{}
    case True{}: framed(bytes)

def parse(+bytes: List<&2, U32>) -> Maybe<&2, List<&2, Extension>>:
  admitted(Bool.and(B.valid(bytes), Nat.is_le(B.length(bytes), 65537n)), bytes)
