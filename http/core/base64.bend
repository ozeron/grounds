import Base

# Strict canonical Base64 decoding, shared by Basic credentials and WebSocket keys.

def b64_digit(+c: U32) -> U32:
  Bool.pick(U32, Bool.and(U32.is_ge(c, 65), U32.is_le(c, 90)), (c - 65 : U32),
    Bool.pick(U32, Bool.and(U32.is_ge(c, 97), U32.is_le(c, 122)), (c - 71 : U32),
      Bool.pick(U32, Bool.and(U32.is_ge(c, 48), U32.is_le(c, 57)), (c + 4 : U32),
        Bool.pick(U32, U32.is_eq(c, 43), 62,
          Bool.pick(U32, U32.is_eq(c, 47), 63, 64)))))

def b64_end(ok: Bool, tail: String, acc: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match ok tail:
    case True{} SNil{}:
      Some{List.reverse(&2, U32, acc)}
    case _ _:
      None{}

def b64_two(+a: U32, +b: U32) -> U32:
  ((a << 2n) .|. (b >> 4n) : U32)

def b64_three(+b: U32, +c: U32) -> U32:
  (((b .&. 15 : U32) << 4n) .|. (c >> 2n) : U32)

def b64_four(+c: U32, +d: U32) -> U32:
  (((c .&. 3 : U32) << 6n) .|. d : U32)

def b64_pad2(+a: U32, +b: U32, tail: String, acc: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  b64_end(Bool.and(Bool.and(U32.is_lt(a, 64), U32.is_lt(b, 64)), U32.is_eq((b .&. 15 : U32), 0)),
    tail, Con{b64_two(a, b), acc})

def b64_pad1(+a: U32, +b: U32, +c: U32, tail: String, acc: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  b64_end(Bool.and(Bool.and(U32.is_lt(a, 64), U32.is_lt(b, 64)),
    Bool.and(U32.is_lt(c, 64), U32.is_eq((c .&. 3 : U32), 0))),
    tail, Con{b64_three(b, c), Con{b64_two(a, b), acc}})

def b64_full(ok: Bool, +a: U32, +b: U32, +c: U32, +d: U32, tail: String, acc: List<&2, U32>, next: String -> List<&2, U32> -> Maybe<&2, List<&2, U32>>) -> Maybe<&2, List<&2, U32>>:
  match ok:
    case True{}:
      next(tail, Con{b64_four(c, d), Con{b64_three(b, c), Con{b64_two(a, b), acc}}})
    case False{}:
      None{}

def b64_padded(pad_c: Bool, pad_d: Bool, +a: U32, +b: U32, +c: U32, +d: U32, tail: String, acc: List<&2, U32>, next: String -> List<&2, U32> -> Maybe<&2, List<&2, U32>>) -> Maybe<&2, List<&2, U32>>:
  match pad_c pad_d:
    case True{} True{}:
      b64_pad2(b64_digit(a), b64_digit(b), tail, acc)
    case False{} True{}:
      b64_pad1(b64_digit(a), b64_digit(b), b64_digit(c), tail, acc)
    case _ False{}:
      +aa = b64_digit(a)
      +bb = b64_digit(b)
      +cc = b64_digit(c)
      +dd = b64_digit(d)
      b64_full(Bool.and(Bool.and(U32.is_lt(aa, 64), U32.is_lt(bb, 64)),
        Bool.and(U32.is_lt(cc, 64), U32.is_lt(dd, 64))), aa, bb, cc, dd, tail, acc, next)

def b64_quad(+a: U32, +b: U32, +c: U32, +d: U32, tail: String, acc: List<&2, U32>, next: String -> List<&2, U32> -> Maybe<&2, List<&2, U32>>) -> Maybe<&2, List<&2, U32>>:
  b64_padded(U32.is_eq(c, 61), U32.is_eq(d, 61), a, b, c, d, tail, acc, next)

def b64_go(fuel: Nat, s: String, acc: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match fuel:
    case 0n:
      None{}
    case 1n+p:
      match s:
        case SNil{}:
          Some{List.reverse(&2, U32, acc)}
        case SCon{Chr{+a}, SCon{Chr{+b}, SCon{Chr{+c}, SCon{Chr{+d}, tail}}}}:
          b64_quad(a, b, c, d, tail, acc, t => bytes => b64_go(p, t, bytes))
        case _:
          None{}
