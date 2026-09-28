import Base
import ./response.bend as Res
import ./request.bend as Req
import ./headers.bend as H
import ./text.bend as T
import ../../utf8/utf8.bend as U

# Cookies are written as RFC 6265 token names and cookie-octet values.
# Unsafe UTF-8 bytes are percent-encoded; percent itself is encoded too,
# making decoding unambiguous.

def in_range(+b: U32, lo: U32, hi: U32) -> Bool:
  Bool.and(U32.is_ge(b, lo), U32.is_le(b, hi))

def name_byte(+b: U32) -> Bool:
  Bool.or(Bool.or(in_range(b, 48, 57), in_range(b, 65, 90)),
    Bool.or(in_range(b, 97, 122),
      Bool.or(Bool.or(U32.is_eq(b, 45), U32.is_eq(b, 95)), U32.is_eq(b, 46))))

def value_byte(+b: U32) -> Bool:
  Bool.and(Bool.not(U32.is_eq(b, 37)),
    Bool.or(U32.is_eq(b, 33),
      Bool.or(in_range(b, 35, 43),
        Bool.or(in_range(b, 45, 58),
          Bool.or(in_range(b, 60, 91), in_range(b, 93, 126))))))

def line_byte(+b: U32) -> Bool:
  Bool.or(U32.is_eq(b, 10), U32.is_eq(b, 13))

def safe(kind: Bool, +b: U32) -> Bool:
  match kind:
    case True{}:
      Bool.and(Bool.not(line_byte(b)), name_byte(b))
    case False{}:
      Bool.and(Bool.not(line_byte(b)), value_byte(b))

def hex.digit(+n: U32) -> Char:
  match n:
    case 0: '0'
    case 1: '1'
    case 2: '2'
    case 3: '3'
    case 4: '4'
    case 5: '5'
    case 6: '6'
    case 7: '7'
    case 8: '8'
    case 9: '9'
    case 10: 'A'
    case 11: 'B'
    case 12: 'C'
    case 13: 'D'
    case 14: 'E'
    case 15: 'F'
    case _: '0'

def hex(+n: U32) -> Char:
  hex.digit((n .&. 15 : U32))

def escaped(ok: Bool, +b: U32, tail: String) -> String:
  match ok:
    case True{}:
      SCon{Chr{b}, tail}
    case False{}:
      SCon{Chr{37}, SCon{hex((b >> 4n : U32)), SCon{hex((b .&. 15 : U32)), tail}}}

def escape.to(bs: List<&2, U32>, +kind: Bool, tail: String) -> String:
  match bs:
    case Nil{}:
      tail
    case Con{+b, t}:
      escaped(safe(kind, b), b, escape.to(t, kind, tail))

def escape(s: String, kind: Bool) -> String:
  escape.to(U.encode(s), kind, "")

# A final pass ensures no line break can reach Set-Cookie, independently of
# the byte encoder. The encoder already replaces these bytes with %XX.
def line_safe(bad: Bool, +b: U32, tail: String) -> String:
  match bad:
    case True{}:
      SCon{'?', tail}
    case False{}:
      SCon{Chr{b}, tail}

def without_lines(s: String) -> String:
  match s:
    case SNil{}:
      ""
    case SCon{Chr{+b}, t}:
      line_safe(line_byte(b), b, without_lines(t))

# Set a host-only cookie for the entire site. Callers do not have to escape
# data: the name and value are encoded into the narrow cookie grammar.
def set_value(name: String, value: String) -> String:
  without_lines(escape.to(U.encode(name), True{}, SCon{'=', escape.to(U.encode(value), False{}, "; Path=/; HttpOnly; Secure; SameSite=Lax")}))

def set(res: Res.Response, name: String, value: String) -> Res.Response:
  match name:
    case SNil{}:
      res
    case other:
      Res.header(res, "set-cookie", set_value(other, value))

def clear(res: Res.Response, name: String) -> Res.Response:
  match name:
    case SNil{}:
      res
    case other:
      Res.header(res, "set-cookie", without_lines(escape.to(U.encode(other), True{}, "=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax")))

def no_crlf(s: String) -> Bool:
  match s:
    case SNil{}:
      True{}
    case SCon{Chr{+b}, t}:
      Bool.and(Bool.not(line_byte(b)), no_crlf(t))

def drop_space(s: String) -> String:
  match s:
    case SCon{Chr{32}, t}:
      drop_space(t)
    case SCon{Chr{9}, t}:
      drop_space(t)
    case SCon{c, t}:
      SCon{c, t}
    case SNil{}:
      ""

def trim(s: String) -> String:
  String.reverse(drop_space(String.reverse(drop_space(s))))

type Measured is Data:
  Measured{length: Nat, text: String}

def measure(s: String, +n: Nat, acc: String) -> Measured:
  match s:
    case SNil{}:
      Measured{n, String.reverse(acc)}
    case SCon{c, t}:
      measure(t, Nat.add(n, 1n), SCon{c, acc})

type Decoded is Data:
  Decoded{bytes: List<&2, U32>}
  Invalid{}

def hex_value(+b: U32) -> U32:
  Bool.pick(U32, in_range(b, 48, 57), (b - 48 : U32),
    Bool.pick(U32, in_range(b, 65, 70), (b - 55 : U32),
      Bool.pick(U32, in_range(b, 97, 102), (b - 87 : U32), 16)))

def pct_next(ok: Bool, +byte: U32, tail: String, acc: List<&2, U32>, next: String -> List<&2, U32> -> Decoded) -> Decoded:
  match ok:
    case True{}:
      next(tail, Con{byte, acc})
    case False{}:
      Invalid{}

def pct(+hi: U32, +lo: U32, tail: String, acc: List<&2, U32>, next: String -> List<&2, U32> -> Decoded) -> Decoded:
  pct_next(Bool.and(U32.is_lt(hex_value(hi), 16), U32.is_lt(hex_value(lo), 16)),
    (hex_value(hi) * 16 + hex_value(lo) : U32), tail, acc, next)

def unescape.go(fuel: Nat, s: String, acc: List<&2, U32>) -> Decoded:
  match fuel:
    case 0n:
      Invalid{}
    case 1n+p:
      match s:
        case SNil{}:
          Decoded{List.reverse(&2, U32, acc)}
        case SCon{Chr{37}, SCon{Chr{+hi}, SCon{Chr{+lo}, tail}}}:
          pct(hi, lo, tail, acc, t => a => unescape.go(p, t, a))
        case SCon{Chr{37}, _}:
          Invalid{}
        case SCon{Chr{+b}, tail}:
          unescape.go(p, tail, Con{b, acc})

def decoded_text(t: U.Text) -> Maybe<&2, String>:
  match t:
    case U.TOk{s}:
      Some{s}
    case U.TBad{_, _}:
      None{}

def decoded_bytes(d: Decoded) -> Maybe<&2, String>:
  match d:
    case Decoded{bs}:
      decoded_text(U.decode(bs))
    case Invalid{}:
      None{}

def unescape_measured(m: Measured) -> Maybe<&2, String>:
  match m:
    case Measured{+n, s}:
      decoded_bytes(unescape.go(Nat.add(n, 1n), s, []))

def unescape(s: String) -> Maybe<&2, String>:
  unescape_measured(measure(s, 0n, ""))

def quoted_tail(back: String) -> Maybe<&2, String>:
  match back:
    case SCon{Chr{34}, rest}:
      unescape(String.reverse(rest))
    case _:
      None{}

def decode_value(s: String) -> Maybe<&2, String>:
  match s:
    case SCon{Chr{34}, tail}:
      quoted_tail(String.reverse(tail))
    case other:
      unescape(other)

def pair_hit(hit: Bool, value: String) -> Maybe<&2, String>:
  match hit:
    case True{}:
      Some{trim(value)}
    case False{}:
      None{}

def pair(cut: T.Cut, +want: String) -> Maybe<&2, String>:
  match cut:
    case T.Cut{key, Some{value}}:
      pair_hit(T.same(trim(key), want, True{}), value)
    case _:
      None{}

def line_next(found: Maybe<&2, String>, rest: Maybe<&2, String>, next: String -> Maybe<&2, String>) -> Maybe<&2, String>:
  match found rest:
    case Some{value} _:
      Some{value}
    case None{} Some{tail}:
      next(tail)
    case None{} None{}:
      None{}

def line_cut(cut: T.Cut, +want: String, next: String -> Maybe<&2, String>) -> Maybe<&2, String>:
  match cut:
    case T.Cut{segment, rest}:
      line_next(pair(T.cut(segment, 61), want), rest, next)

def line(fuel: Nat, s: String, +want: String) -> Maybe<&2, String>:
  match fuel:
    case 0n:
      None{}
    case 1n+p:
      line_cut(T.cut(s, 59), want, t => line(p, t, want))

def first(found: Maybe<&2, String>, later: Maybe<&2, String>) -> Maybe<&2, String>:
  match found:
    case Some{value}:
      Some{value}
    case None{}:
      later

def measured(m: Measured, +want: String) -> Maybe<&2, String>:
  match m:
    case Measured{+n, s}:
      line(Nat.add(n, 1n), s, want)

def lines(hs: List<&2, String>, +want: String) -> Maybe<&2, String>:
  match hs:
    case Nil{}:
      None{}
    case Con{h, t}:
      first(measured(measure(h, 0n, ""), want), lines(t, want))

def decoded_hit(hit: Maybe<&2, String>) -> Maybe<&2, String>:
  match hit:
    case Some{value}:
      decode_value(value)
    case None{}:
      None{}

# The first matching pair, across all Cookie fields in wire order.
def get(req: Req.Request, name: String) -> Maybe<&2, String>:
  match req:
    case Req.Request{_, _, hs, _}:
      decoded_hit(lines(H.all(hs, "cookie"), escape(name, True{})))

# A signed value is value followed by "." and a lowercase HMAC-SHA256 hex
# digest. The key and value are UTF-8 bytes. The native target uses OpenSSL 3.
def sign(key: String, value: String) -> IO(Result<&1, &1, U32 & String, String>):
  import "./effs/cookie.c"
  import "./effs/cookie.js"

# Some{value} for a valid signature, None{} for a missing, malformed or
# incorrect signature. Comparison of a well-formed MAC is constant-time.
def verify(key: String, signed: String) -> IO(Result<&1, &1, U32 & String, Maybe<&2, String>>):
  import "./effs/cookie.c"
  import "./effs/cookie.js"
