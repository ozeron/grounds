import Base
import ./request.bend as Req
import ./headers.bend as H
import ./method.bend as M
import ./text.bend as T
import ../../utf8/utf8.bend as U

# RFC 6750 Bearer and RFC 7617 Basic credentials. A verifier decides whether
# either credential represents a principal; parsing alone grants no access.
type Credential is Data:
  Bearer{token: String}
  Basic{user: String, password: String}

type Claim is Data:
  Claim{name: String, value: String}

type Principal is Data:
  Principal{subject: String, claims: List<&2, Claim>}

type Attempt is Data:
  Missing{}
  Unsupported{}
  BadBearer{}
  BadBasic{}
  Duplicate{}
  Got{credential: Credential}

def lower(s: String) -> String:
  match s:
    case SNil{}:
      ""
    case SCon{Chr{+c}, tail}:
      SCon{Chr{T.lower(c)}, lower(tail)}

def spaces(s: String) -> String:
  match s:
    case SCon{Chr{32}, tail}:
      spaces(tail)
    case other:
      other

def bearer_char(+c: U32) -> Bool:
  Bool.or(Bool.or(Bool.and(U32.is_ge(c, 48), U32.is_le(c, 57)), Bool.and(U32.is_ge(c, 65), U32.is_le(c, 90))),
    Bool.or(Bool.and(U32.is_ge(c, 97), U32.is_le(c, 122)),
      Bool.or(U32.is_eq(c, 45), Bool.or(U32.is_eq(c, 46), Bool.or(U32.is_eq(c, 95),
        Bool.or(U32.is_eq(c, 126), Bool.or(U32.is_eq(c, 43), U32.is_eq(c, 47))))))))

type TokenCheck is Data:
  TokenCheck{valid: Bool, token: String}

def bearer_ok(s: String, seen: Bool, +padding: Bool, valid: Bool, acc: String) -> TokenCheck:
  match s:
    case SNil{}:
      TokenCheck{Bool.and(seen, valid), String.reverse(acc)}
    case SCon{Chr{61}, tail}:
      bearer_ok(tail, seen, True{}, valid, SCon{'=', acc})
    case SCon{Chr{+c}, tail}:
      bearer_ok(tail, True{}, padding, Bool.and(valid, Bool.and(Bool.not(padding), bearer_char(c))), SCon{Chr{c}, acc})

def bearer_valid(ok: Bool, token: String) -> Attempt:
  match ok:
    case True{}:
      Got{Bearer{token}}
    case False{}:
      BadBearer{}

def bearer_checked(check: TokenCheck) -> Attempt:
  match check:
    case TokenCheck{ok, token}:
      bearer_valid(ok, token)

def bearer(token: String) -> Attempt:
  bearer_checked(bearer_ok(token, False{}, False{}, True{}, ""))

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

def b64_quad(+a: U32, +b: U32, +c: U32, +d: U32, tail: String, acc: List<&2, U32>, next: String -> List<&2, U32> -> Maybe<&2, List<&2, U32>>) -> Maybe<&2, List<&2, U32>>:
  match c d:
    case 61 61:
      b64_pad2(b64_digit(a), b64_digit(b), tail, acc)
    case +x 61:
      b64_pad1(b64_digit(a), b64_digit(b), b64_digit(x), tail, acc)
    case +x +y:
      +aa = b64_digit(a)
      +bb = b64_digit(b)
      +cc = b64_digit(x)
      +dd = b64_digit(y)
      b64_full(Bool.and(Bool.and(U32.is_lt(aa, 64), U32.is_lt(bb, 64)),
        Bool.and(U32.is_lt(cc, 64), U32.is_lt(dd, 64))), aa, bb, cc, dd, tail, acc, next)

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

type SafeText is Data:
  SafeText{ok: Bool, text: String}

def safe_text(s: String, ok: Bool, acc: String) -> SafeText:
  match s:
    case SNil{}:
      SafeText{ok, String.reverse(acc)}
    case SCon{Chr{+c}, tail}:
      safe_text(tail, Bool.and(ok, Bool.and(U32.is_ge(c, 32), Bool.not(U32.is_eq(c, 127)))), SCon{Chr{c}, acc})

def basic_parts(cut: T.Cut) -> Attempt:
  match cut:
    case T.Cut{user, Some{password}}:
      Got{Basic{user, password}}
    case _:
      BadBasic{}

def basic_checked(ok: Bool, s: String) -> Attempt:
  match ok:
    case True{}:
      basic_parts(T.cut(s, 58))
    case False{}:
      BadBasic{}

def basic_safe(check: SafeText) -> Attempt:
  match check:
    case SafeText{ok, s}:
      basic_checked(ok, s)

def basic_text(t: U.Text) -> Attempt:
  match t:
    case U.TOk{s}:
      basic_safe(safe_text(s, True{}, ""))
    case U.TBad{_, _}:
      BadBasic{}

def basic_bytes(bs: Maybe<&2, List<&2, U32>>) -> Attempt:
  match bs:
    case Some{data}:
      basic_text(U.decode(data))
    case None{}:
      BadBasic{}

def basic(encoded: String) -> Attempt:
  basic_bytes(b64_go(4294967295n, encoded, []))

def scheme_missing(s: String) -> Attempt:
  match s:
    case "bearer":
      BadBearer{}
    case "basic":
      BadBasic{}
    case _:
      Unsupported{}

def scheme_with(s: String, value: String) -> Attempt:
  match s:
    case "bearer":
      bearer(spaces(value))
    case "basic":
      basic(spaces(value))
    case _:
      Unsupported{}

def parsed(cut: T.Cut) -> Attempt:
  match cut:
    case T.Cut{name, Some{value}}:
      scheme_with(lower(name), value)
    case T.Cut{name, None{}}:
      scheme_missing(lower(name))

def parse_header(value: String) -> Attempt:
  parsed(T.cut(value, 32))

# Take Authorization out of the request before passing it to an application.
# Duplicates are rejected instead of choosing an ambiguous credential.
type Seen is Data:
  NoneSeen{}
  OneSeen{value: String}
  Repeated{}

type Fields is Data:
  Fields{seen: Seen, headers: List<&2, H.Header>}

def seen.add(seen: Seen, value: String) -> Seen:
  match seen:
    case NoneSeen{}:
      OneSeen{value}
    case _:
      Repeated{}

def fields.next(hit: Bool, name: String, value: String, tail: List<&2, H.Header>, seen: Seen, acc: List<&2, H.Header>, next: List<&2, H.Header> -> Seen -> List<&2, H.Header> -> Fields) -> Fields:
  match hit:
    case True{}:
      next(tail, seen.add(seen, value), acc)
    case False{}:
      next(tail, seen, Con{H.Header{name, value}, acc})

def fields(fuel: Nat, hs: List<&2, H.Header>, seen: Seen, acc: List<&2, H.Header>) -> Fields:
  match fuel:
    case 0n:
      Fields{Repeated{}, []}
    case 1n+p:
      match hs:
        case Nil{}:
          Fields{seen, List.reverse(&2, H.Header, acc)}
        case Con{H.Header{+name, value}, tail}:
          fields.next(T.same_ci(name, "authorization", True{}), name, value, tail, seen, acc, rest => seen2 => acc2 => fields(p, rest, seen2, acc2))

def attempt(seen: Seen) -> Attempt:
  match seen:
    case NoneSeen{}:
      Missing{}
    case OneSeen{value}:
      parse_header(value)
    case Repeated{}:
      Duplicate{}

type Taken is Data:
  Taken{attempt: Attempt, request: Req.Request}

def taken(f: Fields, m: M.Method, target: String, body: List<&2, U32>) -> Taken:
  match f:
    case Fields{seen, hs}:
      Taken{attempt(seen), Req.Request{m, target, hs, body}}

def take(req: Req.Request) -> Taken:
  match req:
    case Req.Request{m, target, hs, body}:
      taken(fields(4294967295n, hs, NoneSeen{}, []), m, target, body)
