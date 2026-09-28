import Base
import ./text.bend as T
import ./request.bend as Req
import ./headers.bend as H
import ./method.bend as M

# Fetch §3.3. An allowlist entry is a serialized origin, or "*" to permit
# wildcard responses without credentials. Methods are case-sensitive HTTP
# methods; request header names compare ignoring ASCII case.
type Policy is Data:
  Policy{origins: List<&2, String>, credentials: Bool, methods: List<&2, String>, headers: List<&2, String>, max_age: U32}

type Decision is Data:
  Deny{}
  Exact{origin: String}
  Any{}

type Clean is Data:
  Clean{safe: Bool, origin: String}

def origin_char(+c: U32) -> Bool:
  Bool.and(Bool.and(U32.is_ge(c, 33), U32.is_le(c, 126)),
    Bool.and(Bool.not(U32.is_eq(c, 42)), Bool.not(U32.is_eq(c, 44))))

def clean.go(s: String, ok: Bool, seen: Bool, acc: String) -> Clean:
  match s:
    case SNil{}:
      Clean{Bool.and(ok, seen), String.reverse(acc)}
    case SCon{Chr{+c}, tail}:
      clean.go(tail, Bool.and(ok, origin_char(c)), True{}, SCon{Chr{c}, acc})

def any_if(ok: Bool, later: Decision) -> Decision:
  match ok:
    case True{}:
      Any{}
    case False{}:
      later

def hit(found: Bool, entry: String, later: Decision) -> Decision:
  match found:
    case True{}:
      Exact{entry}
    case False{}:
      later

def decide.go(origins: List<&2, String>, +origin: String, +credentials: Bool) -> Decision:
  match origins:
    case Nil{}:
      Deny{}
    case Con{+entry, tail}:
      hit(T.same(entry, origin, True{}), entry,
        any_if(Bool.and(Bool.not(credentials), T.same(entry, "*", True{})), decide.go(tail, origin, credentials)))

def decide.clean(check: Clean, origins: List<&2, String>, credentials: Bool) -> Decision:
  match check:
    case Clean{True{}, origin}:
      decide.go(origins, origin, credentials)
    case Clean{False{}, _}:
      Deny{}

def decide(origins: List<&2, String>, credentials: Bool, origin: String) -> Decision:
  decide.clean(clean.go(origin, True{}, False{}, ""), origins, credentials)

def listed(origins: List<&2, String>, +origin: String) -> Bool:
  match origins:
    case Nil{}:
      False{}
    case Con{entry, tail}:
      Bool.or(T.same(entry, origin, True{}), listed(tail, origin))

# The predicate used by cors_safe: every exact result is listed, and a
# wildcard requires an explicit "*" entry without credentials.
def safe(decision: Decision, origins: List<&2, String>, credentials: Bool) -> Bool:
  match decision:
    case Deny{}:
      True{}
    case Exact{origin}:
      listed(origins, origin)
    case Any{}:
      Bool.and(Bool.not(credentials), listed(origins, "*"))

# Read the three CORS request fields once. The handler still receives the
# original request, including Origin; only those field values are copied.
type Slot is Data:
  Absent{}
  One{value: String}
  Many{}

type Fields is Data:
  Fields{origin: Slot, method: Slot, headers: Slot, rest: List<&2, H.Header>}

type Observed is Data:
  Observed{origin: Slot, method: Slot, headers: Slot, request: Req.Request}

def copy(s: String, acc: String) -> String:
  match s:
    case SNil{}:
      String.reverse(acc)
    case SCon{Chr{+c}, tail}:
      copy(tail, SCon{Chr{c}, acc})

def slot.add(slot: Slot, +value: String) -> Slot:
  match slot:
    case Absent{}:
      One{copy(value, "")}
    case _:
      Many{}

def lower(s: String) -> String:
  match s:
    case SNil{}:
      ""
    case SCon{Chr{+c}, tail}:
      SCon{Chr{T.lower(c)}, lower(tail)}

def lower_kind(s: String) -> U32:
  match s:
    case "origin":
      1
    case "access-control-request-method":
      2
    case "access-control-request-headers":
      3
    case _:
      0

def field_kind(s: String) -> U32:
  lower_kind(lower(s))

def field_next(+kind: U32, name: String, +value: String, tail: List<&2, H.Header>, origin: Slot, method: Slot, headers: Slot, acc: List<&2, H.Header>, next: List<&2, H.Header> -> Slot -> Slot -> Slot -> List<&2, H.Header> -> Fields) -> Fields:
  match kind:
    case 1:
      next(tail, slot.add(origin, value), method, headers, Con{H.Header{name, value}, acc})
    case 2:
      next(tail, origin, slot.add(method, value), headers, Con{H.Header{name, value}, acc})
    case 3:
      next(tail, origin, method, slot.add(headers, value), Con{H.Header{name, value}, acc})
    case _:
      next(tail, origin, method, headers, Con{H.Header{name, value}, acc})

def fields(fuel: Nat, hs: List<&2, H.Header>, origin: Slot, method: Slot, headers: Slot, acc: List<&2, H.Header>) -> Fields:
  match fuel:
    case 0n:
      Fields{Many{}, Many{}, Many{}, List.reverse(&2, H.Header, acc)}
    case 1n+p:
      match hs:
        case Nil{}:
          Fields{origin, method, headers, List.reverse(&2, H.Header, acc)}
        case Con{H.Header{+name, +value}, tail}:
          field_next(field_kind(name), name, value, tail, origin, method, headers, acc,
            rest => o => m => h => a => fields(p, rest, o, m, h, a))

def observed(f: Fields, m: M.Method, target: String, body: List<&2, U32>) -> Observed:
  match f:
    case Fields{origin, method, headers, rest}:
      Observed{origin, method, headers, Req.Request{m, target, rest, body}}

def observe(req: Req.Request) -> Observed:
  match req:
    case Req.Request{m, target, hs, body}:
      observed(fields(4294967295n, hs, Absent{}, Absent{}, Absent{}, []), m, target, body)

# Access-Control-Request-Headers is an HTTP field-name list. Reject empty
# members, controls and names outside token grammar before reflecting it.
def tpunct(+c: U32) -> Bool:
  match c:
    case 33: True{}
    case 35: True{}
    case 36: True{}
    case 37: True{}
    case 38: True{}
    case 39: True{}
    case 42: True{}
    case 43: True{}
    case 45: True{}
    case 46: True{}
    case 94: True{}
    case 95: True{}
    case 96: True{}
    case 124: True{}
    case 126: True{}
    case _: False{}

def tchar(+c: U32) -> Bool:
  Bool.or(Bool.or(Bool.and(U32.is_ge(c, 48), U32.is_le(c, 57)),
    Bool.and(U32.is_ge(c, 65), U32.is_le(c, 90))),
    Bool.or(Bool.and(U32.is_ge(c, 97), U32.is_le(c, 122)), tpunct(c)))

def drop_space(s: String) -> String:
  match s:
    case SCon{Chr{32}, tail}:
      drop_space(tail)
    case SCon{Chr{9}, tail}:
      drop_space(tail)
    case other:
      other

def trim(s: String) -> String:
  String.reverse(drop_space(String.reverse(drop_space(s))))

def lookup_hit(hit: Bool, entry: String, later: Maybe<&2, String>) -> Maybe<&2, String>:
  match hit:
    case True{}:
      Some{entry}
    case False{}:
      later

def lookup_ci(allowed: List<&2, String>, +name: String) -> Maybe<&2, String>:
  match allowed:
    case Nil{}:
      None{}
    case Con{+entry, tail}:
      lookup_hit(T.same_ci(entry, name, True{}), entry, lookup_ci(tail, name))

def lookup_exact(allowed: List<&2, String>, +name: String) -> Maybe<&2, String>:
  match allowed:
    case Nil{}:
      None{}
    case Con{+entry, tail}:
      lookup_hit(T.same(entry, name, True{}), entry, lookup_exact(tail, name))

type TokenText is Data:
  TokenText{ok: Bool, text: String}

def token_copy.go(s: String, seen: Bool, ok: Bool, acc: String) -> TokenText:
  match s:
    case SNil{}:
      TokenText{Bool.and(seen, ok), String.reverse(acc)}
    case SCon{Chr{+c}, tail}:
      token_copy.go(tail, True{}, Bool.and(ok, tchar(c)), SCon{Chr{c}, acc})

def token_text(check: TokenText) -> Maybe<&2, String>:
  match check:
    case TokenText{True{}, value}:
      Some{value}
    case TokenText{False{}, _}:
      None{}

def checked_token(s: String) -> Maybe<&2, String>:
  token_text(token_copy.go(s, False{}, True{}, ""))

def matched_token(found: Maybe<&2, String>) -> Maybe<&2, String>:
  match found:
    case Some{value}:
      checked_token(value)
    case None{}:
      None{}

def method_name(methods: List<&2, String>, method: String) -> Maybe<&2, String>:
  matched_token(lookup_exact(methods, method))

def joined(first: Maybe<&2, String>, rest: Maybe<&2, String>) -> Maybe<&2, String>:
  match first rest:
    case Some{a} Some{b}:
      Some{a ++ ", " ++ b}
    case _ _:
      None{}

def header_value.cut(cut: T.Cut, +allowed: List<&2, String>, next: String -> List<&2, String> -> Maybe<&2, String>) -> Maybe<&2, String>:
  match cut:
    case T.Cut{part, Some{rest}}:
      joined(matched_token(lookup_ci(allowed, trim(part))), next(rest, allowed))
    case T.Cut{part, None{}}:
      matched_token(lookup_ci(allowed, trim(part)))

def header_value.go(fuel: Nat, value: String, +allowed: List<&2, String>) -> Maybe<&2, String>:
  match fuel:
    case 0n:
      None{}
    case 1n+p:
      header_value.cut(T.cut(value, 44), allowed, rest => names => header_value.go(p, rest, names))

def header_value(value: String, +allowed: List<&2, String>) -> Maybe<&2, String>:
  header_value.go(4294967295n, value, allowed)
