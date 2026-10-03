import Base
import ./signaling_auth.bend as Access
import ../http/core/cookie.bend as Cookie
import ../http/core/cookie_crypto.bend as Crypto
import ../http/core/request.bend as Req
import ../http/core/method.bend as M
import ../http/core/headers.bend as H
import ../http/core/text.bend as Text
import ../crypto/bytes.bend as B
import ../utf8/utf8.bend as U

# Server-owned synthetic session admission. Monotonic deadlines belong to the
# issuing process; never interpret client-provided time as a trusted clock.
type State is Data:
  State{key: String, payload: String, end: Nat}

def payload(session: String, end: Nat) -> String:
  "grounds-signal-v1:" ++ B.hex(U.encode(session)) ++ ":" ++ Nat.show(end)

def ticket(state: State) -> Maybe<&2, String>:
  match state:
    case State{key, value, _}: Crypto.sign(key, value)

def length(text: String, +n: Nat) -> Nat:
  match text:
    case SNil{}: n
    case SCon{_, tail}: length(tail, Nat.add(n, 1n))

type Found is Data:
  Missing{}
  One{value: String}
  Duplicate{}

def found(value: Maybe<&2, String>, previous: Found) -> Found:
  match value previous:
    case None{} p: p
    case Some{v} Missing{}: One{v}
    case Some{_} _: Duplicate{}

def segments.next(rest: Maybe<&2, String>, previous: Found, next: String -> Found -> Found) -> Found:
  match rest:
    case None{}: previous
    case Some{tail}: next(tail, previous)

def segments.cut(cut: Text.Cut, previous: Found, next: String -> Found -> Found) -> Found:
  match cut:
    case Text.Cut{segment, rest}:
      segments.next(rest, found(Cookie.pair(Text.cut(segment, 61), "grounds-fixture"), previous), next)

def segments(left: Nat, text: String, previous: Found) -> Found:
  match left:
    case 0n: Duplicate{}
    case 1n+p: segments.cut(Text.cut(text, 59), previous, t => f => segments(p, t, f))

def cookie_value(result: Found) -> Maybe<&2, String>:
  match result:
    case One{value}: Cookie.decode_value(value)
    case _: None{}

def cookie_bounded(ok: Bool, text: String) -> Maybe<&2, String>:
  match ok:
    case False{}: None{}
    case True{}: cookie_value(segments(1025n, text, Missing{}))

def cookie(headers: List<&2, String>) -> Maybe<&2, String>:
  match headers:
    case [+text]: cookie_bounded(Nat.is_le(length(text, 0n), 1024n), text)
    case _: None{}

def authentic(result: Maybe<&2, String>, expected: String) -> Bool:
  match result:
    case None{}: False{}
    case Some{value}: Text.same(value, expected, True{})

def verify_value(state: State, supplied: Maybe<&2, String>) -> Bool:
  match state supplied:
    case State{key, expected, _} Some{signed}: authentic(Crypto.verify(key, signed), expected)
    case _ _: False{}

def verify_live(live: Bool, state: State, headers: List<&2, String>) -> Bool:
  match live:
    case False{}: False{}
    case True{}: verify_value(state, cookie(headers))

def verify(+state: State, headers: List<&2, String>, now: Nat) -> Bool:
  match state:
    case State{_, _, end}: verify_live(Nat.is_lt(now, end), state, headers)

def headers.checked(host: Bool, origin: Bool, state: State, cookies: List<&2, String>, now: Nat) -> Access.Decision:
  match host origin:
    case False{} _: Access.BadRequest{}
    case True{} False{}: Access.DeniedOrigin{}
    case True{} True{}: Access.checked(True{}, True{}, verify(state, cookies, now))

def authorize(request: Req.Request, host: String, origin: String, state: State, now: Nat) -> Access.Decision:
  match request:
    case Req.Request{M.MGet{}, +path, +headers, Nil{}}:
      headers.checked(Bool.and(Text.same(path, "/signal", True{}), Access.one(H.all(headers, "host"), host)),
        Access.one(H.all(headers, "origin"), origin), state, H.all(headers, "cookie"), now)
    case _: Access.BadRequest{}
