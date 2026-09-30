import Base
import ./stun.bend as Stun
import ./stun_auth.bend as Auth
import ./stun_fingerprint.bend as Fingerprint
import ../utf8/utf8.bend as U

# None means unrelated/unauthenticated traffic: keep waiting. An authenticated
# response can instead terminate the transaction with an explicit failure.
type Response is Data:
  Success{address: Stun.IPv4}
  Error{code: U32}
  Invalid{}

type Reply is Data:
  Reply{response: Response, algorithm: Auth.Mode}

# Comprehension-required attributes understood by the base STUN/ICE usage.
# Known-but-unexpected attributes are ignored; extensions need explicit support.
def known(kind: U32) -> Bool:
  match kind:
    case 1: True{}
    case 6: True{}
    case 8: True{}
    case 9: True{}
    case 10: True{}
    case 20: True{}
    case 21: True{}
    case 28: True{}
    case 29: True{}
    case 30: True{}
    case 32: True{}
    case 36: True{}
    case 37: True{}
    case _: False{}

def understood(attrs: List<&2, Stun.Attribute>, ok: Bool) -> Bool:
  match attrs:
    case Nil{}:
      ok
    case Con{Stun.Attribute{+kind, _}, tail}:
      understood(tail, Bool.and(ok, Bool.or(U32.is_le(32768, kind), known(kind))))

def chars(text: String, +count: Nat) -> Bool:
  match text:
    case SNil{}:
      Nat.is_lt(count, 128n)
    case SCon{_, tail}:
      chars(tail, Nat.add(count, 1n))

def reason(text: U.Text) -> Bool:
  match text:
    case U.TOk{text}:
      chars(text, 0n)
    case U.TBad{_, _}:
      False{}

def error_checked(ok: Bool, code: U32) -> Response:
  match ok:
    case True{}: Error{code}
    case False{}: Invalid{}

def error_value(bytes: List<&2, U32>) -> Response:
  match bytes:
    case Con{_, Con{_, Con{+class_bits, Con{+number, text}}}}:
      +cls = U32.and(class_bits, 7)
      error_checked(Bool.and(Bool.and(U32.is_le(3, cls), U32.is_le(cls, 6)),
        Bool.and(U32.is_le(number, 99), reason(U.decode(text)))), (cls * 100 + number : U32))
    case _:
      Invalid{}

def error(attrs: List<&2, Stun.Attribute>) -> Response:
  match attrs:
    case Nil{}:
      Invalid{}
    case Con{Stun.Attribute{9, bytes}, _}:
      error_value(bytes)
    case Con{_, tail}:
      error(tail)

def success(address: Maybe<&2, Stun.IPv4>) -> Response:
  match address:
    case Some{a}: Success{a}
    case None{}: Invalid{}

def classified(ok: Bool, kind: U32, attrs: List<&2, Stun.Attribute>) -> Response:
  match ok kind:
    case False{} _: Invalid{}
    case True{} 257: success(Stun.mapped_ipv4(Stun.Packet{257, [], attrs}))
    case True{} _: error(attrs)

def correlated(ok: Bool, +kind: U32, +attrs: List<&2, Stun.Attribute>) -> Maybe<&2, Response>:
  match ok:
    case False{}:
      None{}
    case True{}:
      Some{classified(understood(attrs, True{}), kind, attrs)}

def authenticated(packet: Maybe<&2, Stun.Packet>, transaction: List<&2, U32>) -> Maybe<&2, Response>:
  match packet:
    case None{}:
      None{}
    case Some{Stun.Packet{+kind, got, attrs}}:
      correlated(Bool.and(Bool.or(U32.is_eq(kind, 257), U32.is_eq(kind, 273)),
        Stun.same(got, transaction, True{})), kind, attrs)

# Only expose this algorithm together with a successfully authenticated reply.
# Authentication guarantees exactly one MI field, so suffix fields cannot spoof it.
def algorithm_attrs(attrs: List<&2, Stun.Attribute>) -> Maybe<&2, Auth.Mode>:
  match attrs:
    case Nil{}: None{}
    case Con{Stun.Attribute{8, _}, _}: Some{Auth.Legacy{}}
    case Con{Stun.Attribute{28, _}, _}: Some{Auth.Sha256{}}
    case Con{_, tail}: algorithm_attrs(tail)

def algorithm(packet: Maybe<&2, Stun.Packet>) -> Maybe<&2, Auth.Mode>:
  match packet:
    case None{}: None{}
    case Some{Stun.Packet{_, _, attrs}}: algorithm_attrs(attrs)

def decorated(response: Maybe<&2, Response>, mode: Maybe<&2, Auth.Mode>) -> Maybe<&2, Reply>:
  match response mode:
    case Some{r} Some{m}: Some{Reply{r, m}}
    case _ _: None{}

def checked(ok: Bool, +raw: List<&2, U32>, transaction: List<&2, U32>, key: List<&2, U32>,
            mode: Auth.Mode) -> Maybe<&2, Reply>:
  match ok:
    case False{}:
      None{}
    case True{}:
      decorated(authenticated(Auth.authenticate_response(raw, key, mode), transaction), algorithm(Stun.parse(raw)))

def parse(+raw: List<&2, U32>, transaction: List<&2, U32>, key: List<&2, U32>,
          mode: Auth.Mode) -> Maybe<&2, Reply>:
  checked(Fingerprint.verify(raw), raw, transaction, key, mode)

# RFC 8489 9.1.4: expire as integrity violation if correlated responses were
# discarded for missing/incorrect integrity. Other unrelated/invalid envelopes
# must not manufacture this outcome. A later authenticated response wins.
def authentication_failed(packet: Maybe<&2, Stun.Packet>) -> Bool:
  match packet:
    case None{}: True{}
    case Some{_}: False{}

def integrity_checked(ok: Bool, raw: List<&2, U32>, key: List<&2, U32>, mode: Auth.Mode) -> Bool:
  match ok:
    case False{}: False{}
    case True{}: authentication_failed(Auth.authenticate(raw, key, mode))

def integrity_packet(packet: Maybe<&2, Stun.Packet>, raw: List<&2, U32>, transaction: List<&2, U32>,
                     key: List<&2, U32>, mode: Auth.Mode) -> Bool:
  match packet:
    case None{}: False{}
    case Some{Stun.Packet{+kind, got, _}}:
      integrity_checked(Bool.and(Bool.or(U32.is_eq(kind, 257), U32.is_eq(kind, 273)),
        Stun.same(got, transaction, True{})), raw, key, mode)

def integrity_envelope(ok: Bool, +raw: List<&2, U32>, transaction: List<&2, U32>,
                       key: List<&2, U32>, mode: Auth.Mode) -> Bool:
  match ok:
    case False{}: False{}
    case True{}: integrity_packet(Stun.parse(raw), raw, transaction, key, mode)

def integrity_failed(+raw: List<&2, U32>, transaction: List<&2, U32>, key: List<&2, U32>,
                     mode: Auth.Mode) -> Bool:
  integrity_envelope(Fingerprint.verify(raw), raw, transaction, key, mode)
