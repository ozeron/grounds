import Base
import ./stun.bend as Stun
import ./stun_auth.bend as Auth
import ./stun_sign.bend as Sign
import ./stun_integrity.bend as Integrity
import ./stun_fingerprint.bend as Fingerprint
import ../crypto/bytes.bend as B
import ../utf8/utf8.bend as U

# Caller-supplied, already exchanged SDP credentials; not generated here.
type Credentials is Data:
  Credentials{local: String, remote: String, password: String}

# Two U32 words retain all 64 bits without exceeding Bend's immediate Nat.
type Role is Data:
  Controlling{high: U32, low: U32}
  Controlled{high: U32, low: U32}

type Check is Data:
  Check{priority: U32, role: Role}

def between(+byte: U32, low: U32, high: U32) -> Bool:
  Bool.and(U32.is_le(low, byte), U32.is_le(byte, high))

def ice_char(+byte: U32) -> Bool:
  Bool.or(Bool.or(between(byte, 65, 90), between(byte, 97, 122)),
    Bool.or(between(byte, 48, 57), Bool.or(U32.is_eq(byte, 43), U32.is_eq(byte, 47))))

def chars(bytes: List<&2, U32>, ok: Bool) -> Bool:
  match bytes:
    case Nil{}:
      ok
    case Con{byte, tail}:
      chars(tail, Bool.and(ok, ice_char(byte)))

def credential(+bytes: List<&2, U32>, low: Nat, high: Nat) -> Bool:
  Bool.and(chars(bytes, True{}),
    Bool.and(Nat.is_le(low, B.length(bytes)), Nat.is_le(B.length(bytes), high)))

def key(credentials: Credentials) -> List<&2, U32>:
  match credentials:
    case Credentials{_, _, password}:
      U.encode(password)

def valid(credentials: Credentials) -> Bool:
  match credentials:
    case Credentials{local, remote, password}:
      # RFC 8839 5.4: send at most 32 local ufrag chars; accept 256 remote.
      Bool.and(Bool.and(credential(U.encode(local), 4n, 32n),
        credential(U.encode(remote), 4n, 256n)), credential(U.encode(password), 22n, 256n))

def username(credentials: Credentials) -> List<&2, U32>:
  match credentials:
    case Credentials{local, remote, _}:
      U.encode(remote ++ ":" ++ local)

def attribute(+kind: U32, +value: List<&2, U32>) -> List<&2, U32>:
  +size = B.length(value)
  +pad = Nat.mod(Nat.sub(4n, Nat.mod(size, 4n)), 4n)
  B.append([U32.from_nat(Nat.div(U32.to_nat(kind), 256n)), U32.and(kind, 255),
    U32.from_nat(Nat.div(size, 256n)), U32.from_nat(Nat.mod(size, 256n))],
    B.append(value, List.replicate(U32, pad, 0)))

def role_attribute(role: Role) -> List<&2, U32>:
  match role:
    case Controlling{high, low}:
      attribute(32810, Sign.word_bytes(high, Sign.word_bytes(low, [])))
    case Controlled{high, low}:
      attribute(32809, Sign.word_bytes(high, Sign.word_bytes(low, [])))

def body(credentials: Credentials, check: Check) -> List<&2, U32>:
  match check:
    case Check{priority, role}:
      B.append(attribute(6, username(credentials)),
        B.append(attribute(36, Sign.word_bytes(priority, [])), role_attribute(role)))

def nomination_role(check: Check) -> Bool:
  match check:
    case Check{_, Controlling{_, _}}: True{}
    case _: False{}

def intent_body(credentials: Credentials, check: Check, nominate: Bool) -> List<&2, U32>:
  B.append(body(credentials, check), Bool.pick(List<&2, U32>, nominate, attribute(37, []), []))

def unsigned_header(header: Maybe<&2, List<&2, U32>>, +body: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match header:
    case None{}:
      None{}
    case Some{bytes}:
      Some{B.append(Integrity.adjusted(bytes, B.length(body)), body)}

def unsigned_checked(ok: Bool, transaction: List<&2, U32>, credentials: Credentials,
                     check: Check) -> Maybe<&2, List<&2, U32>>:
  match ok:
    case False{}:
      None{}
    case True{}:
      unsigned_header(Stun.binding_request(transaction), body(credentials, check))

def priority_ok(check: Check) -> Bool:
  match check:
    case Check{+priority, _}:
      Bool.and(U32.is_gt(priority, 0), U32.is_le(priority, 2147483647))

def unsigned(transaction: List<&2, U32>, +credentials: Credentials, +check: Check) -> Maybe<&2, List<&2, U32>>:
  unsigned_checked(Bool.and(valid(credentials), priority_ok(check)), transaction, credentials, check)

def intent_unsigned_checked(ok: Bool, transaction: List<&2, U32>, credentials: Credentials, check: Check, nominate: Bool) -> Maybe<&2, List<&2, U32>>:
  match ok:
    case False{}: None{}
    case True{}: unsigned_header(Stun.binding_request(transaction), intent_body(credentials, check, nominate))

def intent_unsigned(transaction: List<&2, U32>, +credentials: Credentials, +check: Check, +nominate: Bool) -> Maybe<&2, List<&2, U32>>:
  intent_unsigned_checked(Bool.and(Bool.and(valid(credentials), priority_ok(check)),
    Bool.or(Bool.not(nominate), nomination_role(check))), transaction, credentials, check, nominate)

def signed(raw: Maybe<&2, List<&2, U32>>, key: List<&2, U32>, mode: Auth.Mode) -> Maybe<&2, List<&2, U32>>:
  match raw:
    case None{}:
      None{}
    case Some{bytes}:
      Auth.sign(bytes, key, mode)

def request(transaction: List<&2, U32>, +credentials: Credentials,
            check: Check, mode: Auth.Mode) -> Maybe<&2, List<&2, U32>>:
  signed(unsigned(transaction, credentials, check), key(credentials), mode)

# Additive nomination request API; ordinary requests and Check retain their
# original shape and bytes. A controlled sender can never emit USE-CANDIDATE.
def intent_request(transaction: List<&2, U32>, +credentials: Credentials,
                   check: Check, nominate: Bool, mode: Auth.Mode) -> Maybe<&2, List<&2, U32>>:
  signed(intent_unsigned(transaction, credentials, check, nominate), key(credentials), mode)

def mapped_checked(ok: Bool, packet: Stun.Packet) -> Maybe<&2, Stun.IPv4>:
  match ok:
    case True{}:
      Stun.mapped_ipv4(packet)
    case False{}:
      None{}

def mapped(packet: Maybe<&2, Stun.Packet>, transaction: List<&2, U32>) -> Maybe<&2, Stun.IPv4>:
  match packet:
    case None{}:
      None{}
    case Some{Stun.Packet{+kind, got, attrs}}:
      mapped_checked(Bool.and(U32.is_eq(kind, 257), Stun.same(got, transaction, True{})),
        Stun.Packet{kind, [], attrs})

def response_checked(ok: Bool, raw: List<&2, U32>, transaction: List<&2, U32>,
                     key: List<&2, U32>, mode: Auth.Mode) -> Maybe<&2, Stun.IPv4>:
  match ok:
    case True{}:
      mapped(Auth.authenticate_response(raw, key, mode), transaction)
    case False{}:
      None{}

# Integrity, required ICE fingerprint, transaction and success class precede
# address decoding. Auth.authenticate_response supplies only protected attrs.
def response(+raw: List<&2, U32>, transaction: List<&2, U32>,
             key: List<&2, U32>, mode: Auth.Mode) -> Maybe<&2, Stun.IPv4>:
  response_checked(Fingerprint.verify(raw), raw, transaction, key, mode)
