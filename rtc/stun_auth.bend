import Base
import ./stun.bend as Stun
import ./stun_integrity.bend as LegacyIntegrity
import ./stun_sign.bend as LegacySign
import ./stun_fingerprint.bend as Fingerprint
import ../crypto/hmac_sha1.bend as Sha1
import ../crypto/hmac.bend as Sha256Hmac
import ../crypto/bytes.bend as B

# An external agreement can select one algorithm; otherwise send both.
type Mode is Data:
  Legacy{}
  Sha256{}
  Dual{}

type Mac is Data:
  Missing{}
  Mac{offset: Nat, bytes: List<&2, U32>}

type Layout is Data:
  Layout{legacy: Mac, sha256: Mac, attributes: List<&2, Stun.Attribute>, fingerprint: Bool}

def width(+value: List<&2, U32>) -> Nat:
  +length = B.length(value)
  Nat.add(4n, Nat.mul(Nat.div(Nat.add(length, 3n), 4n), 4n))

# phase 0: ordinary attributes; 1: SHA-1; 2: SHA-256.
# Ordinary attributes after the first integrity attribute are ignored (9).
# Offsets still include their original wire bytes for subsequent HMACs.
def layout_checked(ok: Bool, next: Unit -> Maybe<&2, Layout>) -> Maybe<&2, Layout>:
  match ok:
    case True{}:
      next(Unit{})
    case False{}:
      None{}

def layout(attrs: List<&2, Stun.Attribute>, +offset: Nat, +phase: U32,
           legacy: Mac, sha256: Mac, +protected: List<&2, Stun.Attribute>) -> Maybe<&2, Layout>:
  match attrs:
    case Nil{}:
      Some{Layout{legacy, sha256, List.reverse(&2, Stun.Attribute, protected), False{}}}
    case Con{Stun.Attribute{8, +value}, tail}:
      layout_checked(Bool.and(U32.is_eq(phase, 0), Nat.is_eq(B.length(value), 20n)),
        _ => layout(tail, Nat.add(offset, 24n), 1, Mac{offset, value}, sha256, protected))
    case Con{Stun.Attribute{28, +value}, tail}:
      layout_checked(Bool.and(U32.is_le(phase, 1), Nat.is_eq(B.length(value), 32n)),
        _ => layout(tail, Nat.add(offset, 36n), 2, legacy, Mac{offset, value}, protected))
    case Con{Stun.Attribute{32808, [_, _, _, _]}, Nil{}}:
      Some{Layout{legacy, sha256, List.reverse(&2, Stun.Attribute, protected), True{}}}
    case Con{Stun.Attribute{32808, _}, _}:
      None{}
    case Con{Stun.Attribute{+kind, +value}, tail}:
      layout(tail, Nat.add(offset, width(value)), phase, legacy, sha256,
        Bool.pick(List<&2, Stun.Attribute>, U32.is_eq(phase, 0),
          Con{Stun.Attribute{kind, value}, protected}, protected))

def selected(mode: Mode, legacy: Mac, sha256: Mac) -> Mac:
  match mode sha256:
    case Legacy{} Missing{}:
      legacy
    case Legacy{} Mac{_, _}:
      Missing{}
    case Sha256{} _:
      sha256
    case Dual{} Missing{}:
      legacy
    case Dual{} _:
      sha256

def digest(mode: Mode, key: List<&2, U32>, bytes: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match mode:
    case Legacy{}:
      Sha1.digest(key, bytes)
    case _:
      Sha256Hmac.digest(key, bytes)

def mac_input(t: Stun.Taken, +length: Nat) -> Maybe<&2, List<&2, U32>>:
  match t:
    case Stun.Took{prefix, _}:
      Some{LegacyIntegrity.adjusted(prefix, length)}
    case Stun.Short{}:
      None{}

def check_input(input: Maybe<&2, List<&2, U32>>, key: List<&2, U32>,
                expected: List<&2, U32>, mode: Mode) -> Bool:
  match input:
    case None{}:
      False{}
    case Some{bytes}:
      LegacyIntegrity.compare(digest(mode, key, bytes), expected)

def check_mac(mac: Mac, raw: List<&2, U32>, key: List<&2, U32>, mode: Mode) -> Bool:
  match mac:
    case Missing{}:
      False{}
    case Mac{+offset, +bytes}:
      check_input(mac_input(Stun.take(raw, Nat.add(20n, offset), []),
        Nat.add(offset, Nat.add(4n, B.length(bytes)))), key, bytes, mode)

def algorithm(sha256: Mac) -> Mode:
  match sha256:
    case Missing{}:
      Legacy{}
    case _:
      Sha256{}

def one_mac(legacy: Mac, sha256: Mac) -> Bool:
  match legacy sha256:
    case Mac{_, _} Mac{_, _}:
      False{}
    case _ _:
      True{}

def response_attrs(attrs: List<&2, Stun.Attribute>, ok: Bool) -> Bool:
  match attrs:
    case Nil{}:
      ok
    case Con{Stun.Attribute{6, _}, tail}:
      response_attrs(tail, False{})
    case Con{_, tail}:
      response_attrs(tail, ok)

def authenticated(ok: Bool, +kind: U32, transaction: List<&2, U32>,
                  attrs: List<&2, Stun.Attribute>) -> Maybe<&2, Stun.Packet>:
  match ok:
    case True{}:
      Some{Stun.Packet{kind, transaction, attrs}}
    case False{}:
      None{}

def with_layout(found: Maybe<&2, Layout>, +raw: List<&2, U32>, key: List<&2, U32>,
                mode: Mode, response: Bool, +kind: U32, transaction: List<&2, U32>) -> Maybe<&2, Stun.Packet>:
  match found:
    case None{}:
      None{}
    case Some{Layout{+legacy, +sha256, +attrs, fingerprint}}:
      authenticated(Bool.and(Bool.and(
        check_mac(selected(mode, legacy, sha256), raw, key, algorithm(sha256)),
        Bool.pick(Bool, fingerprint, Fingerprint.verify(raw), True{})),
        Bool.pick(Bool, response, Bool.and(one_mac(legacy, sha256),
          Bool.and(U32.is_eq(U32.and(kind, 256), 256), response_attrs(attrs, True{}))), True{})), kind, transaction, attrs)

def with_packet(parsed: Maybe<&2, Stun.Packet>, raw: List<&2, U32>, key: List<&2, U32>,
                mode: Mode, response: Bool) -> Maybe<&2, Stun.Packet>:
  match parsed:
    case None{}:
      None{}
    case Some{Stun.Packet{+kind, transaction, attrs}}:
      with_layout(layout(attrs, 0n, 0, Missing{}, Missing{}, []), raw, key,
        mode, response, kind, transaction)

# Returns only the ordinary attributes preceding the first integrity field.
# The caller supplies a prepared credential key. No Unicode/key derivation here.
def authenticate(+raw: List<&2, U32>, key: List<&2, U32>, mode: Mode) -> Maybe<&2, Stun.Packet>:
  with_packet(Stun.parse(raw), raw, key, mode, False{})

# RFC 8489 9.1.3: a response uses exactly one integrity algorithm.
def authenticate_response(+raw: List<&2, U32>, key: List<&2, U32>, mode: Mode) -> Maybe<&2, Stun.Packet>:
  with_packet(Stun.parse(raw), raw, key, mode, True{})

def present(packet: Maybe<&2, Stun.Packet>) -> Bool:
  match packet:
    case Some{_}:
      True{}
    case None{}:
      False{}

def verify(raw: List<&2, U32>, key: List<&2, U32>, mode: Mode) -> Bool:
  present(authenticate(raw, key, mode))

def appended(mac: Maybe<&2, List<&2, U32>>, prefix: List<&2, U32>,
             +kind: U32, +size: U32) -> Maybe<&2, List<&2, U32>>:
  match mac:
    case None{}:
      None{}
    case Some{bytes}:
      Some{B.append(prefix, B.append([0, kind, 0, size], bytes))}

def mac_kind(mode: Mode) -> U32:
  match mode:
    case Legacy{}:
      8
    case _:
      28

def mac_size(mode: Mode) -> U32:
  match mode:
    case Legacy{}:
      20
    case _:
      32

def append_mac(+raw: List<&2, U32>, key: List<&2, U32>, +mode: Mode) -> Maybe<&2, List<&2, U32>>:
  +kind = mac_kind(mode)
  +size = mac_size(mode)
  +prefix = LegacyIntegrity.adjusted(raw, Nat.add(Nat.sub(B.length(raw), 20n),
    Nat.add(4n, U32.to_nat(size))))
  appended(digest(mode, key, prefix), prefix, kind, size)

def second(first: Maybe<&2, List<&2, U32>>, key: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match first:
    case None{}:
      None{}
    case Some{bytes}:
      append_mac(bytes, key, Sha256{})

def overhead(mode: Mode) -> Nat:
  match mode:
    case Legacy{}:
      24n
    case Sha256{}:
      36n
    case Dual{}:
      60n

def seal_checked(ok: Bool, raw: List<&2, U32>, +key: List<&2, U32>, mode: Mode) -> Maybe<&2, List<&2, U32>>:
  match ok:
    case False{}:
      None{}
    case True{}:
      match mode:
        case Dual{}:
          second(append_mac(raw, key, Legacy{}), key)
        case _:
          append_mac(raw, key, mode)

def seal_packet(parsed: Maybe<&2, Stun.Packet>, +raw: List<&2, U32>, key: List<&2, U32>, +mode: Mode) -> Maybe<&2, List<&2, U32>>:
  match parsed:
    case None{}:
      None{}
    case Some{Stun.Packet{_, _, attrs}}:
      seal_checked(Bool.and(LegacySign.unsigned(attrs, True{}),
        Nat.is_le(Nat.add(Nat.sub(B.length(raw), 20n), overhead(mode)), 65532n)), raw, key, mode)

# Seal can produce STUN usages without FINGERPRINT, including the RFC vector.
def seal(+raw: List<&2, U32>, key: List<&2, U32>, mode: Mode) -> Maybe<&2, List<&2, U32>>:
  seal_packet(Stun.parse(raw), raw, key, mode)

def fingerprint_checked(ok: Bool, +raw: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match ok:
    case False{}:
      None{}
    case True{}:
      +prefix = LegacyIntegrity.adjusted(raw, Nat.sub(B.length(raw), 12n))
      Some{B.append(prefix, B.append([128, 40, 0, 4], LegacySign.word_bytes(Fingerprint.value(prefix), [])))}

def fingerprint(sealed: Maybe<&2, List<&2, U32>>) -> Maybe<&2, List<&2, U32>>:
  match sealed:
    case None{}:
      None{}
    case Some{+raw}:
      fingerprint_checked(Nat.is_le(B.length(raw), 65544n), raw)

# ICE always uses a final FINGERPRINT, after SHA-1 then SHA-256 when dual.
def sign(raw: List<&2, U32>, key: List<&2, U32>, mode: Mode) -> Maybe<&2, List<&2, U32>>:
  fingerprint(seal(raw, key, mode))
