import Base
import ./stun.bend as Stun
import ./stun_integrity.bend as Integrity
import ./stun_fingerprint.bend as Fingerprint
import ../crypto/hmac_sha1.bend as Hmac
import ../crypto/bytes.bend as B

# Append legacy MESSAGE-INTEGRITY and FINGERPRINT to a valid STUN message.
# The caller provides the prepared short-term or long-term credential key.
def ordinary(kind: U32) -> Bool:
  match kind:
    case 8:
      False{}
    case 28:
      False{}
    case 32808:
      False{}
    case _:
      True{}

def unsigned(attrs: List<&2, Stun.Attribute>, ok: Bool) -> Bool:
  match attrs:
    case Nil{}:
      ok
    case Con{Stun.Attribute{+kind, _}, tail}:
      unsigned(tail, Bool.and(ok, ordinary(kind)))

def word_bytes(+x: U32, tail: List<&2, U32>) -> List<&2, U32>:
  Con{U32.and(U32.shrn(x, 24n), 255),
    Con{U32.and(U32.shrn(x, 16n), 255),
      Con{U32.and(U32.shrn(x, 8n), 255), Con{U32.and(x, 255), tail}}}}

def sealed(mac: Maybe<&2, List<&2, U32>>, prefix: List<&2, U32>, +body_length: Nat) -> Maybe<&2, List<&2, U32>>:
  match mac:
    case None{}:
      None{}
    case Some{bytes}:
      with_mac = B.append(prefix, B.append([0, 8, 0, 20], bytes))
      +full_prefix = Integrity.adjusted(with_mac, Nat.add(body_length, 32n))
      Some{B.append(full_prefix, B.append([128, 40, 0, 4],
        word_bytes(Fingerprint.value(full_prefix), [])))}

def with_header(raw: List<&2, U32>, key: List<&2, U32>, +body_length: Nat) -> Maybe<&2, List<&2, U32>>:
  +prefix = Integrity.adjusted(raw, Nat.add(body_length, 24n))
  sealed(Hmac.digest(key, prefix), prefix, body_length)

def checked(ok: Bool, raw: List<&2, U32>, key: List<&2, U32>, +body_length: Nat) -> Maybe<&2, List<&2, U32>>:
  match ok:
    case True{}:
      with_header(raw, key, body_length)
    case False{}:
      None{}

def with_packet(packet: Maybe<&2, Stun.Packet>, +raw: List<&2, U32>, key: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match packet:
    case None{}:
      None{}
    case Some{Stun.Packet{_, _, attrs}}:
      +body_length = Nat.sub(B.length(raw), 20n)
      checked(Bool.and(unsigned(attrs, True{}), Nat.is_le(body_length, 65500n)),
        raw, key, body_length)

def sign(+raw: List<&2, U32>, key: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  with_packet(Stun.parse(raw), raw, key)
