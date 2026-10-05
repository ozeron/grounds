import Base
import ../crypto/bytes.bend as B
import ../crypto/hkdf.bend as H
import ../crypto/hmac.bend as M
import ../crypto/traffic.bend as T

# TLS 1.3 SHA-256 certificate/ECDHE schedule, with no PSK (RFC 9846 7.1).
# The caller supplies validated key-agreement output and exact transcript hashes.
# These stages do not authenticate a certificate, negotiate parameters, validate
# handshake order or authorize application data. Logical consumption is not
# physical secret erasure; native/runtime/JIT review remains required.

type ToApplication is Type:
  ToApplication{secret: List<&2, U32>}

type FinishedKey is Type:
  FinishedKey{key: List<&2, U32>}

type HandshakeTraffic is Type:
  HandshakeTraffic{client: List<&2, U32>, server: List<&2, U32>}

type ApplicationTraffic is Type:
  ApplicationTraffic{client: List<&2, U32>, server: List<&2, U32>}

type Handshake is Type:
  Handshake{next: ToApplication, traffic: HandshakeTraffic,
            client_finished: FinishedKey, server_finished: FinishedKey}

def bytes32(+bytes: List<&2, U32>) -> Bool:
  Bool.and(Nat.is_eq(B.length(bytes), 32n), B.valid(bytes))

def zeros() -> List<&2, U32>:
  List.replicate(U32, 32n, 0)

# SHA-256 of the empty message, used by Derive-Secret("derived", "").
def empty_hash() -> List<&2, U32>:
  [227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36,
   39, 174, 65, 228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85]

def derived_label() -> List<&2, U32>:
  [100, 101, 114, 105, 118, 101, 100]

def finished_label() -> List<&2, U32>:
  [102, 105, 110, 105, 115, 104, 101, 100]

def client_handshake_label() -> List<&2, U32>:
  [99, 32, 104, 115, 32, 116, 114, 97, 102, 102, 105, 99]

def server_handshake_label() -> List<&2, U32>:
  [115, 32, 104, 115, 32, 116, 114, 97, 102, 102, 105, 99]

def client_application_label() -> List<&2, U32>:
  [99, 32, 97, 112, 32, 116, 114, 97, 102, 102, 105, 99]

def server_application_label() -> List<&2, U32>:
  [115, 32, 97, 112, 32, 116, 114, 97, 102, 102, 105, 99]

def derive_valid(valid: Bool, secret: List<&2, U32>, label: List<&2, U32>, hash: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match valid:
    case False{}: None{}
    case True{}: T.expand_label(secret, label, hash, 32n)

def derive(secret: List<&2, U32>, label: List<&2, U32>, +hash: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  derive_valid(bytes32(hash), secret, label, hash)

def extracted(ikm: List<&2, U32>, salt: Maybe<&2, List<&2, U32>>) -> Maybe<&2, List<&2, U32>>:
  match salt:
    case None{}: None{}
    case Some{salt}: H.extract(salt, ikm)

def next_secret(secret: List<&2, U32>, ikm: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  extracted(ikm, derive(secret, derived_label(), empty_hash()))

def handshake_finished(next: ToApplication, traffic: HandshakeTraffic,
                       client: Maybe<&2, List<&2, U32>>, server: Maybe<&2, List<&2, U32>>) -> Maybe<&1, Handshake>:
  match client server:
    case Some{c} Some{s}:
      Some{Handshake{next, traffic, FinishedKey{c}, FinishedKey{s}}}
    case _ _: None{}

def handshake_traffic(next: ToApplication, client: Maybe<&2, List<&2, U32>>, server: Maybe<&2, List<&2, U32>>) -> Maybe<&1, Handshake>:
  match client server:
    case Some{+c} Some{+s}:
      handshake_finished(next, HandshakeTraffic{c, s},
        T.expand_label(c, finished_label(), [], 32n), T.expand_label(s, finished_label(), [], 32n))
    case _ _: None{}

def handshake_secret(+hash: List<&2, U32>, value: Maybe<&2, List<&2, U32>>) -> Maybe<&1, Handshake>:
  match value:
    case None{}: None{}
    case Some{+secret}:
      handshake_traffic(ToApplication{secret}, derive(secret, client_handshake_label(), hash),
        derive(secret, server_handshake_label(), hash))

def early(shared: List<&2, U32>, hash: List<&2, U32>, value: Maybe<&2, List<&2, U32>>) -> Maybe<&1, Handshake>:
  match value:
    case None{}: None{}
    case Some{secret}: handshake_secret(hash, next_secret(secret, shared))

def start_valid(valid: Bool, shared: List<&2, U32>, hash: List<&2, U32>) -> Maybe<&1, Handshake>:
  match valid:
    case False{}: None{}
    case True{}: early(shared, hash, H.extract(zeros(), zeros()))

def start(+shared: List<&2, U32>, +hello_hash: List<&2, U32>) -> Maybe<&1, Handshake>:
  start_valid(Bool.and(bytes32(shared), bytes32(hello_hash)), shared, hello_hash)

def application_pair(client: Maybe<&2, List<&2, U32>>, server: Maybe<&2, List<&2, U32>>) -> Maybe<&1, ApplicationTraffic>:
  match client server:
    case Some{c} Some{s}: Some{ApplicationTraffic{c, s}}
    case _ _: None{}

def application_main(+hash: List<&2, U32>, value: Maybe<&2, List<&2, U32>>) -> Maybe<&1, ApplicationTraffic>:
  match value:
    case None{}: None{}
    case Some{+secret}:
      application_pair(derive(secret, client_application_label(), hash),
        derive(secret, server_application_label(), hash))

def application(owner: ToApplication, server_finished_hash: List<&2, U32>) -> Maybe<&1, ApplicationTraffic>:
  match owner:
    case ToApplication{secret}: application_main(server_finished_hash, next_secret(secret, zeros()))

def finished_valid(valid: Bool, key: List<&2, U32>, hash: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match valid:
    case False{}: None{}
    case True{}: M.digest(key, hash)

def finished(owner: FinishedKey, +transcript_hash: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match owner:
    case FinishedKey{+key}:
      finished_valid(Bool.and(bytes32(key), bytes32(transcript_hash)), key, transcript_hash)

# All 32 admitted tag bytes contribute to the difference. This source-level
# accumulator does not establish constant-time behavior of generated code.
def difference(expected: List<&2, U32>, supplied: List<&2, U32>, acc: U32) -> U32:
  match expected supplied:
    case Nil{} Nil{}: acc
    case Con{a, at} Con{b, bt}: difference(at, bt, U32.or(acc, U32.xor(a, b)))
    case _ _: 1

def verify_valid(valid: Bool, expected: List<&2, U32>, supplied: List<&2, U32>) -> Bool:
  match valid:
    case False{}: False{}
    case True{}: U32.is_eq(difference(expected, supplied, 0), 0)

def verify_result(expected: Maybe<&2, List<&2, U32>>, +supplied: List<&2, U32>) -> Bool:
  match expected:
    case None{}: False{}
    case Some{tag}: verify_valid(bytes32(supplied), tag, supplied)

def verify_finished(owner: FinishedKey, transcript_hash: List<&2, U32>, supplied: List<&2, U32>) -> Bool:
  verify_result(finished(owner, transcript_hash), supplied)
