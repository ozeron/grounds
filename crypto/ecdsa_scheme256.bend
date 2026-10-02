import Base
import ./ecdsa256.bend as E
import ./ecdsa_sign256.bend as S
import ./ecdsa_der256.bend as D

# P-256/SHA-256 ECDSA digest API with strict DER signatures. The SHA-256
# digest is exactly 32 bytes; private scalars and public keys use the P-256
# module's validated BE32 and uncompressed SEC1 profiles respectively.
# These pure functions still require the documented runtime/erasure review
# before live-secret use and the separate TLS certificate/handshake owner.

def verify.decoded(peer: List<&2, U32>, digest: List<&2, U32>, signature: Maybe<&1, List<&2, U32>>) -> Bool:
  match signature:
    case None{}:
      False{}
    case Some{signature}:
      E.verify_digest(peer, digest, signature)

def verify_digest(peer: List<&2, U32>, digest: List<&2, U32>, signature: List<&2, U32>) -> Bool:
  verify.decoded(peer, digest, D.decode(signature))

def sign.encoded(signature: Maybe<&1, List<&2, U32>>) -> Maybe<&1, List<&2, U32>>:
  match signature:
    case None{}:
      None{}
    case Some{signature}:
      Some{D.encode(signature)}

def sign_digest(private: List<&2, U32>, digest: List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  sign.encoded(S.sign_digest(private, digest))
