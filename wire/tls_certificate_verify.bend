import Base
import ../crypto/bytes.bend as B
import ../crypto/sha256.bend as H
import ../crypto/ecdsa_scheme256.bend as E
import ../crypto/rsa_signature256.bend as R
import ../crypto/rsa_private.bend as S
import ../crypto/x509_public_key.bend as K
import ../crypto/x509_algorithm.bend as A

# TLS 1.3 CertificateVerify, RFC 9846/8446 section 4.4.3. The caller owns
# transcript ordering and signature-scheme negotiation. This profile admits
# ecdsa_secp256r1_sha256 and rsa_pss_rsae_sha256, never PKCS#1 v1.5 here.
type Role is Data:
  Server{}
  Client{}

type EcdsaPrivate is Type:
  EcdsaPrivate{scalar: List<&2, U32>}

def context(role: Role) -> List<&2, U32>:
  match role:
    case Server{}:
      [84, 76, 83, 32, 49, 46, 51, 44, 32, 115, 101, 114, 118, 101, 114, 32,
       67, 101, 114, 116, 105, 102, 105, 99, 97, 116, 101, 86, 101, 114, 105, 102, 121]
    case Client{}:
      [84, 76, 83, 32, 49, 46, 51, 44, 32, 99, 108, 105, 101, 110, 116, 32,
       67, 101, 114, 116, 105, 102, 105, 99, 97, 116, 101, 86, 101, 114, 105, 102, 121]

def content.checked(valid: Bool, role: Role, hash: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match valid:
    case False{}: None{}
    case True{}:
      Some{B.append(List.replicate(U32, 64n, 32), B.append(context(role), Con{0, hash}))}

def content(role: Role, +transcript_hash: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  content.checked(Bool.and(Nat.is_eq(B.length(transcript_hash), 32n), B.valid(transcript_hash)), role, transcript_hash)

def digest.content(value: Maybe<&2, List<&2, U32>>) -> Maybe<&2, List<&2, U32>>:
  match value:
    case None{}: None{}
    case Some{bytes}: H.digest(bytes)

def digest(role: Role, transcript_hash: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  digest.content(content(role, transcript_hash))

def sign_ecdsa.digest(owner: EcdsaPrivate, value: Maybe<&2, List<&2, U32>>) -> Maybe<&1, List<&2, U32>>:
  match owner value:
    case EcdsaPrivate{private} Some{hash}: E.sign_digest(private, hash)
    case _ _: None{}

# Every result consumes the key wrapper, including invalid transcript input.
# ECDSA uses RFC 6979; no host nonce or additional RNG draw is required.
def sign_ecdsa(owner: EcdsaPrivate, role: Role, transcript_hash: List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  sign_ecdsa.digest(owner, digest(role, transcript_hash))

def verify_ecdsa.digest(peer: List<&2, U32>, signature: List<&2, U32>, value: Maybe<&2, List<&2, U32>>) -> Bool:
  match value:
    case None{}: False{}
    case Some{hash}: E.verify_digest(peer, hash, signature)

def verify_ecdsa(peer: List<&2, U32>, role: Role, transcript_hash: List<&2, U32>, signature: List<&2, U32>) -> Bool:
  verify_ecdsa.digest(peer, signature, digest(role, transcript_hash))

def sign_rsa.digest(owner: S.Private, salt: List<&2, U32>, blind: List<&2, U32>, value: Maybe<&2, List<&2, U32>>) -> Maybe<&1, List<&2, U32>>:
  match value:
    case None{}: None{}
    case Some{hash}: S.sign_digest(owner, hash, salt, blind)

# Exactly 32 fresh salt bytes and k fresh blinding bytes are supplied by the
# credential/connection owner. Rejected blinding consumes this key owner too;
# abort or retry using a freshly imported owner and fresh host RNG draws.
def sign_rsa(owner: S.Private, role: Role, transcript_hash: List<&2, U32>, salt: List<&2, U32>, blind: List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  sign_rsa.digest(owner, salt, blind, digest(role, transcript_hash))

def verify_rsa.digest(modulus: List<&2, U32>, exponent: List<&2, U32>, signature: List<&2, U32>, value: Maybe<&2, List<&2, U32>>) -> Bool:
  match value:
    case None{}: False{}
    case Some{hash}: R.verify_pss_digest(modulus, exponent, hash, signature)

def verify_rsa(modulus: List<&2, U32>, exponent: List<&2, U32>, role: Role, transcript_hash: List<&2, U32>, signature: List<&2, U32>) -> Bool:
  verify_rsa.digest(modulus, exponent, signature, digest(role, transcript_hash))

# Protocol-facing verification binds the negotiated scheme to the authenticated
# leaf's admitted SPKI algorithm. In particular PSS-only SPKI is ineligible for
# rsa_pss_rsae_sha256 even when its raw RSA mathematics would verify.
# The raw verify_rsa helper above is mathematical only; M3 uses this dispatcher.
def verify(scheme: U32, key: K.PublicKey, role: Role, transcript_hash: List<&2, U32>, signature: List<&2, U32>) -> Bool:
  match scheme key:
    case 1027 K.P256{encoded}: verify_ecdsa(encoded, role, transcript_hash, signature)
    case 2052 K.Rsa{A.Rsa{}, modulus, exponent}: verify_rsa(modulus, exponent, role, transcript_hash, signature)
    case _ _: False{}
