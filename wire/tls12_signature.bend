import Base
import ../crypto/bytes.bend as B
import ../crypto/sha256.bend as H
import ../crypto/sha384.bend as H384
import ../crypto/sha512.bend as H512
import ../crypto/ecdsa384.bend as E384
import ../crypto/ecdsa_der384.bend as ED384
import ../crypto/ecdsa_scheme256.bend as E
import ../crypto/rsa_encoding_sha2.bend as RE
import ../crypto/rsa_signature_sha2.bend as R2
import ../crypto/rsa_signature256.bend as R
import ../crypto/x509_public_key.bend as K
import ../crypto/x509_algorithm.bend as A

# TLS 1.2 ServerKeyExchange signatures (RFC 5246 7.4.3, RFC 8422 5.4,
# RFC 8446 4.2.3 for the PSS code points). The signed content is
# client_random || server_random || ServerECDHParams, hashed with the
# scheme's hash. TLS 1.2 ECDSA schemes name a hash, not a curve: the curve
# is the leaf key's (P-256 or P-384), with the FIPS 186 leftmost-bits rule
# for a longer digest. RSA keys must be rsaEncryption SPKI (never PSS-only)
# and may sign PKCS#1 v1.5 or RSAE-PSS; PKCS#1 v1.5 is accepted here only,
# never for TLS 1.3 CertificateVerify.

def offered() -> List<&2,U32>:
  [1027,2052,1283,2053,2054,1025,1281,1537]

def ecdsa_scheme(+scheme: U32) -> Bool:
  Bool.or(U32.is_eq(scheme,1027),U32.is_eq(scheme,1283))

def rsa_scheme(+scheme: U32) -> Bool:
  Bool.or(Bool.or(U32.is_eq(scheme,2052),Bool.or(U32.is_eq(scheme,2053),U32.is_eq(scheme,2054))),
    Bool.or(U32.is_eq(scheme,1025),Bool.or(U32.is_eq(scheme,1281),U32.is_eq(scheme,1537))))

def first32(left: Nat, bytes: List<&2,U32>) -> List<&2,U32>:
  List.take(&2,U32,bytes,left)

def digest(+scheme: U32, +content: List<&2,U32>) -> Maybe<&2,List<&2,U32>>:
  Bool.pick(Maybe<&2,List<&2,U32>>,Bool.or(U32.is_eq(scheme,1027),Bool.or(U32.is_eq(scheme,2052),U32.is_eq(scheme,1025))),H.digest(content),
    Bool.pick(Maybe<&2,List<&2,U32>>,Bool.or(U32.is_eq(scheme,1283),Bool.or(U32.is_eq(scheme,2053),U32.is_eq(scheme,1281))),H384.digest(content),H512.digest(content)))

# P-256: a 48-byte SHA-384 digest is truncated to its leftmost 32 bytes.
def p256(encoded: List<&2,U32>, signature: List<&2,U32>, value: Maybe<&2,List<&2,U32>>) -> Bool:
  match value:
    case None{}: False{}
    case Some{digest}: E.verify_digest(encoded,first32(32n,digest),signature)

def p384.decoded(encoded: List<&2,U32>, digest: List<&2,U32>, signature: Maybe<&1,List<&2,U32>>) -> Bool:
  match signature:
    case None{}: False{}
    case Some{signature}: E384.verify_digest(encoded,digest,signature)

# P-384: a 32-byte SHA-256 digest is the same integer left-padded to 48 bytes.
def p384(encoded: List<&2,U32>, signature: List<&2,U32>, value: Maybe<&2,List<&2,U32>>) -> Bool:
  match value:
    case None{}: False{}
    case Some{+digest}: p384.decoded(encoded,B.append(List.replicate(U32,Nat.sub(48n,B.length(digest)),0),digest),ED384.decode(signature))

def rsa.digest(scheme: U32, modulus: List<&2,U32>, exponent: List<&2,U32>, signature: List<&2,U32>, digest: List<&2,U32>) -> Bool:
  match scheme:
    case 2052: R.verify_pss_digest(modulus,exponent,digest,signature)
    case 2053: R2.verify_pss_digest(48n,RE.Sha384{},modulus,exponent,digest,signature)
    case 2054: R2.verify_pss_digest(64n,RE.Sha512{},modulus,exponent,digest,signature)
    case 1025: R.verify_v15_digest(modulus,exponent,digest,signature)
    case 1281: R2.verify_v15_digest(RE.Sha384{},modulus,exponent,digest,signature)
    case 1537: R2.verify_v15_digest(RE.Sha512{},modulus,exponent,digest,signature)
    case _: False{}

def rsa(scheme: U32, modulus: List<&2,U32>, exponent: List<&2,U32>, signature: List<&2,U32>, value: Maybe<&2,List<&2,U32>>) -> Bool:
  match value:
    case None{}: False{}
    case Some{digest}: rsa.digest(scheme,modulus,exponent,signature,digest)

def content(client: List<&2,U32>, server: List<&2,U32>, params: List<&2,U32>) -> List<&2,U32>:
  B.append(client,B.append(server,params))

# The caller has already bound the scheme to the offered list and the suite's
# authentication algorithm; a scheme/key mismatch still verifies as False.
def verify(+scheme: U32, key: K.PublicKey, signed: List<&2,U32>, signature: List<&2,U32>) -> Bool:
  match key:
    case K.P256{encoded}: Bool.and(ecdsa_scheme(scheme),p256(encoded,signature,digest(scheme,signed)))
    case K.P384{encoded}: Bool.and(ecdsa_scheme(scheme),p384(encoded,signature,digest(scheme,signed)))
    case K.Rsa{A.Rsa{},modulus,exponent}: Bool.and(rsa_scheme(scheme),rsa(scheme,modulus,exponent,signature,digest(scheme,signed)))
    case _: False{}
