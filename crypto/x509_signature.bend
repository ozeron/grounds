import Base
import ./x509_certificate.bend as C
import ./x509_public_key.bend as K
import ./x509_algorithm.bend as A
import ./sha256.bend as H
import ./sha384.bend as H384
import ./sha512.bend as H512
import ./rsa_signature256.bend as R
import ./rsa_signature_sha2.bend as R2
import ./rsa_encoding_sha2.bend as RE
import ./ecdsa256.bend as E
import ./ecdsa384.bend as E384
import ./ecdsa_der256.bend as ED
import ./ecdsa_der384.bend as ED384

# Mathematical issuer signature check only. Names, time, constraints, trust
# and issuer selection remain the independent chain verifier's responsibility.
def signed_bytes(tbs: C.Tbs) -> List<&2, U32>:
  match tbs:
    case C.Tbs{C.Header{encoded, _, _, _}, _, _}: encoded

def digest(algorithm: A.Signature, bytes: List<&2,U32>) -> Maybe<&2,List<&2,U32>>:
  match algorithm:
    case A.Ecdsa384{}: H384.digest(bytes)
    case A.RsaPss384{_}: H384.digest(bytes)
    case A.RsaV15384{}: H384.digest(bytes)
    case A.RsaPss512{_}: H512.digest(bytes)
    case A.RsaV15512{}: H512.digest(bytes)
    case _: H.digest(bytes)

def rsa.digest(algorithm: A.Signature, modulus: List<&2,U32>, exponent: List<&2,U32>,
  signature: List<&2,U32>, digest: Maybe<&2,List<&2,U32>>) -> Bool:
  match algorithm digest:
    case A.RsaPss256{} Some{digest}: R.verify_pss_digest(modulus, exponent, digest, signature)
    case A.RsaV15256{} Some{digest}: R.verify_v15_digest(modulus, exponent, digest, signature)
    case A.RsaPss384{salt} Some{digest}: R2.verify_pss_digest(U32.to_nat(salt), RE.Sha384{}, modulus, exponent, digest, signature)
    case A.RsaPss512{salt} Some{digest}: R2.verify_pss_digest(U32.to_nat(salt), RE.Sha512{}, modulus, exponent, digest, signature)
    case A.RsaV15384{} Some{digest}: R2.verify_v15_digest(RE.Sha384{}, modulus, exponent, digest, signature)
    case A.RsaV15512{} Some{digest}: R2.verify_v15_digest(RE.Sha512{}, modulus, exponent, digest, signature)
    case _ _: False{}

def rsa.checked(valid: Bool, +algorithm: A.Signature, modulus: List<&2,U32>, exponent: List<&2,U32>,
  tbs: C.Tbs, signature: List<&2,U32>) -> Bool:
  match valid:
    case True{}: rsa.digest(algorithm, modulus, exponent, signature, digest(algorithm, signed_bytes(tbs)))
    case False{}: False{}

def ec.decoded(large: Bool, peer: List<&2,U32>, digest: List<&2,U32>, signature: Maybe<&1,List<&2,U32>>) -> Bool:
  match large signature:
    case False{} Some{signature}:
      # SEC1 bits2int: the leftmost 256 bits, even for SHA-384.
      E.verify_digest(peer, List.take(&2,U32,digest,32n), signature)
    case True{} Some{signature}: E384.verify_digest(peer, digest, signature)
    case _ _: False{}

def ec.digest(+large: Bool, peer: List<&2,U32>, +signature: List<&2,U32>, digest: Maybe<&2,List<&2,U32>>) -> Bool:
  match digest:
    case Some{digest}:
      ec.decoded(large, peer, digest, Bool.pick(Maybe<&1,List<&2,U32>>, large, ED384.decode(signature), ED.decode(signature)))
    case None{}: False{}

def ec.checked(valid: Bool, large: Bool, algorithm: A.Signature, peer: List<&2,U32>, tbs: C.Tbs, signature: List<&2,U32>) -> Bool:
  match valid:
    case True{}: ec.digest(large, peer, signature, digest(algorithm,signed_bytes(tbs)))
    case False{}: False{}

def verify_decoded(issuer: Maybe<&1,K.PublicKey>, certificate: Maybe<&1,C.Certificate>) -> Bool:
  match issuer certificate:
    case Some{K.Rsa{+key_algorithm,modulus,exponent}} Some{C.Certificate{tbs,+algorithm,signature}}:
      rsa.checked(A.compatible(key_algorithm,algorithm),algorithm,modulus,exponent,tbs,signature)
    case Some{K.P256{peer}} Some{C.Certificate{tbs,+algorithm,signature}}:
      ec.checked(A.compatible(A.P256{},algorithm),False{},algorithm,peer,tbs,signature)
    case Some{K.P384{peer}} Some{C.Certificate{tbs,+algorithm,signature}}:
      ec.checked(A.compatible(A.P384{},algorithm),True{},algorithm,peer,tbs,signature)
    case _ _: False{}

def verify_signature(issuer_spki: List<&2,U32>, certificate: List<&2,U32>) -> Bool:
  verify_decoded(K.decode(issuer_spki),C.decode(certificate))
