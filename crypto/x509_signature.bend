import Base
import ./x509_certificate.bend as C
import ./x509_public_key.bend as K
import ./x509_algorithm.bend as A
import ./sha256.bend as H
import ./rsa_signature256.bend as R
import ./ecdsa256.bend as E
import ./ecdsa_der256.bend as ED

# Mathematical issuer signature check only. This does not establish names,
# time validity, constraints, issuer selection, trust, or TLS admission.
def signed_bytes(tbs: C.Tbs) -> List<&2, U32>:
  match tbs:
    case C.Tbs{C.Header{encoded, _, _, _}, _, _}:
      encoded

def rsa.digest(algorithm: A.Signature, modulus: List<&2, U32>, exponent: List<&2, U32>,
               signature: List<&2, U32>, digest: Maybe<&2, List<&2, U32>>) -> Bool:
  match algorithm digest:
    case A.RsaPss256{} Some{digest}:
      R.verify_pss_digest(modulus, exponent, digest, signature)
    case A.RsaV15256{} Some{digest}:
      R.verify_v15_digest(modulus, exponent, digest, signature)
    case _ _:
      False{}

def rsa.checked(valid: Bool, algorithm: A.Signature, modulus: List<&2, U32>, exponent: List<&2, U32>,
                tbs: C.Tbs, signature: List<&2, U32>) -> Bool:
  match valid:
    case True{}:
      rsa.digest(algorithm, modulus, exponent, signature, H.digest(signed_bytes(tbs)))
    case False{}:
      False{}

def ec.decoded(peer: List<&2, U32>, digest: List<&2, U32>, signature: Maybe<&1, List<&2, U32>>) -> Bool:
  match signature:
    case Some{signature}:
      E.verify_digest(peer, digest, signature)
    case None{}:
      False{}

def ec.digest(peer: List<&2, U32>, signature: List<&2, U32>, digest: Maybe<&2, List<&2, U32>>) -> Bool:
  match digest:
    case Some{digest}:
      ec.decoded(peer, digest, ED.decode(signature))
    case None{}:
      False{}

def ec.checked(valid: Bool, peer: List<&2, U32>, tbs: C.Tbs, signature: List<&2, U32>) -> Bool:
  match valid:
    case True{}:
      ec.digest(peer, signature, H.digest(signed_bytes(tbs)))
    case False{}:
      False{}

def verify_decoded(issuer: Maybe<&1, K.PublicKey>, certificate: Maybe<&1, C.Certificate>) -> Bool:
  match issuer certificate:
    case Some{K.Rsa{+key_algorithm, modulus, exponent}} Some{C.Certificate{tbs, +algorithm, signature}}:
      rsa.checked(A.compatible(key_algorithm, algorithm), algorithm, modulus, exponent, tbs, signature)
    case Some{K.P256{peer}} Some{C.Certificate{tbs, +algorithm, signature}}:
      ec.checked(A.compatible(A.P256{}, algorithm), peer, tbs, signature)
    case _ _:
      False{}

def verify_signature(issuer_spki: List<&2, U32>, certificate: List<&2, U32>) -> Bool:
  verify_decoded(K.decode(issuer_spki), C.decode(certificate))
