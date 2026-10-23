import Base
import ./private_key.bend as K
import ./rsa_private.bend as R
import ./pem.bend as M
import ./x509_public_key.bend as P
import ./x509_algorithm.bend as A
import ./x509_certificate.bend as C

# Local server credential admission, not chain trust or hostname/time policy.
# M3 owns the handshake chain decision. This affine owner retains the exact
# leaf encoding and permits only the profile's CertificateVerify key families.
type Credential is Type:
  Credential{leaf: List<&2, U32>, key: K.Private}

def checked(valid: Bool, leaf: List<&2, U32>, key: K.Private) -> Maybe<&1, Credential>:
  match valid:
    case True{}:
      Some{Credential{leaf, key}}
    case False{}:
      None{}

def matched(leaf: List<&2, U32>, key: K.Private, public: Maybe<&1, P.PublicKey>) -> Maybe<&1, Credential>:
  match key public:
    case K.P256{scalar, +derived} Some{P.P256{encoded}}:
      checked(K.same(derived, encoded), leaf, K.P256{scalar, derived})
    case K.Rsa{R.Private{+n, +e, d, p, q, dp, dq, qi}} Some{P.Rsa{A.Rsa{}, modulus, exponent}}:
      checked(Bool.and(K.same(n, modulus), K.same(e, exponent)), leaf, K.Rsa{R.Private{n, e, d, p, q, dp, dq, qi}})
    case _ _:
      None{}

def certificate(leaf: List<&2, U32>, key: K.Private, certificate: Maybe<&1, C.Certificate>) -> Maybe<&1, Credential>:
  match certificate:
    case Some{C.Certificate{C.Tbs{_, C.Identity{_, _, _, spki}, _}, _, _}}:
      matched(leaf, key, P.decode(spki))
    case None{}:
      None{}

def from_key(+leaf: List<&2, U32>, key: K.Private) -> Maybe<&1, Credential>:
  certificate(leaf, key, C.decode(leaf))

def imported.validated(result: Maybe<&1, Credential>) -> Result<&2, &1, M.Error, Credential>:
  match result:
    case Some{credential}:
      Done{credential}
    case None{}:
      Fail{M.Malformed{}}

def imported(leaf: List<&2, U32>, key: Result<&2, &1, M.Error, K.Private>) -> Result<&2, &1, M.Error, Credential>:
  match key:
    case Fail{error}:
      Fail{error}
    case Done{key}:
      imported.validated(from_key(leaf, key))

# PEM private key plus DER leaf; encrypted PEM keeps its distinct error.
def import_pem(leaf: List<&2, U32>, private_pem: List<&2, U32>) -> Result<&2, &1, M.Error, Credential>:
  imported(leaf, K.pem(private_pem))
