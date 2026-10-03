import Base
import ./x509_name_schema.bend as N
import ./x509_certificate.bend as X

# Actual issuer/subject extraction around the pure Name schema owner.
# SAN binding, CA/CRL issuer restrictions, normalized matching, signature and
# path authorization are separate checks; this result is not authorization.
def decoded(certificate: Maybe<&1, X.Certificate>) -> Maybe<&1, Bool>:
  match certificate:
    case Some{X.Certificate{X.Tbs{_, X.Identity{issuer, _, subject, _}, _}, _, _}}:
      N.pair(issuer, subject)
    case None{}: None{}

def certificate(bytes: List<&2, U32>) -> Maybe<&1, Bool>:
  decoded(X.decode(bytes))
