import Base
import ./bytes.bend as B
import ./der.bend as D
import ./x509_identity.bend as I
import ./x509_hostname.bend as H
import ./x509_extensions.bend as E
import ./x509_certificate.bend as X

# Selected DNS/IP SAN payload admission. Other framed GeneralName forms remain
# deferred; their syntax/semantics are not processed by this owner. None means
# malformed framing or a malformed DNS/IP name, even after a valid match.
# Some{True} means every name is supported, Some{False} means forms are deferred.
def dns(+bytes: List<&2, U32>) -> Bool:
  match bytes:
    case Con{42, Con{46, suffix}}:
      Bool.and(Nat.is_le(B.length(bytes), 253n), I.domain(suffix))
    case bytes: I.domain(bytes)

def checked(valid: Bool, supported: Bool) -> Maybe<&1, Bool>:
  match valid:
    case True{}: Some{supported}
    case False{}: None{}

def names(items: List<&2, H.Name>, supported: Bool, valid: Bool) -> Maybe<&1, Bool>:
  match items:
    case Nil{}: checked(valid, supported)
    case Con{H.Name{130, bytes}, rest}: names(rest, supported, Bool.and(valid, dns(bytes)))
    case Con{H.Name{135, _}, rest}: names(rest, supported, valid)
    case Con{_, rest}: names(rest, False{}, valid)

def framed(value: Maybe<&1, List<&2, H.Name>>) -> Maybe<&1, Bool>:
  match value:
    case Some{items}: names(items, True{}, True{})
    case None{}: None{}

def inspect(bytes: List<&2, U32>) -> Maybe<&1, Bool>:
  framed(H.frame(bytes))

# A critical SAN cannot pass by recognizing only one of its name forms.
def permits(value: Maybe<&1, Bool>, critical: Bool) -> Bool:
  match value:
    case Some{supported}: Bool.or(Bool.not(critical), supported)
    case None{}: False{}

def find(entries: List<&1, E.Extension>) -> Maybe<&1, E.Extension>:
  match entries:
    case Nil{}: None{}
    case Con{E.Extension{Con{85, Con{29, Con{17, Nil{}}}}, critical, bytes}, _}:
      Some{E.Extension{[85,29,17], critical, bytes}}
    case Con{_, rest}: find(rest)

def subject.san(empty: Bool, value: Maybe<&1, E.Extension>) -> Bool:
  match value:
    case None{}: Bool.not(empty)
    case Some{E.Extension{_, +critical, bytes}}:
      Bool.and(Bool.or(Bool.not(empty), critical), permits(inspect(bytes), critical))

def subject.extensions(empty: Bool, entries: Maybe<&1, List<&1, E.Extension>>) -> Bool:
  match entries:
    case Some{entries}: subject.san(empty, find(entries))
    case None{}: False{}

def subject.body(value: Maybe<&1, List<&2, U32>>, extensions: Maybe<&2, List<&2, U32>>) -> Bool:
  match value:
    case Some{Nil{}}: subject.extensions(True{}, E.optional(extensions))
    case Some{Con{_, _}}: subject.extensions(False{}, E.optional(extensions))
    case None{}: False{}

# The RFC 5280 empty-subject/SAN binding requirement only. A nonempty subject
# still needs a Name schema owner; signature, issuer, path/trust and time remain.
def subject(subject: List<&2, U32>, extensions: Maybe<&2, List<&2, U32>>) -> Bool:
  subject.body(D.complete(48, subject), extensions)

def certificate.decoded(value: Maybe<&1, X.Certificate>) -> Bool:
  match value:
    case Some{X.Certificate{X.Tbs{_, X.Identity{_, _, subject_bytes, _}, X.Tail{_, _, extensions}}, _, _}}:
      subject(subject_bytes, extensions)
    case None{}: False{}

def certificate(bytes: List<&2, U32>) -> Bool:
  certificate.decoded(X.decode(bytes))
