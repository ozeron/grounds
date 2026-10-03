import Base
import ./x509_extensions.bend as E
import ./x509_constraints.bend as C
import ./x509_certificate.bend as X
import ./x509_eku.bend as K
import ./x509_san.bend as S
import ./x509_name_schema.bend as N

# An extension-processing result, not a certificate authorization. The exact
# recognized payloads/critical flags survive; unsupported noncritical entries
# remain available to later purpose/identity owners instead of disappearing.
type Admission is Type:
  Admission{basic: Maybe<&2, List<&2, U32>>, basic_critical: Bool,
    usage: Maybe<&2, List<&2, U32>>, usage_critical: Bool,
    deferred: List<&1, E.Extension>}

def kind(oid: List<&2, U32>) -> U32:
  match oid:
    case Con{85, Con{29, Con{19, Nil{}}}}: 1
    case Con{85, Con{29, Con{15, Nil{}}}}: 2
    case Con{85, Con{29, Con{37, Nil{}}}}: 3
    case Con{85, Con{29, Con{17, Nil{}}}}: 4
    case _: 0

def basic.valid(value: Maybe<&1, C.Basic>) -> Bool:
  match value:
    case Some{_}: True{}
    case None{}: False{}

def usage.valid(value: Maybe<&1, C.Usage>) -> Bool:
  match value:
    case Some{_}: True{}
    case None{}: False{}

def eku.valid(value: Maybe<&1, List<&2, List<&2, U32>>>) -> Bool:
  match value:
    case Some{_}: True{}
    case None{}: False{}

def eku.checked(valid: Bool, critical: Bool, oid: List<&2, U32>, bytes: List<&2, U32>, state: Admission) -> Maybe<&1, Admission>:
  match valid state:
    case True{} Admission{basic, basic_critical, usage, usage_critical, deferred}:
      Some{Admission{basic, basic_critical, usage, usage_critical,
        Con{E.Extension{oid, critical, bytes}, deferred}}}
    case _ _: None{}

def basic.checked(valid: Bool, critical: Bool, bytes: List<&2, U32>, state: Admission) -> Maybe<&1, Admission>:
  match valid state:
    case True{} Admission{None{}, _, usage, usage_critical, deferred}:
      Some{Admission{Some{bytes}, critical, usage, usage_critical, deferred}}
    case _ _: None{}

def usage.checked(valid: Bool, critical: Bool, bytes: List<&2, U32>, state: Admission) -> Maybe<&1, Admission>:
  match valid state:
    case True{} Admission{basic, basic_critical, None{}, _, deferred}:
      Some{Admission{basic, basic_critical, Some{bytes}, critical, deferred}}
    case _ _: None{}

def unknown(critical: Bool, oid: List<&2, U32>, bytes: List<&2, U32>, state: Admission) -> Maybe<&1, Admission>:
  match critical state:
    case False{} Admission{basic, basic_critical, usage, usage_critical, deferred}:
      Some{Admission{basic, basic_critical, usage, usage_critical,
        Con{E.Extension{oid, False{}, bytes}, deferred}}}
    case _ _: None{}

def dispatch(kind: U32, +critical: Bool, oid: List<&2, U32>, +bytes: List<&2, U32>, state: Admission) -> Maybe<&1, Admission>:
  match kind:
    case 1: basic.checked(basic.valid(C.basic(bytes)), critical, bytes, state)
    case 2: usage.checked(usage.valid(C.usage(bytes)), critical, bytes, state)
    case 3: eku.checked(eku.valid(K.decode(bytes)), critical, oid, bytes, state)
    case 4: eku.checked(S.permits(S.inspect(bytes), critical), critical, oid, bytes, state)
    case _: unknown(critical, oid, bytes, state)

def step(entry: E.Extension, state: Admission) -> Maybe<&1, Admission>:
  match entry:
    case E.Extension{+oid, critical, bytes}: dispatch(kind(oid), critical, oid, bytes, state)

def finish.checked(valid: Bool, state: Admission) -> Maybe<&1, Admission>:
  match valid state:
    case True{} Admission{basic, basic_critical, usage, usage_critical, deferred}:
      Some{Admission{basic, basic_critical, usage, usage_critical,
        List.reverse(&1, E.Extension, deferred)}}
    case _ _: None{}

def finish(state: Admission) -> Maybe<&1, Admission>:
  match state:
    case Admission{+basic, basic_critical, +usage, usage_critical, deferred}:
      finish.checked(C.policy(basic, usage), Admission{basic, basic_critical, usage, usage_critical, deferred})

def walk(entries: List<&1, E.Extension>, state: Maybe<&1, Admission>) -> Maybe<&1, Admission>:
  match entries state:
    case Nil{} Some{state}: finish(state)
    case Con{entry, rest} Some{state}: walk(rest, step(entry, state))
    case _ _: None{}

def entries(value: Maybe<&1, List<&1, E.Extension>>) -> Maybe<&1, Admission>:
  match value:
    case Some{entries}: walk(entries, Some{Admission{None{}, False{}, None{}, False{}, []}})
    case None{}: None{}

def decode(bytes: List<&2, U32>) -> Maybe<&1, Admission>:
  entries(E.decode(bytes))

def optional(bytes: Maybe<&2, List<&2, U32>>) -> Maybe<&1, Admission>:
  entries(E.optional(bytes))

def certificate.subject(valid: Bool, extensions: Maybe<&2, List<&2, U32>>) -> Maybe<&1, Admission>:
  match valid:
    case True{}: optional(extensions)
    case False{}: None{}

def certificate.ca(value: Maybe<&1, C.Basic>) -> Bool:
  match value:
    case Some{C.Basic{ca, _}}: ca
    case None{}: True{}

def certificate.crl(value: Maybe<&1, C.Usage>) -> Bool:
  match value:
    case Some{C.Usage{bits}}: U32.is_ne(U32.and(bits, 2), 0)
    case None{}: True{}

def certificate.nonempty_basic(value: Maybe<&2, List<&2, U32>>) -> Bool:
  match value:
    case Some{bytes}: certificate.ca(C.basic(bytes))
    case None{}: False{}

def certificate.nonempty_usage(value: Maybe<&2, List<&2, U32>>) -> Bool:
  match value:
    case Some{bytes}: certificate.crl(C.usage(bytes))
    case None{}: False{}

def certificate.empty_checked(requires_name: Bool, state: Admission) -> Maybe<&1, Admission>:
  match requires_name:
    case False{}: Some{state}
    case True{}: None{}

def certificate.empty(subject: List<&2, U32>, state: Maybe<&1, Admission>) -> Maybe<&1, Admission>:
  match subject state:
    case [48,0] Some{Admission{+basic, bc, +usage, uc, deferred}}:
      certificate.empty_checked(Bool.or(certificate.nonempty_basic(basic), certificate.nonempty_usage(usage)),
        Admission{basic, bc, usage, uc, deferred})
    case _ state: state

def certificate.names(names: Maybe<&1, Bool>, +subject: List<&2, U32>, +extensions: Maybe<&2, List<&2, U32>>) -> Maybe<&1, Admission>:
  match names:
    # Unknown attributes/Teletex remain pending: this result is partial policy
    # processing, not a normalized Name match or certificate authorization.
    case Some{_}: certificate.empty(subject, certificate.subject(S.subject(subject, extensions), extensions))
    case None{}: None{}

def certificate.decoded(value: Maybe<&1, X.Certificate>) -> Maybe<&1, Admission>:
  match value:
    case Some{X.Certificate{X.Tbs{_, X.Identity{issuer, _, +subject, _}, X.Tail{_, _, extensions}}, _, _}}:
      certificate.names(N.pair(issuer, subject), subject, extensions)
    case None{}: None{}

def certificate(bytes: List<&2, U32>) -> Maybe<&1, Admission>:
  certificate.decoded(X.decode(bytes))

def eku.find(entries: List<&1, E.Extension>) -> Maybe<&2, List<&2, U32>>:
  match entries:
    case Nil{}: None{}
    case Con{E.Extension{Con{85, Con{29, Con{37, Nil{}}}}, _, bytes}, _}: Some{bytes}
    case Con{_, rest}: eku.find(rest)

def tls13.admitted(value: Maybe<&1, Admission>, server: Bool, allow_any: Bool) -> Bool:
  match value:
    case Some{Admission{_, _, usage, _, deferred}}:
      K.tls13(usage, eku.find(deferred), server, allow_any)
    case None{}: False{}

# Purpose permission only; it cannot satisfy signature, trust or identity.
def tls13_extensions(bytes: List<&2, U32>, server: Bool, allow_any: Bool) -> Bool:
  tls13.admitted(decode(bytes), server, allow_any)

def tls13_certificate(bytes: List<&2, U32>, server: Bool, allow_any: Bool) -> Bool:
  tls13.admitted(certificate(bytes), server, allow_any)
