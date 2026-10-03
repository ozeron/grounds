import Base
import ./x509_identity.bend as I
import ./bytes.bend as B
import ./der.bend as D
import ./oid.bend as O
import ./x509_extensions.bend as E
import ./x509_certificate.bend as X

# DNS/IP service identity permission only. GeneralName framing preserves
# other forms for their schema/profile owners; this is not chain authorization.
type Name is Data:
  Name{tag: U32, bytes: List<&2, U32>}

type State is Type:
  State{rest: List<&2, U32>, reversed: List<&2, Name>}

def ia5(bytes: List<&2, U32>, valid: Bool) -> Bool:
  match bytes:
    case Nil{}: valid
    case Con{byte, rest}: ia5(rest, Bool.and(valid, U32.is_lt(byte, 128)))

def form(tag: U32, +bytes: List<&2, U32>) -> Bool:
  match tag:
    case 129: ia5(bytes, Nat.is_gt(B.length(bytes), 0n))
    case 130: ia5(bytes, Nat.is_gt(B.length(bytes), 0n))
    case 134: ia5(bytes, Nat.is_gt(B.length(bytes), 0n))
    case 135: I.ip_length(bytes)
    case 136: O.contents(bytes)
    # Constructed GeneralNames need later OtherName/Name/X.400/EDI schema
    # owners. Retain their exact contents, never label framing as processing.
    case 160: Nat.is_gt(B.length(bytes), 0n)
    case 163: Nat.is_gt(B.length(bytes), 0n)
    case 164: Nat.is_gt(B.length(bytes), 0n)
    case 165: Nat.is_gt(B.length(bytes), 0n)
    case _: False{}

def item.checked(valid: Bool, tag: U32, bytes: List<&2, U32>, rest: List<&2, U32>, reversed: List<&2, Name>) -> Maybe<&1, State>:
  match valid:
    case True{}: Some{State{rest, Con{Name{tag, bytes}, reversed}}}
    case False{}: None{}

def item(value: Maybe<&1, D.Element>, reversed: List<&2, Name>) -> Maybe<&1, State>:
  match value:
    case Some{D.Element{+tag, +bytes, rest, _}}: item.checked(form(tag, bytes), tag, bytes, rest, reversed)
    case None{}: None{}

def walk(left: Nat, value: Maybe<&1, State>) -> Maybe<&1, List<&2, Name>>:
  match left value:
    case _ Some{State{Nil{}, reversed}}: Some{List.reverse(&2, Name, reversed)}
    case 1n+p Some{State{bytes, reversed}}: walk(p, item(D.read(bytes), reversed))
    case _ _: None{}

def frame.body(value: Maybe<&1, List<&2, U32>>) -> Maybe<&1, List<&2, Name>>:
  match value:
    case Some{Con{byte, rest}}: walk(65535n, Some{State{Con{byte, rest}, []}})
    case _: None{}

def frame(bytes: List<&2, U32>) -> Maybe<&1, List<&2, Name>>:
  frame.body(D.complete(48, bytes))

def match_name(tag: U32, bytes: List<&2, U32>, kind: U32, reference: List<&2, U32>) -> Bool:
  match tag kind:
    case 130 0: I.dns(bytes, reference)
    case 135 1: I.ip(bytes, reference)
    case _ _: False{}

def matches(names: List<&2, Name>, +kind: U32, +reference: List<&2, U32>, found: Bool) -> Bool:
  match names:
    case Nil{}: found
    case Con{Name{tag, bytes}, rest}: matches(rest, kind, reference, Bool.or(found, match_name(tag, bytes, kind, reference)))

def san.framed(names: Maybe<&1, List<&2, Name>>, kind: U32, reference: List<&2, U32>) -> Bool:
  match names:
    case Some{names}: matches(names, kind, reference, False{})
    case None{}: False{}

# kind 0 is DNS-ID, kind 1 is IP-ID. Matching never crosses identifier types.
# Complete framing runs first; a match cannot hide malformed later framing.
def san(bytes: List<&2, U32>, kind: U32, reference: List<&2, U32>) -> Bool:
  san.framed(frame(bytes), kind, reference)

def find(entries: List<&1, E.Extension>) -> Maybe<&2, List<&2, U32>>:
  match entries:
    case Nil{}: None{}
    case Con{E.Extension{Con{85, Con{29, Con{17, Nil{}}}}, _, bytes}, _}: Some{bytes}
    case Con{_, rest}: find(rest)

def extensions.found(bytes: Maybe<&2, List<&2, U32>>, kind: U32, reference: List<&2, U32>) -> Bool:
  match bytes:
    case Some{bytes}: san(bytes, kind, reference)
    case None{}: False{}

def extensions.decoded(entries: Maybe<&1, List<&1, E.Extension>>, kind: U32, reference: List<&2, U32>) -> Bool:
  match entries:
    case Some{entries}: extensions.found(find(entries), kind, reference)
    case None{}: False{}

def extensions(bytes: List<&2, U32>, kind: U32, reference: List<&2, U32>) -> Bool:
  extensions.decoded(E.decode(bytes), kind, reference)

def certificate.decoded(value: Maybe<&1, X.Certificate>, kind: U32, reference: List<&2, U32>) -> Bool:
  match value:
    case Some{X.Certificate{X.Tbs{_, _, X.Tail{_, _, bytes}}, _, _}}:
      extensions.decoded(E.optional(bytes), kind, reference)
    case None{}: False{}

# Read the actual extension field. Subject CN is never a fallback. Critical
# extension handling, SAN schema/profile admission and trust remain mandatory.
def certificate(bytes: List<&2, U32>, kind: U32, reference: List<&2, U32>) -> Bool:
  certificate.decoded(X.decode(bytes), kind, reference)
