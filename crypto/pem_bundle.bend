import Base
import ./pem.bend as P
import ./bytes.bend as B
import ./x509_certificate.bend as C
import ./der.bend as D
import ./oid.bend as O
import ./x509_algorithm.bend as A
import ./x509_name.bend as N
import ./x509_extensions.bend as E
import ../utf8/utf8.bend as Utf

# RFC 7468 explanatory text is allowed outside blocks. Every delimiter line
# must be exact; malformed/duplicate/overflow entries fail the whole bundle.
# No filtering, partial trust result or ambient trust.
type Error is Data:
  Empty{}
  Malformed{}
  Duplicate{}
  Limit{}

type Parsed is Data:
  Parsed{pem: List<&2,U32>, rest: List<&2,U32>}

def show(error: Error) -> String:
  match error:
    case Empty{}: "empty-bundle"
    case Malformed{}: "malformed-bundle"
    case Duplicate{}: "duplicate-anchor"
    case Limit{}: "bundle-limit"

def within(bytes: List<&2,U32>, +left: U32) -> Bool:
  match bytes left:
    case Nil{} _: True{}
    case Con{_,_} 0: False{}
    case Con{+byte,rest} left:
      Bool.and(U32.is_le(byte,255),within(rest,U32.sub(left,1)))

def seen(+raw: List<&2,U32>, roots: List<&2,List<&2,U32>>) -> Bool:
  match roots:
    case Nil{}: False{}
    case Con{other,rest}: Bool.or(C.anchor.equal(raw,other),seen(raw,rest))

def finish(roots: List<&2,List<&2,U32>>) -> Result<&2,&2,Error,List<&2,List<&2,U32>>>:
  match roots:
    case Nil{}: Fail{Empty{}}
    case roots: Done{List.reverse(&2,List<&2,U32>,roots)}

def delimiter(text: String) -> Bool:
  match text:
    case SCon{Chr{45},SCon{Chr{45},SCon{Chr{45},SCon{Chr{45},SCon{Chr{45},_}}}}}: True{}
    case _: False{}

def body.more(bad: Bool, rest: List<&2,U32>, collected: List<&2,U32>,
  more: List<&2,U32> -> List<&2,U32> -> Result<&2,&2,Error,Parsed>) -> Result<&2,&2,Error,Parsed>:
  match bad:
    case True{}: Fail{Malformed{}}
    case False{}: more(rest,collected)

# Delimiters are compared with String.eq, not string-literal match patterns:
# under Bend 2.0.38 those two literal matches cost ~1.2 GiB of checker memory
# in every program importing this module (see http/client/BUILD_MEMORY.md).
def body.end(ended: Bool, +text: String, rest: List<&2,U32>, collected: List<&2,U32>,
  more: List<&2,U32> -> List<&2,U32> -> Result<&2,&2,Error,Parsed>) -> Result<&2,&2,Error,Parsed>:
  match ended:
    case True{}:
      Done{Parsed{List.reverse(&2,U32,List.reverse.go(&2,U32,Utf.encode(text),collected)),rest}}
    case False{}:
      body.more(delimiter(text),rest,Con{10,List.reverse.go(&2,U32,Utf.encode(text),collected)},more)

def body.line(pair: String & List<&2,U32>, collected: List<&2,U32>,
  more: List<&2,U32> -> List<&2,U32> -> Result<&2,&2,Error,Parsed>) -> Result<&2,&2,Error,Parsed>:
  (+text,+rest) = pair
  body.end(String.eq(text,"-----END CERTIFICATE-----"),text,rest,collected,more)

def body(left: Nat, bytes: List<&2,U32>, collected: List<&2,U32>) -> Result<&2,&2,Error,Parsed>:
  match left bytes:
    case _ Nil{}: Fail{Malformed{}}
    case 0n _: Fail{Limit{}}
    case 1n+p bytes:
      body.line(P.line(bytes,""),collected,r => acc => body(p,r,acc))

def unique(duplicate: Bool, raw: List<&2,U32>, roots: List<&2,List<&2,U32>>,
  next: List<&2,List<&2,U32>> -> Result<&2,&2,Error,List<&2,List<&2,U32>>>) -> Result<&2,&2,Error,List<&2,List<&2,U32>>>:
  match duplicate:
    case True{}: Fail{Duplicate{}}
    case False{}: next(Con{raw,roots})

# Nested framing is checked with the chain owners' structural decoders before
# any entry is admitted. Valid DER outside the supported key/Name/signature
# profile still loads; chain search applies that policy only if it is used.
def framed.attributes(items: List<&2,N.Attribute>, valid: Bool) -> Bool:
  match items:
    case Nil{}: valid
    case Con{N.Attribute{oid,_,_,_},rest}: framed.attributes(rest,Bool.and(valid,O.contents(oid)))

def framed.rdns(rdns: List<&2,List<&2,N.Attribute>>, valid: Bool) -> Bool:
  match rdns:
    case Nil{}: valid
    case Con{items,rest}: framed.rdns(rest,framed.attributes(items,valid))

def framed.name(value: Maybe<&1,N.Name>) -> Bool:
  match value:
    case Some{N.Name{rdns,_}}: framed.rdns(rdns,True{})
    case None{}: False{}

def framed.bits(value: Maybe<&1,List<&2,U32>>) -> Bool:
  match value:
    case Some{bits}: C.bit_string(bits)
    case None{}: False{}

def framed.key(value: Maybe<&1,D.Element>) -> Bool:
  match value:
    case Some{D.Element{48,_,rest,algorithm}}:
      Bool.and(C.anchor.identifier(A.identifier(algorithm)),framed.bits(D.complete(3,rest)))
    case _: False{}

def framed.spki(value: Maybe<&1,List<&2,U32>>) -> Bool:
  match value:
    case Some{body}: framed.key(D.read(body))
    case None{}: False{}

def framed.extensions(value: Maybe<&1,List<&1,E.Extension>>) -> Bool:
  match value:
    case Some{_}: True{}
    case None{}: False{}

def framed(value: Maybe<&1,C.Tbs>) -> Bool:
  match value:
    case Some{C.Tbs{_,C.Identity{issuer,_,subject,spki},C.Tail{_,_,extensions}}}:
      Bool.and(Bool.and(framed.name(N.collected(D.complete(48,issuer),True{})),
          framed.name(N.collected(D.complete(48,subject),True{}))),
        Bool.and(framed.spki(D.complete(48,spki)),framed.extensions(E.optional(extensions))))
    case None{}: False{}

def certificate(+raw: List<&2,U32>, valid: Bool, +roots: List<&2,List<&2,U32>>,
  next: List<&2,List<&2,U32>> -> Result<&2,&2,Error,List<&2,List<&2,U32>>>) -> Result<&2,&2,Error,List<&2,List<&2,U32>>>:
  match valid:
    case False{}: Fail{Malformed{}}
    case True{}: unique(seen(raw,roots),raw,roots,next)

def block(value: Result<&2,&1,P.Error,P.Block>, roots: List<&2,List<&2,U32>>,
  next: List<&2,List<&2,U32>> -> Result<&2,&2,Error,List<&2,List<&2,U32>>>) -> Result<&2,&2,Error,List<&2,List<&2,U32>>>:
  match value:
    case Done{P.Block{P.Certificate{},+der}}: certificate(der,framed(C.anchor(der)),roots,next)
    case _: Fail{Malformed{}}

def parsed(value: Result<&2,&2,Error,Parsed>, roots: List<&2,List<&2,U32>>,
  next: List<&2,U32> -> List<&2,List<&2,U32>> -> Result<&2,&2,Error,List<&2,List<&2,U32>>>) -> Result<&2,&2,Error,List<&2,List<&2,U32>>>:
  match value:
    case Done{Parsed{pem,rest}}: block(P.decode(pem),roots,r => next(rest,r))
    case Fail{error}: Fail{error}

def start.more(bad: Bool, rest: List<&2,U32>, roots: List<&2,List<&2,U32>>,
  next: List<&2,U32> -> List<&2,List<&2,U32>> -> Result<&2,&2,Error,List<&2,List<&2,U32>>>) -> Result<&2,&2,Error,List<&2,List<&2,U32>>>:
  match bad:
    case True{}: Fail{Malformed{}}
    case False{}: next(rest,roots)

def start.begin(begun: Bool, +text: String, +rest: List<&2,U32>, +left: U32, roots: List<&2,List<&2,U32>>,
  next: U32 -> List<&2,U32> -> List<&2,List<&2,U32>> -> Result<&2,&2,Error,List<&2,List<&2,U32>>>) -> Result<&2,&2,Error,List<&2,List<&2,U32>>>:
  match begun left:
    case True{} 0: Fail{Limit{}}
    case True{} left:
      parsed(body(Nat.add(B.length(rest),1n),rest,Con{10,List.reverse(&2,U32,Utf.encode(text))}),roots,r => acc => next(U32.sub(left,1),r,acc))
    case False{} _:
      start.more(delimiter(text),rest,roots,r => acc => next(left,r,acc))

def start.line(pair: String & List<&2,U32>, +left: U32, roots: List<&2,List<&2,U32>>,
  next: U32 -> List<&2,U32> -> List<&2,List<&2,U32>> -> Result<&2,&2,Error,List<&2,List<&2,U32>>>) -> Result<&2,&2,Error,List<&2,List<&2,U32>>>:
  (+text,+rest) = pair
  start.begin(String.eq(text,"-----BEGIN CERTIFICATE-----"),text,rest,left,roots,next)

def start(fuel: Nat, +left: U32, bytes: List<&2,U32>, roots: List<&2,List<&2,U32>>) -> Result<&2,&2,Error,List<&2,List<&2,U32>>>:
  match fuel bytes:
    case _ Nil{}: finish(roots)
    case 0n _: Fail{Limit{}}
    case 1n+p bytes: start.line(P.line(bytes,""),left,roots,l => r => acc => start(p,l,r,acc))

def decode.checked(valid: Bool, +bytes: List<&2,U32>) -> Result<&2,&2,Error,List<&2,List<&2,U32>>>:
  match valid:
    case True{}: start(Nat.add(B.length(bytes),1n),256,bytes,[])
    case False{}: Fail{Limit{}}

# 2 MiB text, 256 anchors, 65535 DER bytes/certificate. Key/signature
# algorithm admission is a separate chain-verification decision.
def decode(+bytes: List<&2,U32>) -> Result<&2,&2,Error,List<&2,List<&2,U32>>>:
  decode.checked(within(bytes,2097152),bytes)
