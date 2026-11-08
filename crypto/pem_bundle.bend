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
# No filtering, partial trust result or ambient trust. `decode.system` (system
# bundles only) drops byte-identical duplicates and skips exactly framed
# OpenSSL TRUSTED CERTIFICATE blocks, which never become anchors.
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

# A system bundle keeps the first of byte-identical DER entries.
def unique(duplicate: Bool, system: Bool, raw: List<&2,U32>, roots: List<&2,List<&2,U32>>,
  next: List<&2,List<&2,U32>> -> Result<&2,&2,Error,List<&2,List<&2,U32>>>) -> Result<&2,&2,Error,List<&2,List<&2,U32>>>:
  match duplicate system:
    case True{} True{}: next(roots)
    case True{} False{}: Fail{Duplicate{}}
    case False{} _: next(Con{raw,roots})

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

# AlgorithmIdentifier parameters are walked to the leaves: every element is
# DER-framed, constructed ones recursively, and every OID is canonical.
# Unknown algorithms with well-formed parameters still load.
def deep.pop(stack: List<&2,List<&2,U32>>, more: List<&2,U32> -> List<&2,List<&2,U32>> -> Bool) -> Bool:
  match stack:
    case Nil{}: True{}
    case Con{bytes,rest}: more(bytes,rest)

def deep.kind(oid: Bool, constructed: Bool, body: List<&2,U32>, rest: List<&2,U32>,
  stack: List<&2,List<&2,U32>>, more: List<&2,U32> -> List<&2,List<&2,U32>> -> Bool) -> Bool:
  match oid constructed:
    case True{} _: Bool.and(O.contents(body),more(rest,stack))
    case False{} True{}: more(body,Con{rest,stack})
    case False{} False{}: more(rest,stack)

def deep.element(value: Maybe<&1,D.Element>, stack: List<&2,List<&2,U32>>,
  more: List<&2,U32> -> List<&2,List<&2,U32>> -> Bool) -> Bool:
  match value:
    case Some{D.Element{+tag,body,rest,_}}:
      deep.kind(U32.is_eq(tag,6),U32.is_ne(U32.and(tag,32),0),body,rest,stack,more)
    case None{}: False{}

def deep.step(bytes: List<&2,U32>, stack: List<&2,List<&2,U32>>,
  more: List<&2,U32> -> List<&2,List<&2,U32>> -> Bool) -> Bool:
  match bytes:
    case Nil{}: deep.pop(stack,more)
    case bytes: deep.element(D.read(bytes),stack,more)

# Siblings left at each enclosing level wait on the stack. Every element read
# and every pop spends fuel; elements are at least two bytes, so 2n+2 suffices.
def deep(fuel: Nat, bytes: List<&2,U32>, stack: List<&2,List<&2,U32>>) -> Bool:
  match fuel:
    case 0n: False{}
    case 1n+p: deep.step(bytes,stack,b => s => deep(p,b,s))

# AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ANY OPTIONAL }:
# nothing, or exactly one element, follows the OID.
def single.element(value: Maybe<&1,D.Element>) -> Bool:
  match value:
    case Some{D.Element{_,_,Nil{},_}}: True{}
    case _: False{}

def single(parameters: List<&2,U32>) -> Bool:
  match parameters:
    case Nil{}: True{}
    case bytes: single.element(D.read(bytes))

def parameters(+parameters: List<&2,U32>) -> Bool:
  Bool.and(single(parameters),
    deep(Nat.add(Nat.add(B.length(parameters),B.length(parameters)),2n),parameters,[]))

def deep.identifier(value: Maybe<&1,A.Identifier>) -> Bool:
  match value:
    case Some{A.Identifier{oid,rest}}: Bool.and(O.contents(oid),parameters(rest))
    case None{}: False{}

def algorithm(encoded: List<&2,U32>) -> Bool:
  deep.identifier(A.identifier(encoded))

# RFC 3279/5480: rsaEncryption takes NULL, id-ecPublicKey a namedCurve OID.
def key.null(parameters: List<&2,U32>) -> Bool:
  match parameters:
    case Con{5,Con{0,Nil{}}}: True{}
    case _: False{}

def key.curve(value: Maybe<&1,D.Element>) -> Bool:
  match value:
    case Some{D.Element{6,_,Nil{},_}}: True{}
    case _: False{}

def key.kind(rsa: Bool, ec: Bool, parameters: List<&2,U32>) -> Bool:
  match rsa ec:
    case True{} _: key.null(parameters)
    case False{} True{}: key.curve(D.read(parameters))
    case False{} False{}: True{}

def key.parameters(+kind: U32, parameters: List<&2,U32>) -> Bool:
  key.kind(U32.is_eq(kind,1),U32.is_eq(kind,21),parameters)

def key.identifier(value: Maybe<&1,A.Identifier>) -> Bool:
  match value:
    case Some{A.Identifier{+oid,+rest}}:
      Bool.and(Bool.and(O.contents(oid),parameters(rest)),key.parameters(A.oid.kind(oid),rest))
    case None{}: False{}

def framed.key(value: Maybe<&1,D.Element>) -> Bool:
  match value:
    case Some{D.Element{48,_,rest,algorithm}}:
      Bool.and(key.identifier(A.identifier(algorithm)),framed.bits(D.complete(3,rest)))
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
    # C.anchor already bound the outer signature algorithm to this one.
    case Some{C.Tbs{C.Header{_,_,_,signature},C.Identity{issuer,_,subject,spki},C.Tail{_,_,extensions}}}:
      Bool.and(Bool.and(Bool.and(framed.name(N.collected(D.complete(48,issuer),True{})),
          framed.name(N.collected(D.complete(48,subject),True{}))),algorithm(signature)),
        Bool.and(framed.spki(D.complete(48,spki)),framed.extensions(E.optional(extensions))))
    case None{}: False{}

def certificate(+raw: List<&2,U32>, valid: Bool, system: Bool, +roots: List<&2,List<&2,U32>>,
  next: List<&2,List<&2,U32>> -> Result<&2,&2,Error,List<&2,List<&2,U32>>>) -> Result<&2,&2,Error,List<&2,List<&2,U32>>>:
  match valid:
    case False{}: Fail{Malformed{}}
    case True{}: unique(seen(raw,roots),system,raw,roots,next)

def block(value: Result<&2,&1,P.Error,P.Block>, system: Bool, roots: List<&2,List<&2,U32>>,
  next: List<&2,List<&2,U32>> -> Result<&2,&2,Error,List<&2,List<&2,U32>>>) -> Result<&2,&2,Error,List<&2,List<&2,U32>>>:
  match value:
    case Done{P.Block{P.Certificate{},+der}}: certificate(der,framed(C.anchor(der)),system,roots,next)
    case _: Fail{Malformed{}}

def parsed(value: Result<&2,&2,Error,Parsed>, system: Bool, roots: List<&2,List<&2,U32>>,
  next: List<&2,U32> -> List<&2,List<&2,U32>> -> Result<&2,&2,Error,List<&2,List<&2,U32>>>) -> Result<&2,&2,Error,List<&2,List<&2,U32>>>:
  match value:
    case Done{Parsed{pem,rest}}: block(P.decode(pem),system,roots,r => next(rest,r))
    case Fail{error}: Fail{error}

# A system bundle's OpenSSL TRUSTED CERTIFICATE block (certificate plus trust
# settings) is skipped up to its exact END line and never becomes an anchor.
# Its contents are not decoded; any other delimiter inside it, or a missing
# END line, fails the whole load.
def skip.more(bad: Bool, rest: List<&2,U32>,
  more: List<&2,U32> -> Result<&2,&2,Error,List<&2,U32>>) -> Result<&2,&2,Error,List<&2,U32>>:
  match bad:
    case True{}: Fail{Malformed{}}
    case False{}: more(rest)

def skip.end(ended: Bool, text: String, rest: List<&2,U32>,
  more: List<&2,U32> -> Result<&2,&2,Error,List<&2,U32>>) -> Result<&2,&2,Error,List<&2,U32>>:
  match ended:
    case True{}: Done{rest}
    case False{}: skip.more(delimiter(text),rest,more)

def skip.line(pair: String & List<&2,U32>,
  more: List<&2,U32> -> Result<&2,&2,Error,List<&2,U32>>) -> Result<&2,&2,Error,List<&2,U32>>:
  (+text,+rest) = pair
  skip.end(String.eq(text,"-----END TRUSTED CERTIFICATE-----"),text,rest,more)

def skip(fuel: Nat, bytes: List<&2,U32>) -> Result<&2,&2,Error,List<&2,U32>>:
  match fuel bytes:
    case _ Nil{}: Fail{Malformed{}}
    case 0n _: Fail{Limit{}}
    case 1n+p bytes: skip.line(P.line(bytes,""),r => skip(p,r))

def skipped(value: Result<&2,&2,Error,List<&2,U32>>, roots: List<&2,List<&2,U32>>,
  next: List<&2,U32> -> List<&2,List<&2,U32>> -> Result<&2,&2,Error,List<&2,List<&2,U32>>>) -> Result<&2,&2,Error,List<&2,List<&2,U32>>>:
  match value:
    case Done{rest}: next(rest,roots)
    case Fail{error}: Fail{error}

def start.more(trusted: Bool, bad: Bool, +rest: List<&2,U32>, roots: List<&2,List<&2,U32>>,
  next: List<&2,U32> -> List<&2,List<&2,U32>> -> Result<&2,&2,Error,List<&2,List<&2,U32>>>) -> Result<&2,&2,Error,List<&2,List<&2,U32>>>:
  match trusted bad:
    case True{} _: skipped(skip(Nat.add(B.length(rest),1n),rest),roots,next)
    case False{} True{}: Fail{Malformed{}}
    case False{} False{}: next(rest,roots)

def start.trusted(system: Bool, text: String) -> Bool:
  match system:
    case True{}: String.eq(text,"-----BEGIN TRUSTED CERTIFICATE-----")
    case False{}: False{}

def start.begin(begun: Bool, +system: Bool, +text: String, +rest: List<&2,U32>, +left: U32, roots: List<&2,List<&2,U32>>,
  next: U32 -> List<&2,U32> -> List<&2,List<&2,U32>> -> Result<&2,&2,Error,List<&2,List<&2,U32>>>) -> Result<&2,&2,Error,List<&2,List<&2,U32>>>:
  match begun left:
    case True{} 0: Fail{Limit{}}
    case True{} left:
      parsed(body(Nat.add(B.length(rest),1n),rest,Con{10,List.reverse(&2,U32,Utf.encode(text))}),system,roots,r => acc => next(U32.sub(left,1),r,acc))
    case False{} _:
      start.more(start.trusted(system,text),delimiter(text),rest,roots,r => acc => next(left,r,acc))

def start.line(pair: String & List<&2,U32>, system: Bool, +left: U32, roots: List<&2,List<&2,U32>>,
  next: U32 -> List<&2,U32> -> List<&2,List<&2,U32>> -> Result<&2,&2,Error,List<&2,List<&2,U32>>>) -> Result<&2,&2,Error,List<&2,List<&2,U32>>>:
  (+text,+rest) = pair
  start.begin(String.eq(text,"-----BEGIN CERTIFICATE-----"),system,text,rest,left,roots,next)

def start(fuel: Nat, +system: Bool, +left: U32, bytes: List<&2,U32>, roots: List<&2,List<&2,U32>>) -> Result<&2,&2,Error,List<&2,List<&2,U32>>>:
  match fuel bytes:
    case _ Nil{}: finish(roots)
    case 0n _: Fail{Limit{}}
    case 1n+p bytes: start.line(P.line(bytes,""),system,left,roots,l => r => acc => start(p,system,l,r,acc))

def decode.checked(valid: Bool, system: Bool, +bytes: List<&2,U32>) -> Result<&2,&2,Error,List<&2,List<&2,U32>>>:
  match valid:
    case True{}: start(Nat.add(B.length(bytes),1n),system,256,bytes,[])
    case False{}: Fail{Limit{}}

# 2 MiB text, 256 anchors, 65535 DER bytes/certificate. Key/signature
# algorithm admission is a separate chain-verification decision.
def decode(+bytes: List<&2,U32>) -> Result<&2,&2,Error,List<&2,List<&2,U32>>>:
  decode.checked(within(bytes,2097152),False{},bytes)

# Same limits and whole-load rejection of malformed entries, for a host's
# system bundle only: byte-identical duplicate certificates are dropped (each
# still counts toward the 256 blocks) and OpenSSL TRUSTED CERTIFICATE blocks
# are skipped. A distinct certificate always needs its own CERTIFICATE block.
def decode.system(+bytes: List<&2,U32>) -> Result<&2,&2,Error,List<&2,List<&2,U32>>>:
  decode.checked(within(bytes,2097152),True{},bytes)
