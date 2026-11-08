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
# bundles only) drops byte-identical duplicates and reads OpenSSL TRUSTED
# CERTIFICATE blocks, which never become anchors but whose trust settings
# can withdraw one (see `distrust`).
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
# The collected block always ends in a plain CERTIFICATE footer, so a
# TRUSTED block's text decodes with P.decode like any other.
def body.end(ended: Bool, +text: String, rest: List<&2,U32>, collected: List<&2,U32>,
  more: List<&2,U32> -> List<&2,U32> -> Result<&2,&2,Error,Parsed>) -> Result<&2,&2,Error,Parsed>:
  match ended:
    case True{}:
      Done{Parsed{List.reverse(&2,U32,List.reverse.go(&2,U32,Utf.encode("-----END CERTIFICATE-----"),collected)),rest}}
    case False{}:
      body.more(delimiter(text),rest,Con{10,List.reverse.go(&2,U32,Utf.encode(text),collected)},more)

def body.footer(trusted: Bool) -> String:
  match trusted:
    case True{}: "-----END TRUSTED CERTIFICATE-----"
    case False{}: "-----END CERTIFICATE-----"

def body.line(pair: String & List<&2,U32>, trusted: Bool, collected: List<&2,U32>,
  more: List<&2,U32> -> List<&2,U32> -> Result<&2,&2,Error,Parsed>) -> Result<&2,&2,Error,Parsed>:
  (+text,+rest) = pair
  body.end(String.eq(text,body.footer(trusted)),text,rest,collected,more)

# Lines up to the block's exact END line. Any other delimiter inside the
# block, or a missing END line, fails the whole load.
def body(left: Nat, +trusted: Bool, bytes: List<&2,U32>, collected: List<&2,U32>) -> Result<&2,&2,Error,Parsed>:
  match left bytes:
    case _ Nil{}: Fail{Malformed{}}
    case 0n _: Fail{Limit{}}
    case 1n+p bytes:
      body.line(P.line(bytes,""),trusted,collected,r => acc => body(p,trusted,r,acc))

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

# AlgorithmIdentifier parameters (ANY) are walked to the leaves as DER. Every
# element is framed (single-octet tags, minimal definite lengths). SEQUENCE
# and SET must be constructed and are walked; every other universal type must
# be primitive with valid contents (`leaf`). Context, application and private
# tags are framing only: constructed ones are walked, primitive ones opaque.
# Unknown algorithms with valid parameters still load.
# OpenSSL 3's d2i_X509 / d2i_X509_AUX rejects the same NULL, BOOLEAN length,
# INTEGER, ENUMERATED, BIT STRING unused-bits, OID, BMPString,
# UniversalString, UTCTime/GeneralizedTime length and primitive/constructed
# errors. It is laxer (BER) where this is DER: it accepts any non-zero
# BOOLEAN octet, masks BIT STRING padding bits, accepts constructed strings
# and indefinite lengths, and never looks inside SEQUENCE, SET or tagged
# parameters.
def leaf.boolean(body: List<&2,U32>) -> Bool:
  match body:
    case Con{+byte,Nil{}}: Bool.or(U32.is_eq(byte,0),U32.is_eq(byte,255))
    case _: False{}

def leaf.null(body: List<&2,U32>) -> Bool:
  match body:
    case Nil{}: True{}
    case _: False{}

# Length a multiple of mask + 1 (BMPString 2, UniversalString 4).
def leaf.aligned(bytes: List<&2,U32>, +mask: U32, +count: U32) -> Bool:
  match bytes:
    case Nil{}: U32.is_eq(U32.and(count,mask),0)
    case Con{_,rest}: leaf.aligned(rest,mask,U32.add(count,1))

def leaf.is(hit: Bool, check: List<&2,U32> -> Bool, body: List<&2,U32>,
  next: List<&2,U32> -> Bool) -> Bool:
  match hit:
    case True{}: check(body)
    case False{}: next(body)

# UTCTime and GeneralizedTime: OpenSSL's minimum lengths (13 and 15).
def leaf(+number: U32, body: List<&2,U32>) -> Bool:
  leaf.is(U32.is_eq(number,5),b => leaf.null(b),body,b =>
    leaf.is(U32.is_eq(number,1),c => leaf.boolean(c),b,c =>
      leaf.is(Bool.or(U32.is_eq(number,2),U32.is_eq(number,10)),d => C.integer(d),c,d =>
        leaf.is(U32.is_eq(number,3),e => C.bit_string(e),d,e =>
          leaf.is(U32.is_eq(number,6),f => O.contents(f),e,f =>
            leaf.is(U32.is_eq(number,30),g => leaf.aligned(g,1,0),f,g =>
              leaf.is(U32.is_eq(number,28),h => leaf.aligned(h,3,0),g,h =>
                leaf.is(U32.is_eq(number,23),i => Nat.is_gt(B.length(i),12n),h,i =>
                  leaf.is(U32.is_eq(number,24),j => Nat.is_gt(B.length(j),14n),i,j => True{})))))))))

def deep.pop(stack: List<&2,List<&2,U32>>, more: List<&2,U32> -> List<&2,List<&2,U32>> -> Bool) -> Bool:
  match stack:
    case Nil{}: True{}
    case Con{bytes,rest}: more(bytes,rest)

def deep.walk(constructed: Bool, body: List<&2,U32>, rest: List<&2,U32>,
  stack: List<&2,List<&2,U32>>, more: List<&2,U32> -> List<&2,List<&2,U32>> -> Bool) -> Bool:
  match constructed:
    case True{}: more(body,Con{rest,stack})
    case False{}: more(rest,stack)

def deep.universal(structured: Bool, constructed: Bool, +number: U32, body: List<&2,U32>, rest: List<&2,U32>,
  stack: List<&2,List<&2,U32>>, more: List<&2,U32> -> List<&2,List<&2,U32>> -> Bool) -> Bool:
  match structured constructed:
    case True{} True{}: more(body,Con{rest,stack})
    case False{} False{}: Bool.and(leaf(number,body),more(rest,stack))
    case _ _: False{}

def deep.kind(universal: Bool, constructed: Bool, +number: U32, body: List<&2,U32>, rest: List<&2,U32>,
  stack: List<&2,List<&2,U32>>, more: List<&2,U32> -> List<&2,List<&2,U32>> -> Bool) -> Bool:
  match universal:
    case True{}:
      deep.universal(Bool.or(U32.is_eq(number,16),U32.is_eq(number,17)),constructed,number,body,rest,stack,more)
    case False{}: deep.walk(constructed,body,rest,stack,more)

def deep.element(value: Maybe<&1,D.Element>, stack: List<&2,List<&2,U32>>,
  more: List<&2,U32> -> List<&2,List<&2,U32>> -> Bool) -> Bool:
  match value:
    case Some{D.Element{+tag,body,rest,_}}:
      deep.kind(U32.is_eq(U32.and(tag,192),0),U32.is_ne(U32.and(tag,32),0),U32.and(tag,31),body,rest,stack,more)
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

# A system bundle's OpenSSL TRUSTED CERTIFICATE block is framed here like a
# CERTIFICATE block and never becomes an anchor. Its contents are decoded
# in a second pass (`distrust`), once every block is framed.
def skipped(value: Result<&2,&2,Error,Parsed>, roots: List<&2,List<&2,U32>>,
  next: List<&2,U32> -> List<&2,List<&2,U32>> -> Result<&2,&2,Error,List<&2,List<&2,U32>>>) -> Result<&2,&2,Error,List<&2,List<&2,U32>>>:
  match value:
    case Done{Parsed{_,rest}}: next(rest,roots)
    case Fail{error}: Fail{error}

def start.more(trusted: Bool, bad: Bool, +rest: List<&2,U32>, roots: List<&2,List<&2,U32>>,
  next: List<&2,U32> -> List<&2,List<&2,U32>> -> Result<&2,&2,Error,List<&2,List<&2,U32>>>) -> Result<&2,&2,Error,List<&2,List<&2,U32>>>:
  match trusted bad:
    case True{} _: skipped(body(Nat.add(B.length(rest),1n),True{},rest,[]),roots,next)
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
      parsed(body(Nat.add(B.length(rest),1n),False{},rest,Con{10,List.reverse(&2,U32,Utf.encode(text))}),system,roots,r => acc => next(U32.sub(left,1),r,acc))
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

# OpenSSL trust settings
# ----------------------
# A TRUSTED CERTIFICATE block is a certificate followed by an optional
# X509_CERT_AUX trailer (OpenSSL's d2i_X509_AUX):
#   SEQUENCE { trust   SEQUENCE OF OBJECT IDENTIFIER OPTIONAL,
#              reject  [0] IMPLICIT SEQUENCE OF OBJECT IDENTIFIER OPTIONAL,
#              alias   UTF8String OPTIONAL,
#              keyid   OCTET STRING OPTIONAL,
#              other   [1] IMPLICIT SEQUENCE OF AlgorithmIdentifier OPTIONAL }
# The certificate gets the nested checks a plain anchor gets (`framed`), and
# each `other` element is an AlgorithmIdentifier checked like a signature
# algorithm's (`algorithm`).
# The block withholds TLS server trust from its certificate when reject
# names serverAuth or anyExtendedKeyUsage, or when a trust list names
# neither (OpenSSL's X509_TRUST_REJECTED and X509_TRUST_UNTRUSTED). Every
# plain anchor with the same DER bytes is then dropped, whatever the order
# of the blocks. A certificate or trailer that does not parse fails the
# whole load.
type Oids is Data:
  Oids{valid: Bool, server: Bool}

type Aux is Data:
  Aux{valid: Bool, stage: U32, restricted: Bool, rejected: Bool}

# serverAuth (1.3.6.1.5.5.7.3.1) or anyExtendedKeyUsage (2.5.29.37.0)
def server(+oid: List<&2,U32>) -> Bool:
  Bool.or(C.anchor.equal(oid,[43,6,1,5,5,7,3,1]),C.anchor.equal(oid,[85,29,37,0]))

def oids.next(valid: Bool, rest: List<&2,U32>, found: Bool,
  next: List<&2,U32> -> Bool -> Oids) -> Oids:
  match valid:
    case True{}: next(rest,found)
    case False{}: Oids{False{},False{}}

def oids.element(value: Maybe<&1,D.Element>, found: Bool,
  next: List<&2,U32> -> Bool -> Oids) -> Oids:
  match value:
    case Some{D.Element{+tag,+body,rest,_}}:
      oids.next(Bool.and(U32.is_eq(tag,6),O.contents(body)),rest,Bool.or(found,server(body)),next)
    case None{}: Oids{False{},False{}}

def oids(fuel: Nat, bytes: List<&2,U32>, found: Bool) -> Oids:
  match fuel bytes:
    case _ Nil{}: Oids{True{},found}
    case 0n _: Oids{False{},False{}}
    case 1n+p bytes: oids.element(D.read(bytes),found,r => f => oids(p,r,f))

def oids.of(+bytes: List<&2,U32>) -> Oids:
  oids(Nat.add(B.length(bytes),1n),bytes,False{})

# other: SEQUENCE OF AlgorithmIdentifier, each element a whole one
def others.element(value: Maybe<&1,D.Element>, next: List<&2,U32> -> Bool) -> Bool:
  match value:
    case Some{D.Element{_,_,rest,encoded}}: Bool.and(algorithm(encoded),next(rest))
    case None{}: False{}

def others(fuel: Nat, bytes: List<&2,U32>) -> Bool:
  match fuel bytes:
    case _ Nil{}: True{}
    case 0n _: False{}
    case 1n+p bytes: others.element(D.read(bytes),r => others(p,r))

def others.of(+bytes: List<&2,U32>) -> Bool:
  others(Nat.add(B.length(bytes),1n),bytes)

def aux.trust(value: Oids, valid: Bool, rejected: Bool) -> Aux:
  match value:
    case Oids{ok,found}: Aux{Bool.and(valid,ok),1,Bool.not(found),rejected}

def aux.reject(value: Oids, valid: Bool, restricted: Bool) -> Aux:
  match value:
    case Oids{ok,found}: Aux{Bool.and(valid,ok),2,restricted,found}

# Fields in order, each at most once: trust 1, reject 2, alias 3, keyid 4,
# other 5; any other tag is stage 0 and fails.
def aux.stage(+tag: U32) -> U32:
  Bool.pick(U32,U32.is_eq(tag,48),1,Bool.pick(U32,U32.is_eq(tag,160),2,
    Bool.pick(U32,U32.is_eq(tag,12),3,Bool.pick(U32,U32.is_eq(tag,4),4,
      Bool.pick(U32,U32.is_eq(tag,161),5,0)))))

def aux.kind(trust: Bool, reject: Bool, other: Bool, +stage: U32, +body: List<&2,U32>,
  valid: Bool, restricted: Bool, rejected: Bool) -> Aux:
  match trust reject other:
    case True{} _ _: aux.trust(oids.of(body),valid,rejected)
    case False{} True{} _: aux.reject(oids.of(body),valid,restricted)
    case False{} False{} True{}:
      Aux{Bool.and(valid,others.of(body)),stage,restricted,rejected}
    case False{} False{} False{}: Aux{valid,stage,restricted,rejected}

def aux.field(+stage: U32, body: List<&2,U32>, value: Aux) -> Aux:
  match value:
    case Aux{valid,+before,restricted,rejected}:
      aux.kind(U32.is_eq(stage,1),U32.is_eq(stage,2),U32.is_eq(stage,5),stage,body,
        Bool.and(valid,U32.is_gt(stage,before)),restricted,rejected)

def aux.step(value: Maybe<&1,D.Element>, state: Aux, next: List<&2,U32> -> Aux -> Aux) -> Aux:
  match value:
    case Some{D.Element{+tag,body,rest,_}}: next(rest,aux.field(aux.stage(tag),body,state))
    case None{}: Aux{False{},0,False{},False{}}

def aux.go(fuel: Nat, bytes: List<&2,U32>, state: Aux) -> Aux:
  match fuel bytes:
    case _ Nil{}: state
    case 0n _: Aux{False{},0,False{},False{}}
    case 1n+p bytes: aux.step(D.read(bytes),state,r => a => aux.go(p,r,a))

def aux.outer(value: Maybe<&1,D.Element>) -> Aux:
  match value:
    case Some{D.Element{48,+body,Nil{},_}}: aux.go(Nat.add(B.length(body),1n),body,Aux{True{},0,False{},False{}})
    case _: Aux{False{},0,False{},False{}}

# No trailer: no trust settings.
def aux(trailer: List<&2,U32>) -> Aux:
  match trailer:
    case Nil{}: Aux{True{},0,False{},False{}}
    case bytes: aux.outer(D.read(bytes))

def distrust.aux(valid: Bool, value: Aux, cert: List<&2,U32>, rest: List<&2,U32>, out: List<&2,List<&2,U32>>,
  next: List<&2,U32> -> List<&2,List<&2,U32>> -> Result<&2,&2,Error,List<&2,List<&2,U32>>>) -> Result<&2,&2,Error,List<&2,List<&2,U32>>>:
  match valid value:
    case True{} Aux{True{},_,False{},False{}}: next(rest,out)
    case True{} Aux{True{},_,_,_}: next(rest,Con{cert,out})
    case _ _: Fail{Malformed{}}

def distrust.certificate(value: Maybe<&1,D.Element>, rest: List<&2,U32>, out: List<&2,List<&2,U32>>,
  next: List<&2,U32> -> List<&2,List<&2,U32>> -> Result<&2,&2,Error,List<&2,List<&2,U32>>>) -> Result<&2,&2,Error,List<&2,List<&2,U32>>>:
  match value:
    case Some{D.Element{48,_,trailer,+cert}}: distrust.aux(framed(C.anchor(cert)),aux(trailer),cert,rest,out,next)
    case _: Fail{Malformed{}}

def distrust.decoded(value: Result<&2,&1,P.Error,P.Block>, rest: List<&2,U32>, out: List<&2,List<&2,U32>>,
  next: List<&2,U32> -> List<&2,List<&2,U32>> -> Result<&2,&2,Error,List<&2,List<&2,U32>>>) -> Result<&2,&2,Error,List<&2,List<&2,U32>>>:
  match value:
    case Done{P.Block{P.Certificate{},bytes}}: distrust.certificate(D.read(bytes),rest,out,next)
    case _: Fail{Malformed{}}

def distrust.block(value: Result<&2,&2,Error,Parsed>, out: List<&2,List<&2,U32>>,
  next: List<&2,U32> -> List<&2,List<&2,U32>> -> Result<&2,&2,Error,List<&2,List<&2,U32>>>) -> Result<&2,&2,Error,List<&2,List<&2,U32>>>:
  match value:
    case Done{Parsed{pem,rest}}: distrust.decoded(P.decode(pem),rest,out,next)
    case Fail{error}: Fail{error}

def distrust.begin(begun: Bool, +rest: List<&2,U32>, out: List<&2,List<&2,U32>>,
  next: List<&2,U32> -> List<&2,List<&2,U32>> -> Result<&2,&2,Error,List<&2,List<&2,U32>>>) -> Result<&2,&2,Error,List<&2,List<&2,U32>>>:
  match begun:
    case True{}:
      distrust.block(body(Nat.add(B.length(rest),1n),True{},rest,
        Con{10,List.reverse(&2,U32,Utf.encode("-----BEGIN CERTIFICATE-----"))}),out,next)
    case False{}: next(rest,out)

def distrust.line(pair: String & List<&2,U32>, out: List<&2,List<&2,U32>>,
  next: List<&2,U32> -> List<&2,List<&2,U32>> -> Result<&2,&2,Error,List<&2,List<&2,U32>>>) -> Result<&2,&2,Error,List<&2,List<&2,U32>>>:
  (+text,+rest) = pair
  distrust.begin(String.eq(text,"-----BEGIN TRUSTED CERTIFICATE-----"),rest,out,next)

# The certificates that TRUSTED blocks withdraw. Runs after the first pass
# has framed every block, so only TRUSTED BEGIN lines start a block here.
def distrust(fuel: Nat, bytes: List<&2,U32>, out: List<&2,List<&2,U32>>) -> Result<&2,&2,Error,List<&2,List<&2,U32>>>:
  match fuel bytes:
    case _ Nil{}: Done{out}
    case 0n _: Fail{Limit{}}
    case 1n+p bytes: distrust.line(P.line(bytes,""),out,r => o => distrust(p,r,o))

def withdrawn.one(drop: Bool, raw: List<&2,U32>, rest: List<&2,List<&2,U32>>) -> List<&2,List<&2,U32>>:
  match drop:
    case True{}: rest
    case False{}: Con{raw,rest}

def withdrawn(roots: List<&2,List<&2,U32>>, +out: List<&2,List<&2,U32>>) -> List<&2,List<&2,U32>>:
  match roots:
    case Nil{}: []
    case Con{+raw,rest}: withdrawn.one(seen(raw,out),raw,withdrawn(rest,out))

def system.kept(roots: List<&2,List<&2,U32>>) -> Result<&2,&2,Error,List<&2,List<&2,U32>>>:
  match roots:
    case Nil{}: Fail{Empty{}}
    case roots: Done{roots}

def system.distrusted(value: Result<&2,&2,Error,List<&2,List<&2,U32>>>, roots: List<&2,List<&2,U32>>) -> Result<&2,&2,Error,List<&2,List<&2,U32>>>:
  match value:
    case Done{out}: system.kept(withdrawn(roots,out))
    case Fail{error}: Fail{error}

def system.roots(value: Result<&2,&2,Error,List<&2,List<&2,U32>>>, +bytes: List<&2,U32>) -> Result<&2,&2,Error,List<&2,List<&2,U32>>>:
  match value:
    case Done{roots}: system.distrusted(distrust(Nat.add(B.length(bytes),1n),bytes,[]),roots)
    case Fail{error}: Fail{error}

# Same limits and whole-load rejection of malformed entries, for a host's
# system bundle only: byte-identical duplicate certificates are dropped (each
# still counts toward the 256 blocks); OpenSSL TRUSTED CERTIFICATE blocks are
# not anchors and do not count, but their trust settings can withdraw an
# anchor (above). A distinct certificate always needs its own CERTIFICATE
# block.
def decode.system(+bytes: List<&2,U32>) -> Result<&2,&2,Error,List<&2,List<&2,U32>>>:
  system.roots(decode.checked(within(bytes,2097152),True{},bytes),bytes)
