import Base
import ./pem.bend as P
import ./bytes.bend as B
import ./x509_certificate.bend as C
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

def body.line(pair: String & List<&2,U32>, collected: List<&2,U32>,
  more: List<&2,U32> -> List<&2,U32> -> Result<&2,&2,Error,Parsed>) -> Result<&2,&2,Error,Parsed>:
  (+text,+rest) = pair
  match text:
    case "-----END CERTIFICATE-----":
      Done{Parsed{List.reverse(&2,U32,List.reverse.go(&2,U32,Utf.encode(text),collected)),rest}}
    case text:
      body.more(delimiter(text),rest,Con{10,List.reverse.go(&2,U32,Utf.encode(text),collected)},more)

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

def certificate(+raw: List<&2,U32>, value: Maybe<&1,C.Tbs>, +roots: List<&2,List<&2,U32>>,
  next: List<&2,List<&2,U32>> -> Result<&2,&2,Error,List<&2,List<&2,U32>>>) -> Result<&2,&2,Error,List<&2,List<&2,U32>>>:
  match value:
    case None{}: Fail{Malformed{}}
    case Some{_}: unique(seen(raw,roots),raw,roots,next)

def block(value: Result<&2,&1,P.Error,P.Block>, roots: List<&2,List<&2,U32>>,
  next: List<&2,List<&2,U32>> -> Result<&2,&2,Error,List<&2,List<&2,U32>>>) -> Result<&2,&2,Error,List<&2,List<&2,U32>>>:
  match value:
    case Done{P.Block{P.Certificate{},+der}}: certificate(der,C.anchor(der),roots,next)
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

def start.line(pair: String & List<&2,U32>, +left: U32, roots: List<&2,List<&2,U32>>,
  next: U32 -> List<&2,U32> -> List<&2,List<&2,U32>> -> Result<&2,&2,Error,List<&2,List<&2,U32>>>) -> Result<&2,&2,Error,List<&2,List<&2,U32>>>:
  (+text,+rest) = pair
  match text left:
    case "-----BEGIN CERTIFICATE-----" 0: Fail{Limit{}}
    case "-----BEGIN CERTIFICATE-----" left:
      parsed(body(Nat.add(B.length(rest),1n),rest,Con{10,List.reverse(&2,U32,Utf.encode(text))}),roots,r => acc => next(U32.sub(left,1),r,acc))
    case text _:
      start.more(delimiter(text),rest,roots,r => acc => next(left,r,acc))

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
