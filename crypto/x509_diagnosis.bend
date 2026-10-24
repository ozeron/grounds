import Base
import ./der.bend as D
import ./x509_algorithm.bend as A
import ./x509_certificate.bend as C
import ./bytes.bend as B

# Failure diagnosis only; never an alternative admission path. Require a
# framed TBS and matching inner/outer algorithms, an octet-aligned nonempty
# signature, and one syntactically framed AlgorithmIdentifier. Bad parameters
# of an implemented algorithm remain malformed rather than being relabeled.
def equal(a: List<&2,U32>, b: List<&2,U32>) -> Bool:
  match a b:
    case Nil{} Nil{}: True{}
    case Con{x,xs} Con{y,ys}: Bool.and(U32.is_eq(x,y),equal(xs,ys))
    case _ _: False{}

def parameters(value: Maybe<&1,D.Element>) -> Bool:
  match value:
    case Some{D.Element{_,_,Nil{},_}}: True{}
    case _: False{}

def identifier(value: Maybe<&1,A.Identifier>) -> Bool:
  match value:
    case Some{A.Identifier{+oid,Nil{}}}:
      Bool.and(Nat.is_ge(B.length(oid),1n),U32.is_eq(A.oid.kind(oid),0))
    case Some{A.Identifier{+oid,rest}}:
      Bool.and(Bool.and(Nat.is_ge(B.length(oid),1n),U32.is_eq(A.oid.kind(oid),0)),parameters(D.read(rest)))
    case _: False{}

def signature(value: Maybe<&1,List<&2,U32>>) -> Bool:
  match value:
    case Some{Con{0,Con{_,_}}}: True{}
    case _: False{}

def outer(tbs: Maybe<&1,C.Tbs>, value: Maybe<&1,D.Element>) -> Bool:
  match tbs value:
    case Some{C.Tbs{C.Header{_,_,_,inner},_,_}} Some{D.Element{48,_,rest,+encoded}}:
      Bool.and(equal(inner,encoded),Bool.and(identifier(A.identifier(encoded)),signature(D.complete(3,rest))))
    case _ _: False{}

def tbs(value: Maybe<&1,D.Element>) -> Bool:
  match value:
    case Some{D.Element{48,+body,rest,encoded}}:
      outer(C.version(encoded,body,D.read(body)),D.read(rest))
    case _: False{}

def body(value: Maybe<&1,List<&2,U32>>) -> Bool:
  match value:
    case Some{bytes}: tbs(D.read(bytes))
    case _: False{}

def unsupported_signature(raw: List<&2,U32>) -> Bool:
  body(D.complete(48,raw))
