import Base
import ./tls_transcript256.bend as S256
import ./tls_transcript384.bend as S384

# Retain both public streaming states until ServerHello/HRR selects its suite.
# Selection consumes and drops the other state, including before HRR rewrite.
# Subsequent attempts to switch transcript hash fail closed.
type Transcript is Type:
  Pending{sha256: S256.Transcript, sha384: S384.Transcript}
  Sha256{owner: S256.Transcript}
  Sha384{owner: S384.Transcript}
  Invalid{}

def start() -> Transcript:
  Pending{S256.start(),S384.start()}

def framed(bytes: List<&2,U32>) -> Bool:
  S256.framed(bytes)

def select(large: Bool, owner: Transcript) -> Transcript:
  match large owner:
    case False{} Pending{owner,_}: Sha256{owner}
    case True{} Pending{_,owner}: Sha384{owner}
    case False{} Sha256{owner}: Sha256{owner}
    case True{} Sha384{owner}: Sha384{owner}
    case _ _: Invalid{}

def append.pending(a: Maybe<&1,S256.Transcript>, b: Maybe<&1,S384.Transcript>) -> Maybe<&1,Transcript>:
  match a b:
    case Some{a} Some{b}: Some{Pending{a,b}}
    case _ _: None{}

def append.sha256(value: Maybe<&1,S256.Transcript>) -> Maybe<&1,Transcript>:
  match value:
    case Some{owner}: Some{Sha256{owner}}
    case None{}: None{}

def append.sha384(value: Maybe<&1,S384.Transcript>) -> Maybe<&1,Transcript>:
  match value:
    case Some{owner}: Some{Sha384{owner}}
    case None{}: None{}

def append(owner: Transcript, +bytes: List<&2,U32>) -> Maybe<&1,Transcript>:
  match owner:
    case Pending{a,b}: append.pending(S256.append(a,bytes),S384.append(b,bytes))
    case Sha256{a}: append.sha256(S256.append(a,bytes))
    case Sha384{b}: append.sha384(S384.append(b,bytes))
    case Invalid{}: None{}

def snapshot.pending(b: S384.Transcript, pair: S256.Transcript & Maybe<&2,List<&2,U32>>) -> Transcript & Maybe<&2,List<&2,U32>>:
  (a,hash) = pair
  (Pending{a,b},hash)

def snapshot.sha256(pair: S256.Transcript & Maybe<&2,List<&2,U32>>) -> Transcript & Maybe<&2,List<&2,U32>>:
  (a,hash) = pair
  (Sha256{a},hash)

def snapshot.sha384(pair: S384.Transcript & Maybe<&2,List<&2,U32>>) -> Transcript & Maybe<&2,List<&2,U32>>:
  (a,hash) = pair
  (Sha384{a},hash)

def snapshot(owner: Transcript) -> Transcript & Maybe<&2,List<&2,U32>>:
  match owner:
    case Pending{a,b}: snapshot.pending(b,S256.snapshot(a))
    case Sha256{a}: snapshot.sha256(S256.snapshot(a))
    case Sha384{b}: snapshot.sha384(S384.snapshot(b))
    case Invalid{}: (Invalid{},None{})

def finish(owner: Transcript) -> Maybe<&2,List<&2,U32>>:
  match owner:
    case Pending{a,_}: S256.finish(a)
    case Sha256{a}: S256.finish(a)
    case Sha384{b}: S384.finish(b)
    case Invalid{}: None{}
