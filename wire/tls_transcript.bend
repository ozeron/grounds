import Base
import ../crypto/bytes.bend as B
import ../crypto/sha256_stream.bend as S

# SHA-256 transcript of complete encoded handshake messages (RFC 9846 4.1).
# Record headers, fragmentation/reassembly, message bodies and full role/order
# validation belong to the handshake owner. Failed admission consumes this owner.
# This module stores a streaming hash, not the full transcript. Snapshots copy
# only public transcript-hash state; they are not key or secret duplication APIs.

type Prefix is Data:
  Empty{}
  ClientHello{}
  Continued{}

type Transcript is Type:
  Transcript{stream: S.Stream, prefix: Prefix, bytes: Nat}

def start() -> Transcript:
  Transcript{S.start(), Empty{}, 0n}

# Local profile bound over all encoded transcript bytes, including headers.
# Every body still has its exact uint24 wire length checked separately.
def limit() -> Nat:
  1048576n

def size(a: U32, b: U32, c: U32) -> Nat:
  Nat.add(Nat.mul(U32.to_nat(a), 65536n),
    Nat.add(Nat.mul(U32.to_nat(b), 256n), U32.to_nat(c)))

def framed(bytes: List<&2, U32>) -> Bool:
  match bytes:
    case Con{+kind, Con{+a, Con{+b, Con{+c, +body}}}}:
      Bool.and(Bool.not(U32.is_eq(kind, 254)),
        Bool.and(B.valid(Con{kind, Con{a, Con{b, Con{c, body}}}}),
          Nat.is_eq(size(a, b, c), B.length(body))))
    case _:
      False{}

def retry_random() -> List<&2, U32>:
  [207, 33, 173, 116, 229, 154, 97, 17, 190, 29, 140, 2, 30, 101, 184, 145,
   194, 162, 17, 22, 122, 187, 140, 94, 7, 158, 9, 226, 200, 168, 51, 156]

def same(xs: List<&2, U32>, ys: List<&2, U32>) -> Bool:
  match xs ys:
    case Nil{} Nil{}: True{}
    case Con{x, xt} Con{y, yt}: Bool.and(U32.is_eq(x, y), same(xt, yt))
    case _ _: False{}

def is_retry(bytes: List<&2, U32>) -> Bool:
  match bytes:
    case Con{2, Con{_, Con{_, Con{_, Con{_, Con{_, tail}}}}}}:
      same(List.take(&2, U32, tail, 32n), retry_random())
    case _:
      False{}

def wrapped(prefix: Prefix, bytes: Nat, value: Maybe<&1, S.Stream>) -> Maybe<&1, Transcript>:
  match value:
    case None{}: None{}
    case Some{stream}: Some{Transcript{stream, prefix, bytes}}

def retry_seed(message: List<&2, U32>, bytes: Nat, value: Maybe<&1, S.Stream>) -> Maybe<&1, Transcript>:
  match value:
    case None{}: None{}
    case Some{stream}: wrapped(Continued{}, bytes, S.update(message, stream))

def retry_hash(message: List<&2, U32>, bytes: Nat, value: Maybe<&2, List<&2, U32>>) -> Maybe<&1, Transcript>:
  match value:
    case None{}: None{}
    case Some{hash}:
      retry_seed(message, bytes, S.update(B.append([254, 0, 0, 32], hash), S.start()))

def retry(prefix: Prefix, message: List<&2, U32>, stream: S.Stream, bytes: Nat) -> Maybe<&1, Transcript>:
  match prefix:
    case ClientHello{}: retry_hash(message, bytes, S.finish(stream))
    case _: None{}

def ordinary(prefix: Prefix, message: List<&2, U32>, stream: S.Stream, bytes: Nat) -> Maybe<&1, Transcript>:
  match prefix message:
    case Empty{} Con{1, tail}:
      wrapped(ClientHello{}, bytes, S.update(Con{1, tail}, stream))
    case Empty{} _:
      None{}
    case _ value:
      wrapped(Continued{}, bytes, S.update(value, stream))

def append_kind(retrying: Bool, prefix: Prefix, message: List<&2, U32>, stream: S.Stream, bytes: Nat) -> Maybe<&1, Transcript>:
  match retrying:
    case True{}: retry(prefix, message, stream, bytes)
    case False{}: ordinary(prefix, message, stream, bytes)

def append_valid(valid: Bool, owner: Transcript, +message: List<&2, U32>, length: Nat) -> Maybe<&1, Transcript>:
  match valid owner:
    case False{} _: None{}
    case True{} Transcript{stream, prefix, bytes}:
      append_kind(is_retry(message), prefix, message, stream, Nat.add(bytes, length))

def append_bounded(bounded: Bool, owner: Transcript, +message: List<&2, U32>, length: Nat) -> Maybe<&1, Transcript>:
  match bounded:
    case False{}: None{}
    case True{}: append_valid(framed(message), owner, message, length)

def append(owner: Transcript, +message: List<&2, U32>) -> Maybe<&1, Transcript>:
  match owner:
    case Transcript{stream, prefix, +bytes}:
      +length = B.length(message)
      append_bounded(Bool.and(Nat.is_le(bytes, limit()), Nat.is_le(length, Nat.sub(limit(), bytes))),
        Transcript{stream, prefix, bytes}, message, length)

# Finishing a snapshot must not consume the continuing public transcript state.
def snapshot(owner: Transcript) -> Transcript & Maybe<&2, List<&2, U32>>:
  match owner:
    case Transcript{S.Stream{+state, +pending, +used, +high, +low}, prefix, bytes}:
      (Transcript{S.Stream{state, pending, used, high, low}, prefix, bytes},
        S.finish(S.Stream{state, pending, used, high, low}))

def finish(owner: Transcript) -> Maybe<&2, List<&2, U32>>:
  match owner:
    case Transcript{stream, _, _}: S.finish(stream)
