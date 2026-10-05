import Base
import ../crypto/bytes.bend as B

# Reassemble complete handshake encodings from TLS handshake record payloads
# (RFC 9846 5.1). Each feed is ONE plaintext/decrypted record, not a TCP read.
# Bodies and full TLS state/epoch/record authentication are caller-owned.

type Error is Data:
  Invalid{}
  Overflow{}
  Alignment{}

type Partial is Type:
  Header{reversed: List<&2, U32>, used: Nat}
  Body{kind: U32, reversed: List<&2, U32>, left: Nat}

type Decoder is Type:
  Decoder{partial: Partial, admitted: Nat}

type Batch is Type:
  Batch{decoder: Decoder, messages: List<&2, List<&2, U32>>}

def start() -> Decoder:
  Decoder{Header{[], 0n}, 0n}

def limit() -> Nat:
  1048576n

def length(a: U32, b: U32, c: U32) -> Nat:
  Nat.add(Nat.mul(U32.to_nat(a), 65536n),
    Nat.add(Nat.mul(U32.to_nat(b), 256n), U32.to_nat(c)))

def aligned_kind(+kind: U32) -> Bool:
  Bool.or(U32.is_eq(kind, 1), Bool.or(U32.is_eq(kind, 2),
    Bool.or(U32.is_eq(kind, 5), Bool.or(U32.is_eq(kind, 20), U32.is_eq(kind, 24)))))

type Step is Type:
  Pending{partial: Partial}
  Complete{kind: U32, bytes: List<&2, U32>}

def header_length(bounded: Bool, +kind: U32, reversed: List<&2, U32>, left: Nat) -> Result<&2, &1, Error, Step>:
  match bounded left:
    case False{} _: Fail{Overflow{}}
    case True{} 0n: Done{Complete{kind, List.reverse(&2, U32, reversed)}}
    case True{} count: Done{Pending{Body{kind, reversed, count}}}

def header(reversed: List<&2, U32>) -> Result<&2, &1, Error, Step>:
  match reversed:
    case Con{+c, Con{+b, Con{+a, Con{+kind, Nil{}}}}}:
      +size = length(a, b, c)
      header_length(Nat.is_le(size, Nat.sub(limit(), 4n)), kind, [c, b, a, kind], size)
    case _: Fail{Invalid{}}

def step(byte: U32, partial: Partial) -> Result<&2, &1, Error, Step>:
  match partial:
    case Header{reversed, 0n}: Done{Pending{Header{Con{byte, reversed}, 1n}}}
    case Header{reversed, 1n}: Done{Pending{Header{Con{byte, reversed}, 2n}}}
    case Header{reversed, 2n}: Done{Pending{Header{Con{byte, reversed}, 3n}}}
    case Header{reversed, 3n}: header(Con{byte, reversed})
    case Header{_, _}: Fail{Invalid{}}
    case Body{kind, reversed, 1n}: Done{Complete{kind, List.reverse(&2, U32, Con{byte, reversed})}}
    case Body{kind, reversed, 1n+left}: Done{Pending{Body{kind, Con{byte, reversed}, left}}}
    case Body{_, _, 0n}: Fail{Invalid{}}

def after_completed(aligned: Bool, byte: U32) -> Result<&2, &1, Error, Step>:
  match aligned:
    case True{}: Fail{Alignment{}}
    case False{}: step(byte, Header{[], 0n})

# Consume each byte once; no accumulated-prefix append rescans are needed.
def consume(bytes: List<&2, U32>, state: Result<&2, &1, Error, Step>, reversed: List<&2, List<&2, U32>>, total: Nat) -> Result<&2, &1, Error, Batch>:
  match bytes state:
    case _ Fail{error}: Fail{error}
    case Nil{} Done{Pending{partial}}:
      Done{Batch{Decoder{partial, total}, List.reverse(&2, List<&2, U32>, reversed)}}
    case Nil{} Done{Complete{_, message}}:
      Done{Batch{Decoder{Header{[], 0n}, total}, List.reverse(&2, List<&2, U32>, Con{message, reversed})}}
    case Con{byte, tail} Done{Pending{partial}}:
      consume(tail, step(byte, partial), reversed, total)
    case Con{byte, tail} Done{Complete{kind, message}}:
      consume(tail, after_completed(aligned_kind(kind), byte), Con{message, reversed}, total)

def feed_valid(valid: Bool, bounded: Bool, partial: Partial, total: Nat, fragment: List<&2, U32>) -> Result<&2, &1, Error, Batch>:
  match valid bounded:
    case False{} _: Fail{Invalid{}}
    case True{} False{}: Fail{Overflow{}}
    case True{} True{}: consume(fragment, Done{Pending{partial}}, [], total)

def feed(owner: Decoder, +fragment: List<&2, U32>) -> Result<&2, &1, Error, Batch>:
  match owner:
    case Decoder{partial, +admitted}:
      +size = B.length(fragment)
      feed_valid(Bool.and(B.valid(fragment), Nat.is_gt(size, 0n)),
        Bool.and(Nat.is_le(size, 16384n), Bool.and(Nat.is_le(admitted, limit()),
          Nat.is_le(size, Nat.sub(limit(), admitted)))), partial, Nat.add(admitted, size), fragment)

# Before changing record type or keys, the handshake owner must require a
# complete-message boundary. Failure consumes all pending state.
def boundary(owner: Decoder) -> Maybe<&1, Decoder>:
  match owner:
    case Decoder{Header{Nil{}, 0n}, total}: Some{Decoder{Header{[], 0n}, total}}
    case _: None{}

def finish(owner: Decoder) -> Bool:
  match owner:
    case Decoder{Header{Nil{}, 0n}, _}: True{}
    case _: False{}
