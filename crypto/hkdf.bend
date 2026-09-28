import Base
import ./sha256.bend as Sha
import ./hmac.bend as Hmac

# HKDF-SHA-256 (RFC 5869). Extract accepts an empty salt; HMAC pads it with
# zero bytes exactly as the RFC's default 32-byte zero salt does.

def extract(salt: List<&2, U32>, ikm: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  Hmac.digest(salt, ikm)

def next_message(prev: List<&2, U32>, info: List<&2, U32>, counter: U32) -> List<&2, U32>:
  List.append(&2, U32, prev, List.append(&2, U32, info, [counter]))

def expand.go(fuel: Nat, +prk: List<&2, U32>, +info: List<&2, U32>, +counter: U32,
              acc: List<&2, U32>, cur: Maybe<&2, List<&2, U32>>) -> Maybe<&2, List<&2, U32>>:
  match fuel cur:
    case 0n _:
      Some{acc}
    case 1n+p None{}:
      None{}
    case 1n+p Some{+block}:
      expand.go(p, prk, info, U32.inc(counter), List.append(&2, U32, acc, block),
        Hmac.digest(prk, next_message(block, info, U32.inc(counter))))

def finish(length: Nat, result: Maybe<&2, List<&2, U32>>) -> Maybe<&2, List<&2, U32>>:
  match result:
    case None{}:
      None{}
    case Some{bytes}:
      Some{List.take(&2, U32, bytes, length)}

def expand.valid(+length: Nat, +prk: List<&2, U32>, +info: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  finish(length, expand.go(Nat.div(Nat.add(length, 31n), 32n), prk, info, 1, [],
    Hmac.digest(prk, next_message([], info, 1))))

def expand.checked(ok: Bool, length: Nat, prk: List<&2, U32>, info: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match ok:
    case False{}:
      None{}
    case True{}:
      expand.valid(length, prk, info)

# RFC 5869 permits at most 255 hash blocks, or 8160 bytes for SHA-256.
# A PRK from extract has exactly 32 bytes.
def expand(+length: Nat, +prk: List<&2, U32>, +info: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  expand.checked(Bool.and(Nat.is_le(length, 8160n),
    Bool.and(Nat.is_eq(List.length(&2, U32, prk), 32n),
      Bool.and(Sha.valid(prk), Sha.valid(info)))), length, prk, info)

def hex_of(result: Maybe<&2, List<&2, U32>>) -> Maybe<&2, String>:
  match result:
    case None{}:
      None{}
    case Some{bytes}:
      Some{Sha.hex(bytes)}

def extract_hex(salt: List<&2, U32>, ikm: List<&2, U32>) -> Maybe<&2, String>:
  hex_of(extract(salt, ikm))

def expand_hex(length: Nat, prk: List<&2, U32>, info: List<&2, U32>) -> Maybe<&2, String>:
  hex_of(expand(length, prk, info))
