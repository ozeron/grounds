import Base
import ./bytes.bend as B
import ./sha256.bend as S

# Byte-aligned SHA-256 streaming. Compression stays in S; this owner retains
# fewer than 64 reversed pending bytes and an exact two-word byte count.
type Stream is Type:
  Stream{state: S.State, pending: List<&2, U32>, used: U32, high: U32, low: U32}

def start() -> Stream:
  Stream{S.initial(), [], 0, 0, 0}

def count_ok(high: U32) -> Bool:
  U32.is_lt(high, 536870912)

def count_high(high: U32, low: U32) -> U32:
  U32.add(high, Bool.pick(U32, U32.is_eq(low, 0), 1, 0))

def bit_length(+high: U32, +low: U32) -> List<&2, U32>:
  S.word_bytes(U32.or(U32.shln(high, 3n), U32.shrn(low, 29n)),
    S.word_bytes(U32.shln(low, 3n), []))

def state_ok(+pending: List<&2, U32>, +used: U32, high: U32, low: U32) -> Bool:
  Bool.and(count_ok(high), Bool.and(U32.is_lt(used, 64),
    Bool.and(U32.is_eq(used, U32.and(low, 63)),
      Bool.and(Nat.is_eq(B.length(pending), U32.to_nat(used)), B.valid(pending)))))

def compressed(value: List<&2, U32> & S.State) -> S.State:
  (_, state) = value
  state

def step.full(full: Bool, byte: U32, state: S.State, pending: List<&2, U32>, used: U32, high: U32, low: U32) -> Stream:
  match full:
    case True{}:
      Stream{compressed(S.block(List.reverse(&2, U32, Con{byte, pending}), state)), [], 0, high, low}
    case False{}:
      Stream{state, Con{byte, pending}, U32.inc(used), high, low}

def step.valid(valid: Bool, full: Bool, byte: U32, state: S.State, pending: List<&2, U32>, used: U32, high: U32, low: U32) -> Maybe<&1, Stream>:
  match valid:
    case False{}:
      None{}
    case True{}:
      Some{step.full(full, byte, state, pending, used, high, low)}

def step(+byte: U32, state: S.State, pending: List<&2, U32>, +used: U32, high: U32, low: U32) -> Maybe<&1, Stream>:
  +next_low = U32.inc(low)
  +next_high = count_high(high, next_low)
  step.valid(Bool.and(U32.is_le(byte, 255), count_ok(next_high)), U32.is_eq(used, 63),
    byte, state, pending, used, next_high, next_low)

def update.go(bytes: List<&2, U32>, owner: Maybe<&1, Stream>) -> Maybe<&1, Stream>:
  match bytes owner:
    case Nil{} value:
      value
    case Con{_, _} None{}:
      None{}
    case Con{byte, tail} Some{Stream{state, pending, used, high, low}}:
      update.go(tail, step(byte, state, pending, used, high, low))

def update.valid(valid: Bool, bytes: List<&2, U32>, owner: Stream) -> Maybe<&1, Stream>:
  match valid:
    case False{}:
      None{}
    case True{}:
      update.go(bytes, Some{owner})

def update(bytes: List<&2, U32>, owner: Stream) -> Maybe<&1, Stream>:
  match owner:
    case Stream{state, +pending, +used, +high, +low}:
      update.valid(state_ok(pending, used, high, low), bytes, Stream{state, pending, used, high, low})

def padded(pending: List<&2, U32>, used: U32, high: U32, low: U32) -> List<&2, U32>:
  after = Nat.add(U32.to_nat(used), 1n)
  zeros = Nat.mod(Nat.add(56n, Nat.sub(64n, after)), 64n)
  B.append(List.reverse(&2, U32, pending),
    Con{128, B.append(List.replicate(U32, zeros, 0), bit_length(high, low))})

def finish.padded(state: S.State, +bytes: List<&2, U32>) -> List<&2, U32>:
  S.output(S.blocks(Nat.div(B.length(bytes), 64n), S.Chain{bytes, state}))

def finish.valid(valid: Bool, state: S.State, pending: List<&2, U32>, used: U32, high: U32, low: U32) -> Maybe<&2, List<&2, U32>>:
  match valid:
    case False{}:
      None{}
    case True{}:
      Some{finish.padded(state, padded(pending, used, high, low))}

def finish(owner: Stream) -> Maybe<&2, List<&2, U32>>:
  match owner:
    case Stream{state, +pending, +used, +high, +low}:
      finish.valid(state_ok(pending, used, high, low), state, pending, used, high, low)

def finish_hex(owner: Stream) -> Maybe<&2, String>:
  S.digest_hex.got(finish(owner))
