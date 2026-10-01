import Base
import ./tls_record.bend as R
import ../crypto/traffic.bend as T

def frame_rejects_bad_byte() -> {R.frame([23, 3, 3, 0, 17, 256]) == R.Bad{R.Invalid{}} : R.Frame}:
  {==}

def overflow(pair: T.WriteKey & Result<&2, &2, R.Error, List<&2, U32>>) -> Bool:
  (_, result) = pair
  match result:
    case Fail{R.Overflow{}}: True{}
    case _: False{}

def largest_padding() -> Nat:
  Nat.add(Nat.mul(65535n, Nat.add(4294967295n, 1n)), 4294967295n)

def largest_padding_guard() -> {overflow(R.seal(T.WriteKey{T.Gone{}, T.Generation{0, 0}}, 23, largest_padding(), [])) == True{} : Bool}:
  {==}
