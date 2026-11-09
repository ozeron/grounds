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

# TLS 1.2 record version (M7 review fix): only 0x0303 reaches the read owner;
# a gone owner reports Crypto{Invalid} once the version passes.
def version12(pair: T.ReadKey & Result<&2, &2, R.Error, R.Record>) -> U32:
  (_, result) = pair
  match result:
    case Fail{R.Version{}}: 1
    case Fail{R.Crypto{T.Invalid{}}}: 2
    case _: 0

def open12_version(+kind: U32, +major: U32, +minor: U32) -> U32:
  version12(R.open12(T.ReadKey{T.Gone{}}, [kind, major, minor, 0, 24], List.replicate(U32, 24n, 0)))

def open12_rejects_0000() -> {open12_version(23, 0, 0) == 1 : U32}:
  {==}

def open12_rejects_0301() -> {open12_version(22, 3, 1) == 1 : U32}:
  {==}

def open12_rejects_0302() -> {open12_version(21, 3, 2) == 1 : U32}:
  {==}

def open12_rejects_0304() -> {open12_version(23, 3, 4) == 1 : U32}:
  {==}

def open12_rejects_0203() -> {open12_version(23, 2, 3) == 1 : U32}:
  {==}

def open12_admits_0303() -> {open12_version(23, 3, 3) == 2 : U32}:
  {==}

# TLS 1.3 framing still ignores the legacy version (authenticated as AAD).
def frame13_keeps_version() -> {R.frame([23, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]) == R.Framed{[23, 0, 0, 0, 16], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], []} : R.Frame}:
  {==}
