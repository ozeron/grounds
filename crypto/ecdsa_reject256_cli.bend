import Base
import ./ecdsa_sign256.bend as S
import ./p256.bend as P
import ./bytes.bend as B
import ../io/io.bend as Io

# Synthetic-only rejection fixtures. No external protocol calls these hooks.
# Short fixture opcodes keep literal-pattern expansion bounded:
# 0=known nonce, 1=zero r, 2=reject, 3=no candidate, 4=no signature,
# 5=actual noncanonical/zero candidate validation.
def signature(value: Maybe<&1, List<&2, U32>>) -> IO(Unit):
  match value:
    case None{}:
      IO.print("invalid")
    case Some{value}:
      IO.print(B.hex(value))

def nonce(value: Maybe<&2, S.Nonce>) -> IO(Unit):
  match value:
    case None{}:
      IO.print("invalid")
    case Some{S.Nonce{key, value}}:
      IO.print(B.hex(B.append(key, value)))

def searched(value: S.Search) -> IO(Unit):
  match value:
    case S.SignAgain{state}:
      nonce(Some{state})
    case _:
      IO.print("unexpected")

# The artificial point's x is the scalar order n; it is intentionally not
# obtained from scalar multiplication. It exercises only r=0 rejection.
def order_be() -> List<&2, U32>:
  [255, 255, 255, 255, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 188, 230, 250, 173, 167, 23, 158, 132, 243, 185, 202, 194, 252, 99, 37, 81]

def scalar(mode: String, private: List<&2, U32>, digest: List<&2, U32>, k: List<&2, U32>) -> IO(Unit):
  match mode:
    case "0":
      signature(S.sign.raw(private, digest, k))
    case "1":
      signature(S.sign.point(private, digest, k,
        Some{Con{4, B.append(order_be(), List.replicate(U32, 32n, 0))}}))
    case _:
      IO.die(Unit, 2, "unknown scalar fixture")

def read_scalar(mode: String, private_path: String, digest_path: String, k_path: String) -> IO(Unit):
  do IO<Unit>:
    private : List<&2, U32> <- Io.read_bytes(private_path)
    digest : List<&2, U32> <- Io.read_bytes(digest_path)
    k : List<&2, U32> <- Io.read_bytes(k_path)
    scalar(mode, private, digest, k)

def rejection(mode: String, key: List<&2, U32>, value: List<&2, U32>) -> IO(Unit):
  match mode:
    case "2":
      nonce(S.rejected(S.Nonce{key, value}))
    case "3":
      searched(S.search.candidate(S.Nonce{key, value}, [], [], None{}))
    case "4":
      searched(S.search.signature(S.Nonce{key, value}, None{}))
    case "5":
      searched(S.search.value(key, [], [], Some{value}))
    case _:
      IO.die(Unit, 2, "unknown rejection fixture")

def read_rejection(mode: String, key_path: String, value_path: String) -> IO(Unit):
  do IO<Unit>:
    key : List<&2, U32> <- Io.read_bytes(key_path)
    value : List<&2, U32> <- Io.read_bytes(value_path)
    rejection(mode, key, value)

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Nil{}:
      IO.pure(Unit, Unit{})
    case Con{"0", Con{a, Con{b, Con{c, tail}}}}:
      do IO<Unit>:
        read_scalar("0", a, b, c)
        dispatch(tail)
    case Con{"1", Con{a, Con{b, Con{c, tail}}}}:
      do IO<Unit>:
        read_scalar("1", a, b, c)
        dispatch(tail)
    case Con{mode, Con{a, Con{b, tail}}}:
      do IO<Unit>:
        read_rejection(mode, a, b)
        dispatch(tail)
    case _:
      IO.die(Unit, 2, "usage: ecdsa_reject256_cli <mode> <files>")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
