import Base
import ./rsa_private.bend as R
import ./rsa_integer.bend as I
import ./rsa_signature256.bend as V
import ./bytes.bend as B
import ../io/io.bend as Io

def emit(value: Maybe<&1, List<&2, U32>>) -> IO(Unit):
  match value:
    case None{}:
      IO.print("invalid")
    case Some{signature}:
      IO.print(B.hex(signature))

def emit.valid(value: Maybe<&1, R.Private>) -> IO(Unit):
  match value:
    case None{}:
      IO.print("false")
    case Some{_}:
      IO.print("true")

def emit.checked(valid: Bool, signature: List<&2, U32>) -> IO(Unit):
  match valid:
    case False{}:
      IO.die(Unit, 3, "RSA private output failed existing Bend verifier")
    case True{}:
      IO.print(B.hex(signature))

def emit.verified(+n: List<&2, U32>, +e: List<&2, U32>, +digest: List<&2, U32>, value: Maybe<&1, List<&2, U32>>) -> IO(Unit):
  match value:
    case None{}:
      IO.print("invalid")
    case Some{+signature}:
      emit.checked(V.verify_pss_digest(n, e, digest, signature), signature)

def operation(mode: String, key: R.Private, digest: String, salt: String, blind: String) -> IO(Unit):
  match mode key:
    case "0" key:
      emit.valid(R.validate(key))
    case "1" R.Private{+n, +e, d, p, q, dp, dq, qi}:
      do IO<Unit>:
        +digest : List<&2, U32> <- Io.read_bytes(digest)
        salt : List<&2, U32> <- Io.read_bytes(salt)
        blind : List<&2, U32> <- Io.read_bytes(blind)
        emit.verified(n, e, digest, R.sign_digest(R.Private{n, e, d, p, q, dp, dq, qi}, digest, salt, blind))
    case _ _:
      IO.die(Unit, 2, "unknown RSA private operation")

def read(mode: String, n: String, e: String, d: String, p: String, q: String, dp: String, dq: String, qi: String, digest: String, salt: String, blind: String) -> IO(Unit):
  do IO<Unit>:
    n : List<&2, U32> <- Io.read_bytes(n)
    e : List<&2, U32> <- Io.read_bytes(e)
    d : List<&2, U32> <- Io.read_bytes(d)
    p : List<&2, U32> <- Io.read_bytes(p)
    q : List<&2, U32> <- Io.read_bytes(q)
    dp : List<&2, U32> <- Io.read_bytes(dp)
    dq : List<&2, U32> <- Io.read_bytes(dq)
    qi : List<&2, U32> <- Io.read_bytes(qi)
    operation(mode, R.Private{n, e, d, p, q, dp, dq, qi}, digest, salt, blind)

def arithmetic.emit(mode: String, modulus: List<&2, U32>, a: List<&2, U32>, b: List<&2, U32>) -> IO(Unit):
  match mode:
    case "2":
      IO.print(B.hex(I.encode(512n, R.product(a, b))))
    case "3":
      IO.print(B.hex(R.reduce(modulus, a)))
    case "4":
      IO.print(B.hex(R.power(modulus, a, b)))
    case "5":
      IO.print(B.hex(R.multiply(modulus, a, b)))
    case "6":
      IO.print(B.hex(R.minus_small(a, I.last_byte(b, 0))))
    case _:
      IO.die(Unit, 2, "unknown internal arithmetic operation")

def arithmetic(mode: String, modulus: String, a: String, b: String) -> IO(Unit):
  do IO<Unit>:
    modulus : List<&2, U32> <- Io.read_bytes(modulus)
    a : List<&2, U32> <- Io.read_bytes(a)
    b : List<&2, U32> <- Io.read_bytes(b)
    arithmetic.emit(mode, modulus, a, b)

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Nil{}:
      IO.pure(Unit, Unit{})
    case Con{"2", Con{n, Con{a, Con{b, tail}}}}:
      do IO<Unit>:
        arithmetic("2", n, a, b)
        dispatch(tail)
    case Con{"3", Con{n, Con{a, Con{b, tail}}}}:
      do IO<Unit>:
        arithmetic("3", n, a, b)
        dispatch(tail)
    case Con{"4", Con{n, Con{a, Con{b, tail}}}}:
      do IO<Unit>:
        arithmetic("4", n, a, b)
        dispatch(tail)
    case Con{"5", Con{n, Con{a, Con{b, tail}}}}:
      do IO<Unit>:
        arithmetic("5", n, a, b)
        dispatch(tail)
    case Con{"6", Con{n, Con{a, Con{b, tail}}}}:
      do IO<Unit>:
        arithmetic("6", n, a, b)
        dispatch(tail)
    case Con{mode, Con{n, Con{e, Con{d, Con{p, Con{q, Con{dp, Con{dq, Con{qi, Con{digest, Con{salt, Con{blind, tail}}}}}}}}}}}}:
      do IO<Unit>:
        read(mode, n, e, d, p, q, dp, dq, qi, digest, salt, blind)
        dispatch(tail)
    case _:
      IO.die(Unit, 2, "usage: rsa_private_cli <0=validate|1=sign> <n> <e> <d> <p> <q> <dp> <dq> <qi> <digest> <salt> <blind>")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- Io.args()
    dispatch(args)
