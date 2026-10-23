import Base
import ./private_key.bend as K
import ./pem.bend as P
import ./rsa_private.bend as R
import ./bytes.bend as B
import ../io/io.bend as Io

# Synthetic fixture diagnostics expose PUBLIC parameters only.
def show(value: Maybe<&1, K.Private>) -> String:
  match value:
    case Some{K.P256{_, public}}:
      String.concat(["p256:", B.hex(public)])
    case Some{K.Rsa{R.Private{n, e, _, _, _, _, _, _}}}:
      String.concat(["rsa:", B.hex(n), ":", B.hex(e)])
    case None{}:
      "none"

def imported(value: Result<&2, &1, P.Error, K.Private>) -> String:
  match value:
    case Done{key}:
      show(Some{key})
    case Fail{P.Encrypted{}}:
      "encrypted"
    case Fail{_}:
      "none"

def read.got(mode: String, bytes: List<&2, U32>) -> IO(Unit):
  match mode:
    case "pem":
      IO.print(imported(K.pem(bytes)))
    case "sec1":
      IO.print(show(K.sec1(False{}, bytes)))
    case "pkcs1":
      IO.print(show(K.pkcs1(bytes)))
    case "pkcs8":
      IO.print(show(K.pkcs8(bytes)))
    case _:
      IO.die(Unit, 2, "unsupported private-key fixture mode")

def read(mode: String, path: String) -> IO(Unit):
  do IO<Unit>:
    bytes : List<&2, U32> <- Io.read_bytes(path)
    read.got(mode, bytes)

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case Nil{}:
      IO.pure(Unit, Unit{})
    case Con{mode, Con{path, rest}}:
      do IO<Unit>:
        read(mode, path)
        dispatch(rest)
    case _:
      IO.die(Unit, 2, "usage: private_key_cli <pem|sec1|pkcs1|pkcs8> <file> ...")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- Io.args()
    dispatch(args)
