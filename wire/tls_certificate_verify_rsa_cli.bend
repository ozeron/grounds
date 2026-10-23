import Base
import ./tls_certificate_verify.bend as C
import ../crypto/rsa_private.bend as S
import ../crypto/bytes.bend as B
import ../io/io.bend as Io

# Separate evaluator keeps each generated compilation unit resource bounded.
def role(name: String) -> C.Role:
  match name:
    case "s": C.Server{}
    case _: C.Client{}

def emit(+n: List<&2, U32>, +e: List<&2, U32>, +r: C.Role, +hash: List<&2, U32>, value: Maybe<&1, List<&2, U32>>) -> IO(Unit):
  match value:
    case None{}: IO.print("invalid")
    case Some{+bytes}:
      do IO<Unit>:
        IO.print(B.hex(bytes))
        IO.print(Bool.pick(String, C.verify_rsa(n, e, r, hash, bytes), "true", "false"))

def sign(+r: C.Role, +folder: String, hash: String, salt: String, blind: String) -> IO(Unit):
  do IO<Unit>:
    +n : List<&2, U32> <- Io.read_bytes(folder ++ "/n")
    +e : List<&2, U32> <- Io.read_bytes(folder ++ "/e")
    d : List<&2, U32> <- Io.read_bytes(folder ++ "/d")
    p : List<&2, U32> <- Io.read_bytes(folder ++ "/p")
    q : List<&2, U32> <- Io.read_bytes(folder ++ "/q")
    dp : List<&2, U32> <- Io.read_bytes(folder ++ "/dp")
    dq : List<&2, U32> <- Io.read_bytes(folder ++ "/dq")
    qi : List<&2, U32> <- Io.read_bytes(folder ++ "/qi")
    +h : List<&2, U32> <- Io.read_bytes(hash)
    s : List<&2, U32> <- Io.read_bytes(salt)
    b : List<&2, U32> <- Io.read_bytes(blind)
    emit(n, e, r, h, C.sign_rsa(S.Private{n, e, d, p, q, dp, dq, qi}, r, h, s, b))

def loop(args: List<String>) -> IO(Unit):
  match args:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{"sign", Con{r, Con{folder, Con{hash, Con{salt, Con{blind, rest}}}}}}:
      do IO<Unit>:
        sign(role(r), folder, hash, salt, blind)
        loop(rest)
    case _: IO.die(Unit, 2, "tls_certificate_verify_rsa_cli run sign <s|c> <key-folder> <hash> <salt> <blind>")

def args(args: List<String>) -> IO(Unit):
  match args:
    case Con{"run", rest}: loop(rest)
    case Con{_, Con{"run", rest}}: loop(rest)
    case _: IO.die(Unit, 2, "tls_certificate_verify_rsa_cli run <commands>")

def main() -> IO(Unit):
  do IO<Unit>:
    values : List<String> <- Io.args()
    args(values)
