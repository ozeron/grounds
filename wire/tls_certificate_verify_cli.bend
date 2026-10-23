import Base
import ./tls_certificate_verify.bend as C
import ../crypto/bytes.bend as B
import ../crypto/x509_public_key.bend as K
import ../crypto/x509_algorithm.bend as A
import ../io/io.bend as Io

# Synthetic-key evaluator only, with no live connection or credential effects.
def role(name: String) -> C.Role:
  match name:
    case "s": C.Server{}
    case _: C.Client{}

def emit(value: Maybe<&2, List<&2, U32>>) -> IO(Unit):
  match value:
    case None{}: IO.print("invalid")
    case Some{bytes}: IO.print(B.hex(bytes))

def signature(value: Maybe<&1, List<&2, U32>>) -> IO(Unit):
  match value:
    case None{}: IO.print("invalid")
    case Some{bytes}: IO.print(B.hex(bytes))

def bool(value: Bool) -> IO(Unit):
  IO.print(Bool.pick(String, value, "true", "false"))

def loop(args: List<String>) -> IO(Unit):
  match args:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{"content", Con{r, Con{path, rest}}}:
      do IO<Unit>:
        hash : List<&2, U32> <- Io.read_bytes(path)
        emit(C.content(role(r), hash))
        loop(rest)
    case Con{"digest", Con{r, Con{path, rest}}}:
      do IO<Unit>:
        hash : List<&2, U32> <- Io.read_bytes(path)
        emit(C.digest(role(r), hash))
        loop(rest)
    case Con{"ecdsa-sign", Con{r, Con{private, Con{hash, rest}}}}:
      do IO<Unit>:
        a : List<&2, U32> <- Io.read_bytes(private)
        b : List<&2, U32> <- Io.read_bytes(hash)
        signature(C.sign_ecdsa(C.EcdsaPrivate{a}, role(r), b))
        loop(rest)
    case Con{"ecdsa-verify", Con{r, Con{peer, Con{hash, Con{sig, rest}}}}}:
      do IO<Unit>:
        a : List<&2, U32> <- Io.read_bytes(peer)
        b : List<&2, U32> <- Io.read_bytes(hash)
        c : List<&2, U32> <- Io.read_bytes(sig)
        bool(C.verify(1027, K.P256{a}, role(r), b, c))
        loop(rest)
    case Con{"rsa-verify", Con{r, Con{modulus, Con{exponent, Con{hash, Con{sig, rest}}}}}}:
      do IO<Unit>:
        a : List<&2, U32> <- Io.read_bytes(modulus)
        b : List<&2, U32> <- Io.read_bytes(exponent)
        c : List<&2, U32> <- Io.read_bytes(hash)
        d : List<&2, U32> <- Io.read_bytes(sig)
        bool(C.verify(2052, K.Rsa{A.Rsa{}, a, b}, role(r), c, d))
        loop(rest)
    case Con{"rsa-restricted", Con{+r, Con{modulus, Con{exponent, Con{hash, Con{sig, rest}}}}}}:
      do IO<Unit>:
        +a : List<&2, U32> <- Io.read_bytes(modulus)
        +b : List<&2, U32> <- Io.read_bytes(exponent)
        +c : List<&2, U32> <- Io.read_bytes(hash)
        +d : List<&2, U32> <- Io.read_bytes(sig)
        bool(C.verify(2052, K.Rsa{A.PssAny{}, a, b}, role(r), c, d))
        bool(C.verify(2052, K.Rsa{A.Pss256{32}, a, b}, role(r), c, d))
        bool(C.verify(2057, K.Rsa{A.PssAny{}, a, b}, role(r), c, d))
        loop(rest)
    case Con{"guards", rest}:
      do IO<Unit>:
        emit(C.content(C.Server{}, Con{256, List.replicate(U32, 31n, 0)}))
        emit(C.digest(C.Client{}, Con{256, List.replicate(U32, 31n, 0)}))
        bool(C.verify(2052, K.Rsa{A.PssAny{}, [], []}, C.Server{}, [], []))
        bool(C.verify(2052, K.Rsa{A.Pss256{32}, [], []}, C.Server{}, [], []))
        bool(C.verify(2057, K.Rsa{A.PssAny{}, [], []}, C.Server{}, [], []))
        bool(C.verify(1025, K.Rsa{A.Rsa{}, [], []}, C.Server{}, [], []))
        bool(C.verify(1027, K.Rsa{A.Rsa{}, [], []}, C.Server{}, [], []))
        bool(C.verify(2052, K.P256{[]}, C.Server{}, [], []))
        loop(rest)
    case _: IO.die(Unit, 2, "tls_certificate_verify_cli run <content|digest|ecdsa-sign|ecdsa-verify|rsa-verify|guards> <s|c> <files>")

def args(args: List<String>) -> IO(Unit):
  match args:
    case Con{"run", rest}: loop(rest)
    case Con{_, Con{"run", rest}}: loop(rest)
    case _: IO.die(Unit, 2, "tls_certificate_verify_cli run <commands>")

def main() -> IO(Unit):
  do IO<Unit>:
    values : List<String> <- Io.args()
    args(values)
