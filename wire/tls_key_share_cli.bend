import Base
import ./tls_key_share.bend as K
import ../crypto/bytes.bend as B
import ../io/io.bend as Io

# Synthetic-key diagnostics only; never a connection-facing secret interface.
def emit(value: Maybe<&1, List<&2, U32>>) -> IO(Unit):
  match value:
    case None{}: IO.print("invalid")
    case Some{bytes}: IO.print(B.hex(bytes))

def public.retired(bytes: List<&2, U32>, result: Unit) -> IO(Unit):
  match result:
    case Unit{}: IO.print(B.hex(bytes))

def public(value: Maybe<&1, K.Offer>) -> IO(Unit):
  match value:
    case None{}: IO.print("invalid")
    case Some{K.Offer{private, bytes}}:
      public.retired(bytes, K.retire(private))

def shared(peer: List<&2, U32>, value: Maybe<&1, K.Offer>) -> IO(Unit):
  match value:
    case None{}: IO.print("invalid")
    case Some{K.Offer{private, bytes}}:
      do IO<Unit>:
        IO.print(B.hex(bytes))
        emit(K.shared(private, peer))

def group(value: String) -> K.Group:
  match value:
    case "x": K.X25519{}
    case _: K.P256{}

def loop(args: List<String>) -> IO(Unit):
  match args:
    case Nil{}: IO.pure(Unit, Unit{})
    case Con{"pub", Con{g, Con{path, rest}}}:
      do IO<Unit>:
        private : List<&2, U32> <- Io.read_bytes(path)
        public(K.from_random(group(g), private))
        loop(rest)
    case Con{"shared", Con{g, Con{path, Con{peer, rest}}}}:
      do IO<Unit>:
        private : List<&2, U32> <- Io.read_bytes(path)
        remote : List<&2, U32> <- Io.read_bytes(peer)
        shared(remote, K.from_random(group(g), private))
        loop(rest)
    case Con{"random", Con{g, rest}}:
      do IO<Unit>:
        offer : Maybe<&1, K.Offer> <- K.generate(group(g))
        public(offer)
        loop(rest)
    case Con{"guards", rest}:
      do IO<Unit>:
        public(K.from_random(K.X25519{}, Con{256, List.replicate(U32, 31n, 0)}))
        public(K.from_random(K.P256{}, Con{256, List.replicate(U32, 31n, 0)}))
        loop(rest)
    case Con{"rejection", rest}:
      do IO<Unit>:
        a : Maybe<&1, K.Offer> <- K.generate.p256_draw(K.generate.p256(0n), Done{List.replicate(U32, 32n, 0)})
        public(a)
        b : Maybe<&1, K.Offer> <- K.generate.p256(0n)
        public(b)
        c : Maybe<&1, K.Offer> <- K.generate.p256_draw(K.generate.p256(16n), Fail{(5, "synthetic RNG error")})
        public(c)
        d : Maybe<&1, K.Offer> <- K.generate.x_draw(Fail{(5, "synthetic RNG error")})
        public(d)
        loop(rest)
    case _: IO.die(Unit, 2, "tls_key_share_cli run <pub|shared|random|guards> <x|p> <files>")

def args(args: List<String>) -> IO(Unit):
  match args:
    case Con{"run", rest}: loop(rest)
    case Con{_, Con{"run", rest}}: loop(rest)
    case _: IO.die(Unit, 2, "tls_key_share_cli run <commands>")

def main() -> IO(Unit):
  do IO<Unit>:
    values : List<String> <- Io.args()
    args(values)
