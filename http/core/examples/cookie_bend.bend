import Base
import ../cookie_bend.bend as Ck
import ../../../crypto/bytes.bend as B
import ../../../utf8/utf8.bend as U
import ../../../io/io.bend as Io

def verified(result: Maybe<&2, String>) -> IO(Unit):
  match result:
    case None{}: IO.print("invalid")
    case Some{value}: IO.print("ok:" ++ B.hex(U.encode(value)))

def operation(kind: Bool, key: String, value: String) -> IO(Unit):
  match kind:
    case True{}:
      do IO<Unit>:
        signed : String <- IO.try(String, Ck.sign(key, value))
        IO.print("ok:" ++ B.hex(U.encode(signed)))
    case False{}:
      do IO<Unit>:
        result : Maybe<&2, String> <- IO.try(Maybe<&2, String>, Ck.verify(key, value))
        verified(result)

# Test-only framing: operation U8, then key/value as U32BE byte length + UTF-8.
type Field is Data:
  Field{bytes: List<&2, U32>, rest: List<&2, U32>}

def take(left: Nat, bytes: List<&2, U32>, reversed: List<&2, U32>) -> Maybe<&2, Field>:
  match left bytes:
    case 0n rest: Some{Field{List.reverse(&2, U32, reversed), rest}}
    case 1n+p Con{byte, tail}: take(p, tail, Con{byte, reversed})
    case _ _: None{}

def field(bytes: List<&2, U32>) -> Maybe<&2, Field>:
  match bytes:
    case Con{a, Con{b, Con{c, Con{d, tail}}}}:
      length = U32.or(U32.shln(a, 24n), U32.or(U32.shln(b, 16n), U32.or(U32.shln(c, 8n), d)))
      take(U32.to_nat(length), tail, [])
    case _: None{}

def decoded_text(kind: Bool, key: String, value: U.Text, rest: List<&2, U32>,
  next: List<&2, U32> -> IO(Unit)) -> IO(Unit):
  match value:
    case U.TOk{value}:
      do IO<Unit>:
        x : Unit <- operation(kind, key, value)
        next(rest)
    case _: IO.die(Unit, 2, "bad fixture")

def decoded_value(kind: Bool, key: U.Text, result: Maybe<&2, Field>,
  next: List<&2, U32> -> IO(Unit)) -> IO(Unit):
  match key result:
    case U.TOk{key} Some{Field{bytes, rest}}: decoded_text(kind, key, U.decode(bytes), rest, next)
    case _ _: IO.die(Unit, 2, "bad fixture")

def decoded_key(kind: Bool, valid: Bool, result: Maybe<&2, Field>,
  next: List<&2, U32> -> IO(Unit)) -> IO(Unit):
  match valid result:
    case True{} Some{Field{bytes, rest}}: decoded_value(kind, U.decode(bytes), field(rest), next)
    case _ _: IO.die(Unit, 2, "bad fixture")

def values(left: Nat, bytes: List<&2, U32>) -> IO(Unit):
  match left bytes:
    case _ Nil{}: IO.pure(Unit, Unit{})
    case 1n+p Con{+kind, tail}:
      decoded_key(U32.is_eq(kind, 1), Bool.or(U32.is_eq(kind, 1), U32.is_eq(kind, 2)), field(tail), rest => values(p, rest))
    case _ _: IO.die(Unit, 2, "bad fixture")

def read_fixture(path: String) -> IO(Unit):
  do IO<Unit>:
    +bytes : List<&2, U32> <- Io.read_bytes(path)
    values(B.length(bytes), bytes)

def dispatch(args: List<String>) -> IO(Unit):
  match args:
    case [path]: read_fixture(path)
    case [_, path]: read_fixture(path)
    case _: IO.die(Unit, 2, "usage: cookie_bend <fixture.bin>")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    dispatch(args)
