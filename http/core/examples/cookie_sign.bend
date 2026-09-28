import Base
import ../cookie.bend as Ck

def report(good: Maybe<&2, String>, tampered: Maybe<&2, String>, wrong_key: Maybe<&2, String>, malformed: Maybe<&2, String>, unicode: Maybe<&2, String>) -> String:
  match good tampered wrong_key malformed unicode:
    case Some{"The quick brown fox jumps over the lazy dog"} None{} None{} None{} Some{"café.☕"}:
      "verified; tampered, wrong-key and malformed signatures rejected"
    case _ _ _ _ _:
      "failed"

def main() -> IO(Unit):
  do IO<Unit>:
    signed : String <- IO.try(String, Ck.sign("key", "The quick brown fox jumps over the lazy dog"))
    x : Unit <- IO.print(signed)
    good : Maybe<&2, String> <- IO.try(Maybe<&2, String>, Ck.verify("key", "The quick brown fox jumps over the lazy dog.f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"))
    unicode_signed : String <- IO.try(String, Ck.sign("key", "café.☕"))
    y : Unit <- IO.print(unicode_signed)
    tampered : Maybe<&2, String> <- IO.try(Maybe<&2, String>, Ck.verify("key", "The quick brown fox jumps over the lazy dog.f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd9"))
    wrong_key : Maybe<&2, String> <- IO.try(Maybe<&2, String>, Ck.verify("other", "The quick brown fox jumps over the lazy dog.f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"))
    malformed : Maybe<&2, String> <- IO.try(Maybe<&2, String>, Ck.verify("key", "The quick brown fox jumps over the lazy dog.bad"))
    unicode : Maybe<&2, String> <- IO.try(Maybe<&2, String>, Ck.verify("key", "café.☕.66fab8c89cbb5003d839cd9008b5ce105aa1e8b08b6690271cf9e0c3292f4200"))
    IO.print(report(good, tampered, wrong_key, malformed, unicode))
