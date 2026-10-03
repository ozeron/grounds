import Base
import ./cookie_crypto.bend as Crypto

# Explicit pure-Bend path; synthetic keys until generated-code review resolves
# runtime timing and erasure findings. Legacy sign/verify retain their behavior.
def sign.result(result: Maybe<&2, String>) -> Result<&1, &1, U32 & String, String>:
  match result:
    case Some{signed}: Done{signed}
    case None{}: Fail{(22, "cookie key/value contains an invalid Unicode scalar")}

def sign(key: String, value: String) -> IO(Result<&1, &1, U32 & String, String>):
  IO.pure(Result<&1, &1, U32 & String, String>, sign.result(Crypto.sign(key, value)))

def verify(key: String, signed: String) -> IO(Result<&1, &1, U32 & String, Maybe<&2, String>>):
  IO.pure(Result<&1, &1, U32 & String, Maybe<&2, String>>, Done{Crypto.verify(key, signed)})
