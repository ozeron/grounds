import Base
import ./cookie_crypto.bend as Crypto

# Explicit immutable application/runtime owner, copied only as configuration.
# Keep it in serve_out_context's Data context, never in client claims. This is
# a synthetic-key logical owner, not secure storage, rotation or erasure.
type SigningKey is Data:
  SigningKey{secret: String}

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

def sign_owned(key: SigningKey, value: String) -> IO(Result<&1,&1,U32 & String,String>):
  match key:
    case SigningKey{secret}: sign(secret,value)

def verify_owned(key: SigningKey, value: String) -> IO(Result<&1,&1,U32 & String,Maybe<&2,String>>):
  match key:
    case SigningKey{secret}: verify(secret,value)
