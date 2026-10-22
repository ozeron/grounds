import Base

# Signed cookie values through the host's HMAC-SHA256 (OpenSSL 3 natively).
# Apart from cookie.bend, whose laws a foreign effect would otherwise void.

# A signed value is value followed by "." and a lowercase HMAC-SHA256 hex
# digest. The key and value are UTF-8 bytes. The native target uses OpenSSL 3.
def sign(key: String, value: String) -> IO(Result<&1, &1, U32 & String, String>):
  import "./effs/cookie.c"
  import "./effs/cookie.js"

# Some{value} for a valid signature, None{} for a missing, malformed or
# incorrect signature. Comparison of a well-formed MAC is constant-time.
def verify(key: String, signed: String) -> IO(Result<&1, &1, U32 & String, Maybe<&2, String>>):
  import "./effs/cookie.c"
  import "./effs/cookie.js"
