import Base
import ./sha256.bend as Sha

# Every SHA-256 compression state serializes to exactly 32 bytes. HMAC and
# HKDF rely on this fixed width when they build their next input block.
law sha256_output_length:
  for s: Sha.State
  {List.length(&2, U32, Sha.output(s)) == 32n : Nat}
