import Base
import ./ice_binding.bend as Ice
import ./stun_auth.bend as Auth

# File-based adapters cannot supply out-of-range U32 bytes. This checks the
# public request interface rejects one before constructing/sending a packet.
def rejects_transaction_byte() -> {Ice.request(
  [256, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
  Ice.Credentials{"localFrag", "remoteFrag", "SyntheticPassword123456789"},
  Ice.Check{1845494271, Ice.Controlling{4294967295, 4294967295}}, Auth.Dual{}) ==
  None{} : Maybe<&2, List<&2, U32>>}:
  {==}
