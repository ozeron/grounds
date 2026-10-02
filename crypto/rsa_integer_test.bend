import Base
import ./rsa_integer.bend as R
import ./bytes.bend as B

def inverse_three() -> {R.inverse_low(3) == 21845 : U32}:
  {==}

def inverse_max() -> {R.inverse_low(32767) == 1 : U32}:
  {==}

def bytes_round_trip() -> {R.encode(5n, R.decode([255, 128, 0, 1, 7])) == [255, 128, 0, 1, 7] : List<&2, U32>}:
  {==}

def montgomery_small() -> {R.result.encode(1n, R.mont(1n, R.inverse_low(3), R.decode([3]), R.decode([1]), R.decode([1]))) == [2] : List<&2, U32>}:
  {==}

def shift_fixture() -> Array<U32>:
  Array.set(U32, Array.set(U32, Array.set(U32, R.zero(), 0, 17), 1, 32767), 2, 2)

def shift_reads_before_write() -> {R.encode(4n, R.right.go(2n, 0, shift_fixture())) == [0, 1, 127, 255] : List<&2, U32>}:
  {==}

def shift_clears_high_carry() -> {R.encode(6n, R.right.go(2n, 0, shift_fixture())) == [0, 0, 0, 1, 127, 255] : List<&2, U32>}:
  {==}

def modulus_fixture() -> List<&2, U32>:
  Con{128, B.append(List.replicate(U32, 254n, 0), [1])}

def rejects_non_byte_modulus() -> {Maybe.is_none(&2, List<&2, U32>, R.public_operation(Con{256, B.append(List.replicate(U32, 254n, 0), [1])}, [3], List.replicate(U32, 256n, 0))) == True{} : Bool}:
  {==}

def rejects_non_byte_exponent() -> {Maybe.is_none(&2, List<&2, U32>, R.public_operation(modulus_fixture(), [256, 1], List.replicate(U32, 256n, 0))) == True{} : Bool}:
  {==}

def rejects_non_byte_representative() -> {Maybe.is_none(&2, List<&2, U32>, R.public_operation(modulus_fixture(), [3], Con{256, List.replicate(U32, 255n, 0)})) == True{} : Bool}:
  {==}

def rejects_small_rsa_key() -> {Maybe.is_none(&2, List<&2, U32>, R.public_operation([17], [3], [2])) == True{} : Bool}:
  {==}

def rejects_modulus_alias() -> {Maybe.is_none(&2, List<&2, U32>, R.public_operation(Con{0, modulus_fixture()}, [3], List.replicate(U32, 257n, 0))) == True{} : Bool}:
  {==}

def rejects_signature_at_modulus() -> {Maybe.is_none(&2, List<&2, U32>, R.public_operation(modulus_fixture(), [3], modulus_fixture())) == True{} : Bool}:
  {==}

def rejects_exponent_one() -> {Maybe.is_none(&2, List<&2, U32>, R.public_operation(modulus_fixture(), [1], List.replicate(U32, 256n, 0))) == True{} : Bool}:
  {==}
