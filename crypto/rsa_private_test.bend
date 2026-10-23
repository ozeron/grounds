import Base
import ./rsa_private.bend as R
import ./rsa_integer.bend as I

def product_small() -> {I.encode(3n, R.product([255, 255], [255])) == [254, 255, 1] : List<&2, U32>}:
  {==}

def reduce_even() -> {R.reduce([10], [255, 255]) == [5] : List<&2, U32>}:
  {==}

def reduce_odd() -> {R.reduce([17], [255, 255]) == [0] : List<&2, U32>}:
  {==}

def subtract_one_borrow() -> {R.minus_small([1, 0, 0], 1) == [0, 255, 255] : List<&2, U32>}:
  {==}

def subtract_two_borrow() -> {R.minus_small([1, 0], 2) == [0, 254] : List<&2, U32>}:
  {==}

def subtract_zero_fixed_loop() -> {R.minus_small([1, 0, 0], 0) == [1, 0, 0] : List<&2, U32>}:
  {==}

def modular_multiply() -> {R.multiply([17], [15], [13]) == [8] : List<&2, U32>}:
  {==}

def masked_private_power() -> {R.power([17], [13], [3]) == [12] : List<&2, U32>}:
  {==}

def modular_difference_underflow() -> {R.difference([17], [2], [9]) == [10] : List<&2, U32>}:
  {==}

def modular_difference_no_underflow() -> {R.difference([17], [13], [9]) == [4] : List<&2, U32>}:
  {==}

def component_blinded() -> {R.component([17], [13], [5], [3], [2]) == Some{[12]} : Maybe<&1, List<&2, U32>>}:
  {==}

def rejects_noninvertible_blind() -> {Maybe.is_none(&1, List<&2, U32>, R.component([17], [13], [5], [3], [0])) == True{} : Bool}:
  {==}

def rejects_fault() -> {Maybe.is_none(&1, List<&2, U32>, R.fault.recovered([3], [2], Some{[4]})) == True{} : Bool}:
  {==}
