import Base
import ./unicode32_fold.bend as F
import ./unicode32_lookup.bend as L

def scalar_zero() -> {F.valid(0) == True{} : Bool}: {==}
def scalar_last() -> {F.valid(1114111) == True{} : Bool}: {==}
def scalar_below_surrogate() -> {F.valid(55295) == True{} : Bool}: {==}
def scalar_above_surrogate() -> {F.valid(57344) == True{} : Bool}: {==}
def scalar_surrogate_first() -> {F.valid(55296) == False{} : Bool}: {==}
def scalar_surrogate_last() -> {F.valid(57343) == False{} : Bool}: {==}
def scalar_beyond_unicode() -> {F.valid(1114112) == False{} : Bool}: {==}
def scalar_u32_last() -> {F.valid(4294967295) == False{} : Bool}: {==}

def lookup.result(result: Array<U32> & Maybe<U32>) -> Maybe<U32>:
  (_, value) = result
  value

def lookup(code: U32) -> Maybe<U32>:
  lookup.result(L.find(3, code, L.fill([0, 7, 20, 9, 4294967295, 11], 0, Array.new(U32, 3n, 0))))

def lookup_first() -> {lookup(0) == Some{7} : Maybe<U32>}: {==}
def lookup_middle() -> {lookup(20) == Some{9} : Maybe<U32>}: {==}
def lookup_last() -> {lookup(4294967295) == Some{11} : Maybe<U32>}: {==}
def lookup_missing_before_middle() -> {lookup(19) == None{} : Maybe<U32>}: {==}
def lookup_missing_after_middle() -> {lookup(21) == None{} : Maybe<U32>}: {==}
