import Base
import ./unicode32_nfkc.bend as N
import ./unicode32_nfkc_tables.bend as T
import ./unicode32_nfkc_compose.bend as C

def scalar_zero() -> {N.scalar(0) == True{} : Bool}: {==}
def scalar_last() -> {N.scalar(1114111) == True{} : Bool}: {==}
def scalar_surrogate_low() -> {N.scalar(55296) == False{} : Bool}: {==}
def scalar_surrogate_high() -> {N.scalar(57343) == False{} : Bool}: {==}
def scalar_above_unicode() -> {N.scalar(1114112) == False{} : Bool}: {==}
def scalar_u32_last() -> {N.scalar(4294967295) == False{} : Bool}: {==}
def empty_scalar_list() -> {N.validate([], 0) == True{} : Bool}: {==}
def invalid_interior_scalar() -> {N.validate([65, 55296, 66], 0) == False{} : Bool}: {==}
def prohibition_is_later() -> {N.validate([57344, 7312, 1114111], 0) == True{} : Bool}: {==}
def hangul_leading_vowel() -> {C.hangul(4352, 4449) == Some{44032} : Maybe<U32>}: {==}
def hangul_trailing() -> {C.hangul(44032, 4520) == Some{44033} : Maybe<U32>}: {==}
def hangul_missing_trailing() -> {C.hangul(44032, 4519) == None{} : Maybe<U32>}: {==}
def missing_asset() -> {T.decode([]) == None{} : Maybe<&1, T.Tables>}: {==}
def invalid_byte_asset() -> {T.decode([256]) == None{} : Maybe<&1, T.Tables>}: {==}
