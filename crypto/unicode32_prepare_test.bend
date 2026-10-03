import Base
import ./unicode32_prepare.bend as S
import ./unicode32_space.bend as W

# Public admission boundaries and SPACE/mark classification; full sequence
# results are checked by the independent frozen Unicode 3.2 runtime oracle.
def stored_empty() -> {S.validate([], 0) == True{} : Bool}: {==}
def stored_invalid_interior() -> {S.validate([65, 55296, 66], 0) == False{} : Bool}: {==}
def stored_invalid_u32() -> {S.validate([4294967295], 0) == False{} : Bool}: {==}
def stored_last_allowed() -> {S.validate([65], 65534) == True{} : Bool}: {==}
def stored_first_disallowed() -> {S.validate([65], 65535) == False{} : Bool}: {==}
def stored_prohibition_is_later() -> {S.validate([57344, 833], 0) == True{} : Bool}: {==}
def missing_normalization_asset() -> {S.tables([], []) == None{} : Maybe<&1, S.Tables>}: {==}

def protected_space() -> {W.regular(8192, True{}) == False{} : Bool}: {==}
def regular_leading_space() -> {W.regular(8192, False{}) == True{} : Bool}: {==}
