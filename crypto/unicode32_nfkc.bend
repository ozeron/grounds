import Base
import ./unicode32_nfkc_tables.bend as T
import ./unicode32_nfkc_decompose.bend as D
import ./unicode32_nfkc_buffer.bend as B
import ./unicode32_nfkc_order.bend as O
import ./unicode32_nfkc_compose.bend as C

# Pure Unicode 3.2 NFKC. The scalar bound admits every expansion of a
# 65,535-byte Name before normalization (at most four B.2 scalars per input).
# Prohibition and insignificant SPACE handling belong after normalization.
def scalar(+code: U32) -> Bool:
  Bool.and(U32.is_le(code, 1114111), Bool.not(Bool.and(U32.is_ge(code, 55296), U32.is_le(code, 57343))))

def validate.next(valid: Bool, next: Unit -> Bool) -> Bool:
  match valid:
    case False{}: False{}
    case True{}: next(Unit{})

def validate(codes: List<&2, U32>, +count: U32) -> Bool:
  match codes:
    case Nil{}: True{}
    case Con{code, rest}:
      validate.next(Bool.and(U32.is_lt(count, 262140), scalar(code)), u => validate(rest, U32.inc(count)))

def composed(result: T.Tables & C.Normalized) -> T.Tables & Maybe<&1, C.Normalized>:
  (state, normalized) = result
  (state, Some{normalized})

def ordered(state: T.Tables, result: Array<U32> & U32) -> T.Tables & Maybe<&1, C.Normalized>:
  composed(C.compose(state, result))

def decomposed(result: T.Tables & B.Buffer) -> T.Tables & Maybe<&1, C.Normalized>:
  (state, buffer) = result
  ordered(state, O.ordered(buffer))

def checked(valid: Bool, state: T.Tables, codes: List<&2, U32>) -> T.Tables & Maybe<&1, C.Normalized>:
  match valid:
    case False{}: (state, None{})
    case True{}: decomposed(D.run(codes, state, B.new()))

def normalize(state: T.Tables, +codes: List<&2, U32>) -> T.Tables & Maybe<&1, C.Normalized>:
  checked(validate(codes, 0), state, codes)
