import Base
import ./bytes.bend as B
import ./x509_name_schema.bend as S
import ../utf8/utf8.bend as U

# RFC 4518 section 2.1: transcode a primitive ASN.1 string value to scalars.
# Validation uses the same strict string syntax as the Name schema. This step
# preserves BOMs, controls, case and spaces; Unicode preparation is separate.
# Teletex (20) and unknown tags return None: no implicit Latin-1 mapping.

def string.codes(text: String, reversed: List<&2, U32>) -> List<&2, U32>:
  match text:
    case SNil{}: List.reverse(&2, U32, reversed)
    case SCon{Chr{code}, rest}: string.codes(rest, Con{code, reversed})

def utf8(result: U.Text) -> Maybe<&1, List<&2, U32>>:
  match result:
    case U.TOk{text}: Some{string.codes(text, [])}
    case U.TBad{_, _}: None{}

def bmp(bytes: List<&2, U32>, reversed: List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  match bytes:
    case Nil{}: Some{List.reverse(&2, U32, reversed)}
    case Con{high, Con{low, rest}}:
      bmp(rest, Con{U32.add(U32.mul(high, 256), low), reversed})
    case _: None{}

def universal(bytes: List<&2, U32>, reversed: List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  match bytes:
    case Nil{}: Some{List.reverse(&2, U32, reversed)}
    case Con{a, Con{b, Con{c, Con{d, rest}}}}:
      universal(rest, Con{U32.add(U32.mul(a, 16777216),
        U32.add(U32.mul(b, 65536), U32.add(U32.mul(c, 256), d))), reversed})
    case _: None{}

def text(checked: Maybe<&1, U32>, tag: U32, bytes: List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  match checked tag:
    case Some{_} 12: utf8(U.decode(bytes))
    case Some{_} 19: Some{bytes}
    case Some{_} 22: Some{bytes}
    case Some{_} 28: universal(bytes, [])
    case Some{_} 30: bmp(bytes, [])
    case _ _: None{}

def checked(valid: Bool, +tag: U32, +bytes: List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  match valid:
    case True{}: text(S.text(tag, bytes), tag, bytes)
    case False{}: None{}

# Same octet bound as the surrounding DER owner, including direct callers.
def decode(+tag: U32, +bytes: List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  checked(Bool.and(B.valid(bytes), Nat.is_le(B.length(bytes), 65535n)), tag, bytes)
