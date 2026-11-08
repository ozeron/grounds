import Base
import ./x509_name_prepare.bend as N

def common_utf8() -> {N.admission([85,4,3], 12, [65,195,169]) == Some{True{}} : Maybe<&1, Bool>}:
  {==}

def country_printable() -> {N.admission([85,4,6], 19, [85,83]) == Some{True{}} : Maybe<&1, Bool>}:
  {==}

def country_SIZE() -> {N.admission([85,4,6], 19, [85]) == None{} : Maybe<&1, Bool>}:
  {==}

def empty_common() -> {N.admission([85,4,3], 12, []) == None{} : Maybe<&1, Bool>}:
  {==}

def empty_qualifier() -> {N.admission([85,4,46], 19, []) == Some{True{}} : Maybe<&1, Bool>}:
  {==}

def wrong_country_tag() -> {N.admission([85,4,6], 12, [85,83]) == None{} : Maybe<&1, Bool>}:
  {==}

def invalid_octet() -> {N.admission([85,4,3], 19, [256]) == None{} : Maybe<&1, Bool>}:
  {==}

def invalid_oid_octet() -> {N.admission([85,4,259], 19, [65]) == None{} : Maybe<&1, Bool>}:
  {==}

def nonminimal_oid() -> {N.admission([85,4,128,3], 19, [65]) == None{} : Maybe<&1, Bool>}:
  {==}

def bmp_surrogate_pair() -> {N.admission([85,4,3], 30, [216,61,222,0]) == None{} : Maybe<&1, Bool>}:
  {==}

def unsupported_teletex() -> {N.admission([85,4,3], 20, [65]) == Some{False{}} : Maybe<&1, Bool>}:
  {==}

def unsupported_domainComponent_profile() -> {N.admission([9,146,38,137,147,242,44,100,1,25], 22, [65]) == Some{False{}} : Maybe<&1, Bool>}:
  {==}

# EV/OV subject attributes (M6). SIZE endpoints 40/41 and 128/129 for every
# new type are exhaustive in x509_name_check.py; these pin type and OID rules.
def repeat(left: Nat, +byte: U32, done: List<&2, U32>) -> List<&2, U32>:
  match left:
    case 0n: done
    case 1n+p: repeat(p, byte, Con{byte, done})

def jurisdiction_country() -> {N.admission([43,6,1,4,1,130,55,60,2,1,3], 19, [85,83]) == Some{True{}} : Maybe<&1, Bool>}:
  {==}

def jurisdiction_country_UTF8() -> {N.admission([43,6,1,4,1,130,55,60,2,1,3], 12, [85,83]) == None{} : Maybe<&1, Bool>}:
  {==}

def jurisdiction_country_SIZE() -> {N.admission([43,6,1,4,1,130,55,60,2,1,3], 19, [85,83,65]) == None{} : Maybe<&1, Bool>}:
  {==}

def jurisdiction_state_UTF8() -> {N.admission([43,6,1,4,1,130,55,60,2,1,2], 12, [85,116,97,104]) == Some{True{}} : Maybe<&1, Bool>}:
  {==}

def jurisdiction_state_IA5() -> {N.admission([43,6,1,4,1,130,55,60,2,1,2], 22, [85,116,97,104]) == None{} : Maybe<&1, Bool>}:
  {==}

def jurisdiction_locality() -> {N.admission([43,6,1,4,1,130,55,60,2,1,1], 19, [70,114,97,110,107,102,117,114,116]) == Some{True{}} : Maybe<&1, Bool>}:
  {==}

def jurisdiction_locality_empty() -> {N.admission([43,6,1,4,1,130,55,60,2,1,1], 19, []) == None{} : Maybe<&1, Bool>}:
  {==}

def jurisdiction_other_arc() -> {N.admission([43,6,1,4,1,130,55,60,2,1,4], 19, [65]) == Some{False{}} : Maybe<&1, Bool>}:
  {==}

def jurisdiction_extended_arc() -> {N.admission([43,6,1,4,1,130,55,60,2,1,3,1], 19, [85,83]) == Some{False{}} : Maybe<&1, Bool>}:
  {==}

def jurisdiction_parent_arc() -> {N.admission([43,6,1,4,1,130,55,60,2,1], 19, [85,83]) == Some{False{}} : Maybe<&1, Bool>}:
  {==}

def jurisdiction_nonminimal_oid() -> {N.admission([43,6,1,4,1,128,130,55,60,2,1,3], 19, [85,83]) == None{} : Maybe<&1, Bool>}:
  {==}

def business_category() -> {N.admission([85,4,15], 12, [80,114,105,118,97,116,101]) == Some{True{}} : Maybe<&1, Bool>}:
  {==}

def business_category_printable() -> {N.admission([85,4,15], 19, [80,114,105,118,97,116,101]) == Some{True{}} : Maybe<&1, Bool>}:
  {==}

def business_category_IA5() -> {N.admission([85,4,15], 22, [80]) == None{} : Maybe<&1, Bool>}:
  {==}

def business_category_teletex() -> {N.admission([85,4,15], 20, [80]) == Some{False{}} : Maybe<&1, Bool>}:
  {==}

def street() -> {N.admission([85,4,9], 12, [77,97,105,110,32,49]) == Some{True{}} : Maybe<&1, Bool>}:
  {==}

def street_empty() -> {N.admission([85,4,9], 19, []) == None{} : Maybe<&1, Bool>}:
  {==}

def postal_code() -> {N.admission([85,4,17], 19, repeat(40n, 57, [])) == Some{True{}} : Maybe<&1, Bool>}:
  {==}

def postal_code_SIZE() -> {N.admission([85,4,17], 19, repeat(41n, 57, [])) == None{} : Maybe<&1, Bool>}:
  {==}

def postal_code_printable_alphabet() -> {N.admission([85,4,17], 19, [49,42]) == None{} : Maybe<&1, Bool>}:
  {==}

def organization_identifier() -> {N.admission([85,4,97], 12, [86,65,84,72,85,45,49]) == Some{True{}} : Maybe<&1, Bool>}:
  {==}

def organization_identifier_IA5() -> {N.admission([85,4,97], 22, [86]) == None{} : Maybe<&1, Bool>}:
  {==}

def organization_identifier_nonminimal_oid() -> {N.admission([85,4,128,97], 12, [86]) == None{} : Maybe<&1, Bool>}:
  {==}

def serial_number_UTF8() -> {N.admission([85,4,5], 12, [49]) == None{} : Maybe<&1, Bool>}:
  {==}

def unsupported_email_profile() -> {N.admission([42,134,72,134,247,13,1,9,1], 22, [65]) == Some{False{}} : Maybe<&1, Bool>}:
  {==}
