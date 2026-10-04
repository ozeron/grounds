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
