import Base
import ./x509_name_text.bend as T

def printable() -> {T.decode(19, [65,32,66,63]) == Some{[65,32,66,63]} : Maybe<&1, List<&2, U32>>}:
  {==}

def printable_alphabet() -> {T.decode(19, [64]) == None{} : Maybe<&1, List<&2, U32>>}:
  {==}

def ia5_control_preserved() -> {T.decode(22, [0,9,127]) == Some{[0,9,127]} : Maybe<&1, List<&2, U32>>}:
  {==}

def ia5_non_ascii() -> {T.decode(22, [128]) == None{} : Maybe<&1, List<&2, U32>>}:
  {==}

def utf8_order() -> {T.decode(12, [65,195,169,240,159,152,128]) == Some{[65,233,128512]} : Maybe<&1, List<&2, U32>>}:
  {==}

def bmp_order() -> {T.decode(30, [0,65,0,233,254,255]) == Some{[65,233,65279]} : Maybe<&1, List<&2, U32>>}:
  {==}

def universal_order() -> {T.decode(28, [0,0,0,65,0,1,246,0]) == Some{[65,128512]} : Maybe<&1, List<&2, U32>>}:
  {==}

def utf8_overlong() -> {T.decode(12, [192,128]) == None{} : Maybe<&1, List<&2, U32>>}:
  {==}

def bmp_surrogate_pair() -> {T.decode(30, [216,61,222,0]) == None{} : Maybe<&1, List<&2, U32>>}:
  {==}

def universal_outside() -> {T.decode(28, [0,17,0,0]) == None{} : Maybe<&1, List<&2, U32>>}:
  {==}

def bad_octet() -> {T.decode(30, [0,256]) == None{} : Maybe<&1, List<&2, U32>>}:
  {==}

def teletex_no_mapping() -> {T.decode(20, [233]) == None{} : Maybe<&1, List<&2, U32>>}:
  {==}
