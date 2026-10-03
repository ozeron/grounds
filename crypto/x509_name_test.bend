import Base
import ./x509_name.bend as N

def empty_subject() -> {N.inspect([48,0], True{}) == Some{True{}} : Maybe<&1, Bool>}:
  {==}

def empty_issuer() -> {N.inspect([48,0], False{}) == None{} : Maybe<&1, Bool>}:
  {==}

def empty_RDN() -> {N.inspect([48,2,49,0], True{}) == None{} : Maybe<&1, Bool>}:
  {==}

def common_name() -> {N.inspect([48,12,49,10,48,8,6,3,85,4,3,12,1,97], False{}) == Some{True{}} : Maybe<&1, Bool>}:
  {==}

def teletex_deferred() -> {N.inspect([48,12,49,10,48,8,6,3,85,4,3,20,1,97], False{}) == Some{False{}} : Maybe<&1, Bool>}:
  {==}

def malformed_UTF8() -> {N.inspect([48,12,49,10,48,8,6,3,85,4,3,12,1,255], False{}) == None{} : Maybe<&1, Bool>}:
  {==}

def malformed_BMP() -> {N.inspect([48,13,49,11,48,9,6,3,85,4,3,30,2,216,0], False{}) == None{} : Maybe<&1, Bool>}:
  {==}
