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

# EV subject: jurisdictionC=US, businessCategory=Private (one RDN each).
def EV_attributes() -> {N.inspect([48,40,49,19,48,17,6,11,43,6,1,4,1,130,55,60,2,1,3,19,2,85,83,49,17,48,15,6,3,85,4,15,12,8,80,114,105,118,97,116,101,32], False{}) == Some{True{}} : Maybe<&1, Bool>}:
  {==}

def EV_jurisdiction_country_SIZE() -> {N.inspect([48,20,49,18,48,16,6,11,43,6,1,4,1,130,55,60,2,1,3,19,1,85], False{}) == None{} : Maybe<&1, Bool>}:
  {==}

def unknown_EV_arc_deferred() -> {N.inspect([48,21,49,19,48,17,6,11,43,6,1,4,1,130,55,60,2,1,9,19,2,85,83], False{}) == Some{False{}} : Maybe<&1, Bool>}:
  {==}
