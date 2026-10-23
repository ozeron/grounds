import Base
import ./x509_ca_path.bend as C

def bc() -> Maybe<&2, List<&2, U32>>:
  Some{[48,3,1,1,255]}

def ku() -> Maybe<&2, List<&2, U32>>:
  Some{[3,2,2,4]}

def v1_rejected() -> {C.check(0, bc(), ku(), 0) == C.InvalidCa{} : C.Decision}:
  {==}

def v2_rejected() -> {C.check(1, bc(), ku(), 0) == C.InvalidCa{} : C.Decision}:
  {==}

def absent_BC_rejected() -> {C.check(2, None{}, ku(), 0) == C.InvalidCa{} : C.Decision}:
  {==}

def CA_false_rejected() -> {C.check(2, Some{[48,0]}, ku(), 0) == C.InvalidCa{} : C.Decision}:
  {==}

def absent_KU_rejected() -> {C.check(2, bc(), None{}, 0) == C.InvalidUsage{} : C.Decision}:
  {==}

def missing_keyCertSign_rejected() -> {C.check(2, bc(), Some{[3,2,7,128]}, 0) == C.InvalidUsage{} : C.Decision}:
  {==}

def CA_allowed() -> {C.check(2, bc(), ku(), 0) == C.Allowed{} : C.Decision}:
  {==}

def target_leaf_not_counted() -> {C.check(2, Some{[48,6,1,1,255,2,1,0]}, ku(), 0) == C.Allowed{} : C.Decision}:
  {==}

def intermediate_spends_pathLen() -> {C.check(2, Some{[48,6,1,1,255,2,1,0]}, ku(), 1) == C.Exceeded{} : C.Decision}:
  {==}

def exact_pathLen_allowed() -> {C.check(2, Some{[48,6,1,1,255,2,1,1]}, ku(), 1) == C.Allowed{} : C.Decision}:
  {==}

def arbitrary_integer_does_not_wrap() -> {C.check(2, Some{[48,10,1,1,255,2,5,1,0,0,0,0]}, ku(), 8) == C.Allowed{} : C.Decision}:
  {==}

def malformed_pathLen_rejected() -> {C.check(2, Some{[48,6,1,1,255,2,1,255]}, ku(), 0) == C.InvalidCa{} : C.Decision}:
  {==}

def self_issued_does_not_spend_pathLen() -> {C.advance(True{}, 0) == 0 : U32}:
  {==}

def non_self_issued_spends_pathLen() -> {C.advance(False{}, 0) == 1 : U32}:
  {==}
