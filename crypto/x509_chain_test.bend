import Base
import ./x509_chain.bend as C
import ./x509_validity.bend as V
import ./x509_extensions.bend as E

def not_before_inclusive() -> {C.time(Some{V.Validity{100n,200n}}, 100n) == C.Success{} : C.Verification}:
  {==}

def not_after_inclusive() -> {C.time(Some{V.Validity{100n,200n}}, 200n) == C.Success{} : C.Verification}:
  {==}

def early_second_rejected() -> {C.time(Some{V.Validity{100n,200n}}, 99n) == C.NotYetValid{} : C.Verification}:
  {==}

def late_second_rejected() -> {C.time(Some{V.Validity{100n,200n}}, 201n) == C.Expired{} : C.Verification}:
  {==}

def unknown_critical_rejected() -> {C.critical([E.Extension{[42,3],True{},[5,0]}]) == C.UnsupportedCriticalExtension{} : C.Verification}:
  {==}

def noncritical_opaque_allowed() -> {C.critical([E.Extension{[42,3],False{},[5,0]}]) == C.Success{} : C.Verification}:
  {==}

def critical_NC_rejected() -> {C.critical([E.Extension{[85,29,30],True{},[48,0]}]) == C.UnsupportedNameConstraints{} : C.Verification}:
  {==}

def noncritical_NC_rejected() -> {C.critical([E.Extension{[85,29,30],False{},[48,0]}]) == C.UnsupportedNameConstraints{} : C.Verification}:
  {==}

def critical_SAN_unsupported_form_rejected() -> {C.critical([E.Extension{[85,29,17],True{},[48,3,129,1,97]}]) == C.UnsupportedCriticalExtension{} : C.Verification}:
  {==}

def critical_SAN_malformed_rejected() -> {C.critical([E.Extension{[85,29,17],True{},[48,0]}]) == C.Malformed{} : C.Verification}:
  {==}

def typed_IP_length_required() -> {C.reference(C.Ip{[192,0,2]}) == False{} : Bool}:
  {==}

def typed_IP_octets_required() -> {C.reference(C.Ip{[192,0,2,256]}) == False{} : Bool}:
  {==}
