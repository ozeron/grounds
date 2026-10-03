import Base
import ./x509_san.bend as S

def DNS_supported() -> {S.inspect([48,3,130,1,97]) == Some{True{}} : Maybe<&1, Bool>}:
  {==}

def malformed_DNS() -> {S.inspect([48,3,130,1,32]) == None{} : Maybe<&1, Bool>}:
  {==}

def deferred_form() -> {S.inspect([48,3,134,1,97]) == Some{False{}} : Maybe<&1, Bool>}:
  {==}

def missing_SAN_empty_subject() -> {S.subject([48,0], None{}) == False{} : Bool}:
  {==}

def critical_deferred_rejected() -> {S.permits(Some{False{}}, True{}) == False{} : Bool}:
  {==}

def critical_SAN_empty_subject() -> {S.subject([48,0], Some{[48,17,48,15,6,3,85,29,17,1,1,255,4,5,48,3,130,1,97]}) == True{} : Bool}:
  {==}
