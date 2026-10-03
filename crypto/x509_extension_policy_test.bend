import Base
import ./x509_extension_policy.bend as P

def exact_basic() -> {P.kind([85, 29, 19]) == 1 : U32}:
  {==}

def not_prefix() -> {P.kind([85, 29, 19, 0]) == 0 : U32}:
  {==}

def unknown_critical() -> {P.decode([48, 12, 48, 10, 6, 2, 42, 3, 1, 1, 255, 4, 1, 0]) == None{} : Maybe<&1, P.Admission>}:
  {==}

def malformed_known_noncritical() -> {P.decode([48, 9, 48, 7, 6, 3, 85, 29, 19, 4, 0]) == None{} : Maybe<&1, P.Admission>}:
  {==}

def nonbyte() -> {P.decode([48, 9, 48, 7, 6, 3, 85, 29, 275, 4, 0]) == None{} : Maybe<&1, P.Admission>}:
  {==}
