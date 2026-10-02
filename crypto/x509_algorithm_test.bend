import Base
import ./x509_algorithm.bend as X

def rsa() -> {X.key([48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0]) == Some{X.Rsa{}} : Maybe<&1, X.Key>}:
  {==}

def rsa_missing_null() -> {X.key([48, 11, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1]) == None{} : Maybe<&1, X.Key>}:
  {==}

def pss_any() -> {X.key([48, 11, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 10]) == Some{X.PssAny{}} : Maybe<&1, X.Key>}:
  {==}

def pss_signature_needs_parameters() -> {X.signature([48, 11, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 10]) == None{} : Maybe<&1, X.Signature>}:
  {==}

def pss_cannot_v15() -> {X.compatible(X.PssAny{}, X.RsaV15256{}) == False{} : Bool}:
  {==}

def excessive_minimum() -> {X.compatible(X.Pss256{33}, X.RsaPss256{}) == False{} : Bool}:
  {==}

def ecdsa_null_rejected() -> {X.signature([48, 12, 6, 8, 42, 134, 72, 206, 61, 4, 3, 2, 5, 0]) == None{} : Maybe<&1, X.Signature>}:
  {==}
