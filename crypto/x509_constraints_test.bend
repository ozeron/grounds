import Base
import ./x509_constraints.bend as X

def absent_default() -> {X.basic([48, 0]) == Some{X.Basic{False{}, None{}}} : Maybe<&1, X.Basic>}:
  {==}

def explicit_default() -> {X.basic([48, 3, 1, 1, 0]) == None{} : Maybe<&1, X.Basic>}:
  {==}

def basic_nonbyte() -> {X.basic([48, 3, 1, 1, 511]) == None{} : Maybe<&1, X.Basic>}:
  {==}

def usage_nonbyte() -> {X.usage([3, 2, 0, 257]) == None{} : Maybe<&1, X.Usage>}:
  {==}

def large_limit() -> {X.path_allows(Some{[1, 0, 0, 0, 0]}, 4294967295) == True{} : Bool}:
  {==}

def negative_limit() -> {X.path_allows(Some{[255]}, 0) == False{} : Bool}:
  {==}

def limit_nonbyte() -> {X.path_allows(Some{[257]}, 0) == False{} : Bool}:
  {==}

def malformed_present() -> {X.policy(Some{[]}, None{}) == False{} : Bool}:
  {==}
