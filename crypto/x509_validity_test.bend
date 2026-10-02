import Base
import ./x509_validity.bend as V

def epoch() -> {V.decode_time([24, 15, 48, 48, 48, 49, 48, 49, 48, 49, 48, 48, 48, 48, 48, 48, 90]) == Some{0n} : Maybe<&1, Nat>}:
  {==}

def nonbyte() -> {V.decode_time([24, 1, 256]) == None{} : Maybe<&1, Nat>}:
  {==}

def year_zero() -> {V.moment(0, 1, 1, 0, 0, 0) == None{} : Maybe<&1, Nat>}:
  {==}

def nonleap_century() -> {V.moment(1900, 2, 29, 0, 0, 0) == None{} : Maybe<&1, Nat>}:
  {==}
