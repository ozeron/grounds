import Base
import ./oid.bend as O
import ./x509_extensions.bend as X
import ./der.bend as D

def published_oid() -> {O.decode([6, 3, 136, 55, 3]) == Some{[136, 55, 3]} : Maybe<&1, List<&2, U32>>}:
  {==}

def nonminimal_first() -> {O.decode([6, 2, 128, 0]) == None{} : Maybe<&1, List<&2, U32>>}:
  {==}

def unterminated() -> {O.decode([6, 1, 129]) == None{} : Maybe<&1, List<&2, U32>>}:
  {==}

def nonbyte() -> {O.decode([6, 1, 256]) == None{} : Maybe<&1, List<&2, U32>>}:
  {==}

def explicit_false() -> {X.item(D.read([6, 3, 85, 29, 19, 1, 1, 0, 4, 0])) == None{} : Maybe<&1, X.Extension>}:
  {==}

def hash_collision() -> {X.key([99, 111, 115, 116, 97, 114, 114, 105, 110, 103]) == X.key([108, 105, 113, 117, 105, 100]) : String}:
  {==}
