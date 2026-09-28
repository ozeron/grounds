import Base
import ./poly1305.bend as P
import ./aead.bend as A

def poly_rejects_bad_byte() -> {P.mac(Con{256, List.replicate(U32, 31n, 0)}, []) == None{} : Maybe<&2, List<&2, U32>>}:
  {==}

def poly_rejects_bad_message() -> {P.mac(List.replicate(U32, 32n, 0), [256]) == None{} : Maybe<&2, List<&2, U32>>}:
  {==}

def aead_rejects_bad_key() -> {A.seal(Con{256, List.replicate(U32, 31n, 0)}, List.replicate(U32, 12n, 0), [], []) == None{} : Maybe<&2, A.Sealed>}:
  {==}

def empty_mac_layout() -> {List.length(&2, U32, A.mac_input([], [])) == 16n : Nat}:
  {==}

def partial_mac_layout() -> {List.length(&2, U32, A.mac_input([1], [2])) == 48n : Nat}:
  {==}
