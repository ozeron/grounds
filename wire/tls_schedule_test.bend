import Base
import ./tls_schedule.bend as S

def invalid_empty_shared() -> {S.start([], S.zeros()) == None{} : Maybe<&1, S.Handshake>}:
  {==}

def invalid_empty_transcript() -> {S.start(S.zeros(), []) == None{} : Maybe<&1, S.Handshake>}:
  {==}

def invalid_nonoctet() -> {S.bytes32(Con{256, List.replicate(U32, 31n, 0)}) == False{} : Bool}:
  {==}

def invalid_finished_key() -> {S.finished(S.FinishedKey{[]}, S.zeros()) == None{} : Maybe<&2, List<&2, U32>>}:
  {==}

def invalid_finished_hash() -> {S.finished(S.FinishedKey{S.zeros()}, []) == None{} : Maybe<&2, List<&2, U32>>}:
  {==}

def all_tag_bytes_matter() -> {S.difference([1, 2, 3], [1, 2, 2], 0) == 1 : U32}:
  {==}
