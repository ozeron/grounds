import Base
import ./der.bend as D

def der_nonbyte() -> {D.decode([4, 1, 256]) == None{} : Maybe<&1, D.Element>}:
  {==}

def der_indefinite() -> {D.decode([48, 128, 0, 0]) == None{} : Maybe<&1, D.Element>}:
  {==}

def der_nonminimal() -> {D.decode([4, 129, 1, 0]) == None{} : Maybe<&1, D.Element>}:
  {==}

def der_truncated() -> {D.decode([4, 2, 0]) == None{} : Maybe<&1, D.Element>}:
  {==}

def der_preserves_encoding() -> {D.decode([4, 1, 17, 5, 0]) == Some{D.Element{4, [17], [5, 0], [4, 1, 17]}} : Maybe<&1, D.Element>}:
  {==}

def complete_body() -> {D.complete(4, [4, 1, 17]) == Some{[17]} : Maybe<&1, List<&2, U32>>}:
  {==}

def complete_rejects_trailing() -> {D.complete(4, [4, 1, 17, 5, 0]) == None{} : Maybe<&1, List<&2, U32>>}:
  {==}

def complete_rejects_wrong_tag() -> {D.complete(48, [4, 1, 17]) == None{} : Maybe<&1, List<&2, U32>>}:
  {==}
