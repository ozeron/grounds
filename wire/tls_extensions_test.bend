import Base
import ./tls_extensions.bend as E

def empty() -> {E.parse([0, 0]) == Some{[]} : Maybe<&2, List<&2, E.Extension>>}:
  {==}

def short() -> {E.parse([0]) == None{} : Maybe<&2, List<&2, E.Extension>>}:
  {==}

def trailing() -> {E.parse([0, 0, 0]) == None{} : Maybe<&2, List<&2, E.Extension>>}:
  {==}

def missing_body() -> {E.parse([0, 4, 0, 43, 0, 1]) == None{} : Maybe<&2, List<&2, E.Extension>>}:
  {==}

def unknown() -> {E.parse([0, 4, 255, 255, 0, 0]) == Some{[E.Extension{65535, []}]} : Maybe<&2, List<&2, E.Extension>>}:
  {==}

def duplicate() -> {E.parse([0, 8, 0, 1, 0, 0, 0, 1, 0, 0]) == None{} : Maybe<&2, List<&2, E.Extension>>}:
  {==}

def nonoctet() -> {E.parse([0, 4, 256, 0, 0, 0]) == None{} : Maybe<&2, List<&2, E.Extension>>}:
  {==}
