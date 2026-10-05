import Base
import ./tls_transcript.bend as T

def valid_empty_hello() -> {T.framed([1, 0, 0, 0]) == True{} : Bool}:
  {==}

def invalid_synthetic_message() -> {T.framed([254, 0, 0, 0]) == False{} : Bool}:
  {==}

def invalid_octet() -> {T.framed([1, 0, 0, 1, 256]) == False{} : Bool}:
  {==}

def invalid_short_header() -> {T.framed([1, 0, 0]) == False{} : Bool}:
  {==}

def invalid_length() -> {T.framed([1, 0, 0, 2, 0]) == False{} : Bool}:
  {==}

def invalid_trailing_byte() -> {T.framed([1, 0, 0, 0, 0]) == False{} : Bool}:
  {==}
