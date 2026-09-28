import Base
import ../wire/bytes.bend as B
import ./websocket_frame.bend as F

def masked_hello() -> B.Bytes:
  B.of_list([129, 133, 55, 250, 33, 61, 127, 159, 77, 81, 88])

def rfc_hello() -> {F.parse(masked_hello()) == F.Frame{True{}, 1, B.of_list([72, 101, 108, 108, 111]), B.BNil{}} : F.Parsed}:
  {==}

def partial() -> {F.parse(B.of_list([129, 133, 55, 250, 33, 61, 127])) == F.More{} : F.Parsed}:
  {==}

def rejects_unmasked() -> {F.parse(B.of_list([129, 5, 72, 101, 108, 108, 111])) == F.Bad{1002} : F.Parsed}:
  {==}

def rejects_fragmented_ping() -> {F.parse(B.of_list([9, 128, 0, 0, 0, 0])) == F.Bad{1002} : F.Parsed}:
  {==}

def rejects_nonminimal_length() -> {F.parse(B.of_list([129, 254, 0, 5, 0, 0, 0, 0])) == F.Bad{1002} : F.Parsed}:
  {==}

def rejects_oversized_frame() -> {F.parse(B.of_list([130, 255, 0, 0, 0, 0, 0, 16, 0, 1])) == F.Bad{1009} : F.Parsed}:
  {==}

def rejects_high_length_bit() -> {F.parse(B.of_list([130, 255, 128])) == F.Bad{1002} : F.Parsed}:
  {==}

def writes_hello() -> {F.write(1, B.of_list([72, 101, 108, 108, 111])) == B.of_list([129, 5, 72, 101, 108, 108, 111]) : B.Bytes}:
  {==}

def writes_extended_length() -> {F.write.large(2, 65536n, B.BNil{}) ==
  B.of_list([130, 127, 0, 0, 0, 0, 0, 1, 0, 0]) : B.Bytes}:
  {==}
