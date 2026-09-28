import Base
import ./stun_fingerprint.bend as Fingerprint
import ./integrity_test.bend as IntegrityTest
import ./test.bend as StunTest
import ../crypto/bytes.bend as B

def rfc_request() -> {Fingerprint.verify(IntegrityTest.request()) == True{} : Bool}:
  {==}

def rfc_ipv4_response() -> {Fingerprint.verify(StunTest.rfc_ipv4()) == True{} : Bool}:
  {==}

def changed_header_fails() -> {Fingerprint.verify(IntegrityTest.alter(IntegrityTest.request(), 0n, 1)) == False{} : Bool}:
  {==}

def changed_content_fails() -> {Fingerprint.verify(IntegrityTest.alter(IntegrityTest.request(), 30n, 0)) == False{} : Bool}:
  {==}

def changed_crc_fails() -> {Fingerprint.verify(IntegrityTest.alter(IntegrityTest.request(), 107n, 0)) == False{} : Bool}:
  {==}

def wrong_size_fails() -> {Fingerprint.verify(IntegrityTest.alter(IntegrityTest.request(), 103n, 3)) == False{} : Bool}:
  {==}

def trailing_attribute_fails() -> {Fingerprint.verify(B.append(
  IntegrityTest.alter(IntegrityTest.request(), 3n, 92), [0, 1, 0, 0])) == False{} : Bool}:
  {==}

def duplicate_fingerprint_fails() -> {Fingerprint.verify(B.append(
  IntegrityTest.alter(IntegrityTest.request(), 3n, 96), [128, 40, 0, 4, 0, 0, 0, 0])) == False{} : Bool}:
  {==}
