import Base
import ./stun.bend as Stun

# RFC 5769 section 2.2: a Binding success response for 192.0.2.1:32853.
def rfc_ipv4() -> List<&2, U32>:
  [1, 1, 0, 60, 33, 18, 164, 66, 183, 231, 167, 1, 188, 52, 214, 134,
   250, 135, 223, 174, 128, 34, 0, 11, 116, 101, 115, 116, 32, 118,
   101, 99, 116, 111, 114, 32, 0, 32, 0, 8, 0, 1, 161, 71, 225, 18,
   166, 67, 0, 8, 0, 20, 43, 145, 245, 153, 253, 158, 144, 195, 140,
   116, 137, 249, 42, 249, 186, 83, 240, 107, 231, 215, 128, 40, 0,
   4, 192, 125, 76, 150]

def mapped(m: Maybe<&2, Stun.Packet>) -> Maybe<&2, Stun.IPv4>:
  match m:
    case Some{packet}:
      Stun.mapped_ipv4(packet)
    case None{}:
      None{}

def rfc_mapped() -> {mapped(Stun.parse(rfc_ipv4())) ==
  Some{Stun.IPv4{192, 0, 2, 1, 32853}} : Maybe<&2, Stun.IPv4>}:
  {==}

def binding_request() -> {Stun.binding_request([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]) ==
  Some{[0, 1, 0, 0, 33, 18, 164, 66, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]} : Maybe<&2, List<&2, U32>>}:
  {==}

def rejects_bad_cookie() -> {Stun.parse([0, 1, 0, 0, 0, 18, 164, 66,
  1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]) == None{} : Maybe<&2, Stun.Packet>}:
  {==}

def rejects_bad_length() -> {Stun.parse([0, 1, 0, 4, 33, 18, 164, 66,
  1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]) == None{} : Maybe<&2, Stun.Packet>}:
  {==}

def rejects_bad_byte() -> {Stun.parse([0, 1, 0, 0, 33, 18, 164, 66,
  1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 256]) == None{} : Maybe<&2, Stun.Packet>}:
  {==}

def rejects_bad_top_bits() -> {Stun.parse([128, 1, 0, 0, 33, 18, 164, 66,
  1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]) == None{} : Maybe<&2, Stun.Packet>}:
  {==}

def rejects_truncated_attribute() -> {Stun.parse([0, 1, 0, 4, 33, 18, 164, 66,
  1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 32, 0, 8]) == None{} : Maybe<&2, Stun.Packet>}:
  {==}

def rejects_short_transaction() -> {Stun.binding_request([1, 2, 3]) == None{} : Maybe<&2, List<&2, U32>>}:
  {==}
