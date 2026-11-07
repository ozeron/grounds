import Base
import ./ip.bend as I

# each def is a test: it checks only if both sides compute to the same value

# IPv6 text to bytes
def v6_loopback() -> {I.v6.octets("::1") == Some{[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]} : Maybe<&2, List<&2, U32>>}:
  {==}

def v6_doc() -> {I.v6.octets("2001:db8::1") == Some{[32,1,13,184,0,0,0,0,0,0,0,0,0,0,0,1]} : Maybe<&2, List<&2, U32>>}:
  {==}

def v6_full() -> {I.v6.octets("2001:0DB8:0000:0000:0000:ff00:0042:8329") == Some{[32,1,13,184,0,0,0,0,0,0,255,0,0,66,131,41]} : Maybe<&2, List<&2, U32>>}:
  {==}

def v6_unspecified() -> {I.v6.octets("::") == Some{[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]} : Maybe<&2, List<&2, U32>>}:
  {==}

def v6_trailing_gap() -> {I.v6.parse("fe80::") == Some{[65152,0,0,0,0,0,0,0]} : Maybe<&2, List<&2, U32>>}:
  {==}

def v6_gap_of_one() -> {I.v6.parse("1:2:3:4:5:6::8") == Some{[1,2,3,4,5,6,0,8]} : Maybe<&2, List<&2, U32>>}:
  {==}

def v6_gap_lead_seven() -> {I.v6.parse("::2:3:4:5:6:7:8") == Some{[0,2,3,4,5,6,7,8]} : Maybe<&2, List<&2, U32>>}:
  {==}

# malformed IPv6 text
def v6_bad_empty() -> {I.v6.parse("") == None{} : Maybe<&2, List<&2, U32>>}:
  {==}

def v6_bad_one_colon() -> {I.v6.parse(":1") == None{} : Maybe<&2, List<&2, U32>>}:
  {==}

def v6_bad_dangling() -> {I.v6.parse("1:") == None{} : Maybe<&2, List<&2, U32>>}:
  {==}

def v6_bad_triple() -> {I.v6.parse(":::") == None{} : Maybe<&2, List<&2, U32>>}:
  {==}

def v6_bad_two_gaps() -> {I.v6.parse("1::2::3") == None{} : Maybe<&2, List<&2, U32>>}:
  {==}

def v6_bad_five_digits() -> {I.v6.parse("12345::1") == None{} : Maybe<&2, List<&2, U32>>}:
  {==}

def v6_bad_nine() -> {I.v6.parse("1:2:3:4:5:6:7:8:9") == None{} : Maybe<&2, List<&2, U32>>}:
  {==}

def v6_bad_seven() -> {I.v6.parse("1:2:3:4:5:6:7") == None{} : Maybe<&2, List<&2, U32>>}:
  {==}

def v6_bad_gap_full() -> {I.v6.parse("1:2:3:4::5:6:7:8") == None{} : Maybe<&2, List<&2, U32>>}:
  {==}

def v6_bad_zone() -> {I.v6.parse("fe80::1%en0") == None{} : Maybe<&2, List<&2, U32>>}:
  {==}

def v6_bad_url_zone() -> {I.v6.parse("fe80::1%25en0") == None{} : Maybe<&2, List<&2, U32>>}:
  {==}

def v6_bad_dotted_tail() -> {I.v6.parse("::ffff:192.0.2.1") == None{} : Maybe<&2, List<&2, U32>>}:
  {==}

def v6_bad_hex() -> {I.v6.parse("2001:db8::g") == None{} : Maybe<&2, List<&2, U32>>}:
  {==}

def v6_bad_space() -> {I.v6.parse(" ::1") == None{} : Maybe<&2, List<&2, U32>>}:
  {==}

# canonical text (RFC 5952 section 4)
def canon_compressed() -> {I.v6.canon("2001:DB8:0:0:0:0:0:1") == Some{"2001:db8::1"} : Maybe<&2, String>}:
  {==}

def canon_zeros() -> {I.v6.canon("2001:0db8:0000::0001") == Some{"2001:db8::1"} : Maybe<&2, String>}:
  {==}

def canon_loopback() -> {I.v6.canon("0:0:0:0:0:0:0:1") == Some{"::1"} : Maybe<&2, String>}:
  {==}

def canon_all() -> {I.v6.canon("0:0:0:0:0:0:0:0") == Some{"::"} : Maybe<&2, String>}:
  {==}

def canon_trailing() -> {I.v6.canon("1:0:0:0:0:0:0:0") == Some{"1::"} : Maybe<&2, String>}:
  {==}

def canon_single_zero() -> {I.v6.canon("2001:db8:0:1:1:1:1:1") == Some{"2001:db8:0:1:1:1:1:1"} : Maybe<&2, String>}:
  {==}

def canon_longest() -> {I.v6.canon("2001:0:0:1:0:0:0:1") == Some{"2001:0:0:1::1"} : Maybe<&2, String>}:
  {==}

def canon_first_tie() -> {I.v6.canon("2001:db8:0:0:1:0:0:1") == Some{"2001:db8::1:0:0:1"} : Maybe<&2, String>}:
  {==}

def canon_hex_widths() -> {I.v6.canon("a:Bc:dEf:1234:0:0:fFfF:10") == Some{"a:bc:def:1234::ffff:10"} : Maybe<&2, String>}:
  {==}

def canon_bad() -> {I.v6.canon("::1%25lo0") == None{} : Maybe<&2, String>}:
  {==}

# IPv4 text
def v4_ok() -> {I.v4.parse("192.0.2.1") == Some{[192,0,2,1]} : Maybe<&2, List<&2, U32>>}:
  {==}

def v4_zero() -> {I.v4.parse("0.0.0.0") == Some{[0,0,0,0]} : Maybe<&2, List<&2, U32>>}:
  {==}

def v4_bad_leading_zero() -> {I.v4.parse("10.01.2.3") == None{} : Maybe<&2, List<&2, U32>>}:
  {==}

def v4_bad_big() -> {I.v4.parse("1.2.3.256") == None{} : Maybe<&2, List<&2, U32>>}:
  {==}

def v4_bad_three() -> {I.v4.parse("1.2.3") == None{} : Maybe<&2, List<&2, U32>>}:
  {==}

def v4_bad_five() -> {I.v4.parse("1.2.3.4.5") == None{} : Maybe<&2, List<&2, U32>>}:
  {==}

def v4_bad_empty_part() -> {I.v4.parse("1..3.4") == None{} : Maybe<&2, List<&2, U32>>}:
  {==}

# literals and names
def octets_v4() -> {I.octets("127.0.0.1") == Some{[127,0,0,1]} : Maybe<&2, List<&2, U32>>}:
  {==}

def octets_v6() -> {I.octets("::1") == Some{[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]} : Maybe<&2, List<&2, U32>>}:
  {==}

def octets_name() -> {I.octets("localhost") == None{} : Maybe<&2, List<&2, U32>>}:
  {==}

def literal_name() -> {I.literal("example.com") == False{} : Bool}:
  {==}

def literal_v6() -> {I.literal("2001:db8::1") == True{} : Bool}:
  {==}

def colon_v6() -> {I.has_colon("fe80::1%4") == True{} : Bool}:
  {==}

# address order (RFC 8305 section 4): families alternate from the first
# address's; scoped addresses are dropped; at most eight
def order_mixed() -> {I.order(["::1", "2001:db8::2", "127.0.0.1", "192.0.2.1"]) == ["::1", "127.0.0.1", "2001:db8::2", "192.0.2.1"] : List<&2, String>}:
  {==}

def order_v4_first() -> {I.order(["127.0.0.1", "::1", "::2"]) == ["127.0.0.1", "::1", "::2"] : List<&2, String>}:
  {==}

def order_scoped() -> {I.order(["fe80::1%4", "127.0.0.1", "::1"]) == ["127.0.0.1", "::1"] : List<&2, String>}:
  {==}

def order_one_family() -> {I.order(["192.0.2.1", "192.0.2.2"]) == ["192.0.2.1", "192.0.2.2"] : List<&2, String>}:
  {==}

def order_none() -> {I.order(["fe80::1%4"]) == [] : List<&2, String>}:
  {==}

def order_capped() -> {I.order(["::1", "::2", "::3", "::4", "::5", "::6", "::7", "::8", "::9", "1.1.1.1"]) == ["::1", "1.1.1.1", "::2", "::3", "::4", "::5", "::6", "::7"] : List<&2, String>}:
  {==}

# an attempt's share of the time left
def budget_last() -> {I.budget(900, 1) == 900 : U32}:
  {==}

def budget_shared() -> {I.budget(2000, 2) == 1000 : U32}:
  {==}

def budget_floor() -> {I.budget(1000, 8) == 250 : U32}:
  {==}

def budget_floor_capped() -> {I.budget(100, 3) == 100 : U32}:
  {==}
