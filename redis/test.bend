import Base
import ./resp.bend as R
import ../utf8/utf8.bend as U

# each def is a test: it checks only if both sides compute to the same value

def p(s: String) -> R.Parsed:
  R.parse(U.encode(s))

def done(r: R.Reply) -> R.Parsed:
  R.Parsed{r, R.BNil{}}

def bulk(s: String) -> R.Reply:
  R.Bulk{U.encode(s)}

# More, Bad, TooLarge or Parsed, without the state More carries
def what(r: R.Parsed) -> String:
  match r:
    case R.Parsed{_, _}:
      "parsed"
    case R.More{_, _}:
      "more"
    case R.Bad{why}:
      why
    case R.TooLarge{}:
      "too large"

def missing(r: R.Parsed) -> Nat:
  match r:
    case R.More{_, n}:
      n
    case _:
      0n

# a parse that stopped, fed the rest
def resume(r: R.Parsed, s: String) -> R.Parsed:
  match r:
    case R.More{m, _}:
      R.parse.at(R.feed(m, R.buf.of(U.encode(s))), 536870912n)
    case other:
      other

# Commands

def encode_set() -> {R.encode(["SET", "k", "v"]) == U.encode("*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$1\r\nv\r\n") : List<&2, U32>}:
  {==}

def encode_utf8() -> {R.encode(["GET", "€"]) == U.encode("*2\r\n$3\r\nGET\r\n$3\r\n€\r\n") : List<&2, U32>}:
  {==}

def encode_empty_arg() -> {R.encode(["SET", "k", ""]) == U.encode("*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$0\r\n\r\n") : List<&2, U32>}:
  {==}

def encode_ten() -> {R.encode(["A", "B", "C", "D", "E", "F", "G", "H", "I", "J"]) == U.encode("*10\r\n$1\r\nA\r\n$1\r\nB\r\n$1\r\nC\r\n$1\r\nD\r\n$1\r\nE\r\n$1\r\nF\r\n$1\r\nG\r\n$1\r\nH\r\n$1\r\nI\r\n$1\r\nJ\r\n") : List<&2, U32>}:
  {==}

def encode_binary() -> {R.encode_bytes([[83, 69, 84], [0, 13, 10, 255]]) == [42, 50, 13, 10, 36, 51, 13, 10, 83, 69, 84, 13, 10, 36, 52, 13, 10, 0, 13, 10, 255, 13, 10] : List<&2, U32>}:
  {==}

def encode_reads_back() -> {R.parse(R.encode(["SET", "a\r\n*1\r\n$8\r\nFLUSHALL", "v"])) == done(R.Arr{[bulk("SET"), bulk("a\r\n*1\r\n$8\r\nFLUSHALL"), bulk("v")]}) : R.Parsed}:
  {==}

# RESP2 replies

def simple() -> {p("+OK\r\n") == done(R.Simple{"OK"}) : R.Parsed}:
  {==}

def error() -> {p("-ERR unknown command\r\n") == done(R.Error{"ERR unknown command"}) : R.Parsed}:
  {==}

def integer() -> {p(":42\r\n") == done(R.Int{"42"}) : R.Parsed}:
  {==}

def negative() -> {p(":-3\r\n") == done(R.Int{"-3"}) : R.Parsed}:
  {==}

def bulk_string() -> {p("$5\r\nhello\r\n") == done(bulk("hello")) : R.Parsed}:
  {==}

def bulk_binary() -> {R.parse([36, 50, 13, 10, 0, 255, 13, 10]) == done(R.Bulk{[0, 255]}) : R.Parsed}:
  {==}

def bulk_crlf_inside() -> {p("$4\r\na\r\nb\r\n") == done(bulk("a\r\nb")) : R.Parsed}:
  {==}

def null_bulk() -> {p("$-1\r\n") == done(R.RNil{}) : R.Parsed}:
  {==}

def empty_bulk() -> {p("$0\r\n\r\n") == done(R.Bulk{[]}) : R.Parsed}:
  {==}

def array() -> {p("*2\r\n$1\r\na\r\n:1\r\n") == done(R.Arr{[bulk("a"), R.Int{"1"}]}) : R.Parsed}:
  {==}

def nested() -> {p("*2\r\n*1\r\n:1\r\n:2\r\n") == done(R.Arr{[R.Arr{[R.Int{"1"}]}, R.Int{"2"}]}) : R.Parsed}:
  {==}

def empty_array() -> {p("*0\r\n") == done(R.Arr{[]}) : R.Parsed}:
  {==}

def null_array() -> {p("*-1\r\n") == done(R.RNil{}) : R.Parsed}:
  {==}

def rest_kept() -> {p("+OK\r\n+NEXT\r\n") == R.Parsed{R.Simple{"OK"}, R.buf.of(U.encode("+NEXT\r\n"))} : R.Parsed}:
  {==}

# RESP3 replies

def resp3_null() -> {p("_\r\n") == done(R.RNil{}) : R.Parsed}:
  {==}

def resp3_bool() -> {p("#t\r\n") == done(R.RBool{True{}}) : R.Parsed}:
  {==}

def resp3_double() -> {p(",3.14\r\n") == done(R.RDouble{"3.14"}) : R.Parsed}:
  {==}

def resp3_big() -> {p("(-123\r\n") == done(R.RBig{"-123"}) : R.Parsed}:
  {==}

def resp3_bulk_error() -> {p("!5\r\nOOPS!\r\n") == done(R.BulkError{U.encode("OOPS!")}) : R.Parsed}:
  {==}

def resp3_verbatim() -> {p("=9\r\ntxt:hello\r\n") == done(R.Verbatim{"txt", U.encode("hello")}) : R.Parsed}:
  {==}

def resp3_map() -> {p("%2\r\n+a\r\n:1\r\n+b\r\n:2\r\n") == done(R.RMap{[R.Simple{"a"}, R.Int{"1"}, R.Simple{"b"}, R.Int{"2"}]}) : R.Parsed}:
  {==}

def resp3_set() -> {p("~2\r\n:1\r\n:2\r\n") == done(R.RSet{[R.Int{"1"}, R.Int{"2"}]}) : R.Parsed}:
  {==}

def resp3_push() -> {p(">2\r\n+message\r\n+hi\r\n") == done(R.RPush{[R.Simple{"message"}, R.Simple{"hi"}]}) : R.Parsed}:
  {==}

def resp3_attribute() -> {p("|1\r\n+ttl\r\n:3\r\n:7\r\n") == done(R.Int{"7"}) : R.Parsed}:
  {==}

# Partial input, and going on

def partial_bulk() -> {what(p("$5\r\nhel")) == "more" : String}:
  {==}

def partial_bulk_missing() -> {missing(p("$5\r\nhel")) == 4n : Nat}:
  {==}

def partial_array() -> {what(p("*2\r\n:1\r\n")) == "more" : String}:
  {==}

def partial_line() -> {what(p("+OK\r")) == "more" : String}:
  {==}

def resumed_bulk() -> {resume(p("$5\r\nhel"), "lo\r\n") == done(bulk("hello")) : R.Parsed}:
  {==}

def resumed_array() -> {resume(p("*2\r\n:1\r\n$3\r\nab"), "c\r\n+x\r\n") == R.Parsed{R.Arr{[R.Int{"1"}, bulk("abc")]}, R.buf.of(U.encode("+x\r\n"))} : R.Parsed}:
  {==}

def resumed_line() -> {resume(p("+O"), "K\r\n") == done(R.Simple{"OK"}) : R.Parsed}:
  {==}

# Refused

def bare_lf() -> {what(p("+OK\n")) == "bare CR or LF" : String}:
  {==}

def bad_type() -> {what(p("?x\r\n")) == "unknown reply type" : String}:
  {==}

def bad_length() -> {what(p("$x\r\n")) == "bad bulk length" : String}:
  {==}

def streamed() -> {what(p("$?\r\n;4\r\nHell\r\n;0\r\n")) == "bad bulk length" : String}:
  {==}

def bulk_no_crlf() -> {what(p("$1\r\nabxx")) == "bulk string not ended by CR LF" : String}:
  {==}

def too_large_bulk() -> {what(R.parse.buf(R.buf.of(U.encode("$11\r\nhello world\r\n")), 10n)) == "too large" : String}:
  {==}

def too_large_array() -> {what(R.parse.buf(R.buf.of(U.encode("*3\r\n:1\r\n:2\r\n:3\r\n")), 2n)) == "too large" : String}:
  {==}

# Writing, and reading back

def write_nested() -> {R.write(R.Arr{[bulk("a"), R.Arr{[R.Int{"-2"}]}, R.RNil{}]}) == U.encode("*3\r\n$1\r\na\r\n*1\r\n:-2\r\n_\r\n") : List<&2, U32>}:
  {==}

def write_map() -> {R.write(R.RMap{[R.Simple{"a"}, R.RBool{True{}}]}) == U.encode("%1\r\n+a\r\n#t\r\n") : List<&2, U32>}:
  {==}

def write_reads_back() -> {R.parse(R.write(R.RSet{[R.Verbatim{"txt", U.encode("hi")}, R.RDouble{"1.5"}, R.BulkError{U.encode("E")}]})) == done(R.RSet{[R.Verbatim{"txt", U.encode("hi")}, R.RDouble{"1.5"}, R.BulkError{U.encode("E")}]}) : R.Parsed}:
  {==}

# numbers the runtime could not hold as a Nat stay text

def huge_int() -> {p(":123456789012345678901234567890\r\n") == done(R.Int{"123456789012345678901234567890"}) : R.Parsed}:
  {==}

def huge_length() -> {what(p("$123456789012345678901234567890\r\n")) == "too large" : String}:
  {==}

def padded_length() -> {what(p("$00000000005\r\nhello\r\n")) == "too large" : String}:
  {==}

def bad_int() -> {what(p(":12a\r\n")) == "bad integer" : String}:
  {==}

# review fixes

def plus_int() -> {p(":+5\r\n") == done(R.Int{"+5"}) : R.Parsed}:
  {==}

def attr_null() -> {what(p("|-1\r\n")) == "bad aggregate length" : String}:
  {==}

def map_null() -> {what(p("%-1\r\n")) == "bad aggregate length" : String}:
  {==}

def bulk_error_null() -> {what(p("!-1\r\n")) == "bad bulk length" : String}:
  {==}

def attr_in_array() -> {p("*2\r\n|1\r\n+a\r\n:1\r\n:5\r\n:6\r\n") == done(R.Arr{[R.Int{"5"}, R.Int{"6"}]}) : R.Parsed}:
  {==}

def empty_attr() -> {p("|0\r\n:7\r\n") == done(R.Int{"7"}) : R.Parsed}:
  {==}

def empty_map() -> {p("%0\r\n") == done(R.RMap{[]}) : R.Parsed}:
  {==}

def verbatim_no_format() -> {R.parse(R.write(R.Verbatim{"", U.encode("ab")})) == done(R.Verbatim{"", U.encode("ab")}) : R.Parsed}:
  {==}

def text_not_utf8() -> {R.parse([45, 69, 82, 82, 32, 255, 33, 13, 10]) == done(R.Error{"ERR \u{ff}!"}) : R.Parsed}:
  {==}

def line_resumed_at_cr() -> {resume(p("+OK\r"), "\n") == done(R.Simple{"OK"}) : R.Parsed}:
  {==}

def line_resumed_twice() -> {resume(resume(p("+ab"), "cd"), "e\r\n") == done(R.Simple{"abcde"}) : R.Parsed}:
  {==}
