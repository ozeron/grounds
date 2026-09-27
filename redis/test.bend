import Base
import ./resp.bend as R
import ../utf8/utf8.bend as U

# each def is a test: it checks only if both sides compute to the same value

def p(s: String) -> R.Parsed:
  R.parse(U.encode(s))

def done(r: R.Reply) -> R.Parsed:
  R.Parsed{r, []}

def bulk(s: String) -> R.Reply:
  R.Bulk{U.encode(s)}

def encode_set() -> {R.encode(["SET", "k", "v"]) == U.encode("*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$1\r\nv\r\n") : List<&2, U32>}:
  {==}

def encode_utf8() -> {R.encode(["GET", "€"]) == U.encode("*2\r\n$3\r\nGET\r\n$3\r\n€\r\n") : List<&2, U32>}:
  {==}

def encode_empty_arg() -> {R.encode(["SET", "k", ""]) == U.encode("*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$0\r\n\r\n") : List<&2, U32>}:
  {==}

def simple() -> {p("+OK\r\n") == done(R.Simple{"OK"}) : R.Parsed}:
  {==}

def error() -> {p("-ERR unknown command\r\n") == done(R.Error{"ERR unknown command"}) : R.Parsed}:
  {==}

def integer() -> {p(":42\r\n") == done(R.Int{False{}, 42n}) : R.Parsed}:
  {==}

def negative() -> {p(":-3\r\n") == done(R.Int{True{}, 3n}) : R.Parsed}:
  {==}

def bulk_string() -> {p("$5\r\nhello\r\n") == done(bulk("hello")) : R.Parsed}:
  {==}

def bulk_binary() -> {R.parse([36, 50, 13, 10, 0, 255, 13, 10]) == done(R.Bulk{[0, 255]}) : R.Parsed}:
  {==}

def bulk_crlf_inside() -> {p("$4\r\na\r\nb\r\n") == done(bulk("a\r\nb")) : R.Parsed}:
  {==}

def null_bulk() -> {p("$-1\r\n") == done(R.RNil{}) : R.Parsed}:
  {==}

def array() -> {p("*2\r\n$1\r\na\r\n:1\r\n") == done(R.Arr{[bulk("a"), R.Int{False{}, 1n}]}) : R.Parsed}:
  {==}

def nested() -> {p("*2\r\n*1\r\n:1\r\n:2\r\n") == done(R.Arr{[R.Arr{[R.Int{False{}, 1n}]}, R.Int{False{}, 2n}]}) : R.Parsed}:
  {==}

def empty_array() -> {p("*0\r\n") == done(R.Arr{[]}) : R.Parsed}:
  {==}

def null_array() -> {p("*-1\r\n") == done(R.RNil{}) : R.Parsed}:
  {==}

def rest_kept() -> {p("+OK\r\n+NEXT\r\n") == R.Parsed{R.Simple{"OK"}, U.encode("+NEXT\r\n")} : R.Parsed}:
  {==}

def partial_bulk() -> {p("$5\r\nhel") == R.More{} : R.Parsed}:
  {==}

def partial_array() -> {p("*2\r\n:1\r\n") == R.More{} : R.Parsed}:
  {==}

def partial_line() -> {p("+OK\r") == R.More{} : R.Parsed}:
  {==}

def bare_lf() -> {p("+OK\n") == R.Bad{"bare CR or LF"} : R.Parsed}:
  {==}

def bad_type() -> {p("?x\r\n") == R.Bad{"unknown reply type"} : R.Parsed}:
  {==}

def bad_length() -> {p("$x\r\n") == R.Bad{"bad bulk length"} : R.Parsed}:
  {==}

def bulk_no_crlf() -> {p("$1\r\nabxx") == R.Bad{"bulk string not ended by CR LF"} : R.Parsed}:
  {==}
