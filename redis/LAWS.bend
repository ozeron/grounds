import Base
import ./resp.bend as R
import ./proof/nat.bend as N
import ./proof/spec.bend as S
import ../utf8/utf8.bend as U

# Laws grounds-redis must keep, from the RESP spec (docs/resp.md, docs/LAWS.md).
# `bend PROOF.bend` fails while any is open or false.
#
# The laws take the parser's fuel and limit as parameters (parse gives 2^32 - 1
# steps, three per argument, and a 2^29-byte limit); parse_encode is the same
# law for parse and encode themselves, on Strings.
#
# The laws are about this parser reading this encoder: the framing is RESP's,
# so they stand for any RESP parser, Redis's included, that reads it as the
# spec says.

def is_more(p: R.Parsed) -> Bool:
  match p:
    case R.More{_, _}:
      True{}
    case _:
      False{}

# Commands (spec: "Sending commands to a Redis server")
# --------

# a command reads back as the array of bulk strings it was built from, and
# the bytes after it are left as they are. The arguments are any bytes: a
# CR LF, or a whole command, inside one stays inside it. No argument can
# end the command early or start another
law command_reads_back:
  for +xs: R.Args
  for +tail: R.Buf
  for +max: Nat
  for +f: Nat
  for +e: {S.cfits(xs, max) == True{} : Bool}
  {R.parse.go(1n+Nat.add(S.steps(xs), 1n+f), max, R.MItem{R.encode.buf(xs, tail), []}) == R.Parsed{R.Arr{S.bulks(xs)}, tail} : R.Parsed}

# Replies (spec: "Bulk strings", "Null bulk strings")
# -------

# a bulk string is framed by its length: any bytes, a CR LF inside them
# included, come back as they are, and what follows is kept
law bulk_framed:
  for +a: R.Buf
  for +tail: R.Buf
  for +max: Nat
  for +f: Nat
  for +e: {S.fit(a, max) == True{} : Bool}
  {R.parse.go(1n+1n+1n+f, max, R.MItem{R.enc.arg(a, tail), []}) == R.Parsed{R.Bulk{R.buf.list(a)}, tail} : R.Parsed}

# a bulk string cut short, anywhere in its bytes, is More: never a reply
law bulk_cut:
  for +a: R.Buf
  for +p: R.Buf
  for +max: Nat
  for +f: Nat
  for +e: {S.fit(a, max) == True{} : Bool}
  for +short: {Nat.is_lt(N.blen(p), N.blen(a)) == True{} : Bool}
  {is_more(R.parse.go(1n+1n+f, max, R.MItem{R.BCon{36, R.render0(R.count(a, R.DNil{}), R.crlf(p))}, []})) == True{} : Bool}

# and cut anywhere before its bytes: after the $, in its length, at the CR
law cut_dollar:
  for +max: Nat
  for +f: Nat
  {is_more(R.parse.go(1n+f, max, R.MItem{R.BCon{36, R.BNil{}}, []})) == True{} : Bool}

law cut_length:
  for +d: R.Dec
  for +max: Nat
  for +f: Nat
  {is_more(R.parse.go(1n+f, max, R.MItem{R.BCon{36, R.render(d, R.BNil{})}, []})) == True{} : Bool}

law cut_cr:
  for +d: R.Dec
  for +max: Nat
  for +f: Nat
  {is_more(R.parse.go(1n+f, max, R.MItem{R.BCon{36, R.render0(d, R.BCon{13, R.BNil{}})}, []})) == True{} : Bool}

# and after its bytes, before or inside the CR LF that ends it
law cut_end:
  for +a: R.Buf
  for +max: Nat
  for +f: Nat
  for +e: {S.fit(a, max) == True{} : Bool}
  {is_more(R.parse.go(1n+1n+f, max, R.MItem{R.BCon{36, R.render0(R.count(a, R.DNil{}), R.crlf(R.cat(a, R.BNil{})))}, []})) == True{} : Bool}

law cut_end_cr:
  for +a: R.Buf
  for +max: Nat
  for +f: Nat
  for +e: {S.fit(a, max) == True{} : Bool}
  {is_more(R.parse.go(1n+1n+f, max, R.MItem{R.BCon{36, R.render0(R.count(a, R.DNil{}), R.crlf(R.cat(a, R.BCon{13, R.BNil{}})))}, []})) == True{} : Bool}

# the null bulk string is nil, and the empty one is the empty string: a
# client must tell them apart
law null_bulk:
  for +rest: R.Buf
  for +max: Nat
  for +f: Nat
  {R.parse.go(1n+1n+f, max, R.MItem{R.BCon{36, R.BCon{45, R.BCon{49, R.crlf(rest)}}}, []}) == R.Parsed{R.RNil{}, rest} : R.Parsed}

law empty_bulk:
  for +rest: R.Buf
  for +max: Nat
  for +f: Nat
  {R.parse.go(1n+1n+1n+f, max, R.MItem{R.BCon{36, R.BCon{48, R.crlf(R.crlf(rest))}}, []}) == R.Parsed{R.Bulk{[]}, rest} : R.Parsed}

# The List and String API
# -----------------------

def texts(xs: List<&2, String>) -> List<&2, R.Reply>:
  match xs:
    case Nil{}:
      []
    case Con{x, t}:
      Con{R.Bulk{U.encode(x)}, texts(t)}

# command_reads_back for encode itself, on Strings, read as parse reads it:
# any Strings come back as the bulk strings of their UTF-8. parse is this
# with fuel 2^32 - 1, which covers every command of fewer than 1.4e9
# arguments; the checker unfolds a literal fuel one step at a time, so the
# law takes any fuel that covers the steps: three per argument, and two
law parse_encode:
  for +xs: List<&2, String>
  for +fuel: Nat
  for +g: Nat
  for +e: {S.cfits(R.args.text(xs), 536870912n) == True{} : Bool}
  for +ef: {fuel == 1n+Nat.add(S.steps(R.args.text(xs)), 1n+g) : Nat}
  {R.parse.go(fuel, 536870912n, R.MItem{R.buf.of(R.encode(xs)), []}) == R.Parsed{R.Arr{texts(xs)}, R.BNil{}} : R.Parsed}
