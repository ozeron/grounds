import Base
import ./resp.bend as R
import ./proof/nat.bend as N
import ./proof/spec.bend as S

# Laws grounds-redis must keep, from the RESP spec (docs/resp.md, docs/LAWS.md).
# `bend PROOF.bend` fails while any is open or false.
#
# The laws take the parser's fuel as a parameter: parse gives 2^32 - 1, one
# step per item and per value, more than any reply that fits in memory.

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
