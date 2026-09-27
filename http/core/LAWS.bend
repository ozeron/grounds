import Base
import ./headers.bend as H
import ./query.bend as Q
import ./text.bend as T
import ./proof/text.bend as P

# Laws grounds-http-core must keep. `bend PROOF.bend` fails while any is open or false.

# names compare ignoring case, and nothing else: same_ci is equality of
# the lowercased Strings
law same_ci:
  for +a: String
  for +b: String
  {T.same_ci(a, b, True{}) == T.same(P.lows(a), P.lows(b), True{}) : Bool}

# a header is found under any spelling of its name, and its first value is
# the one read: Host and Content-Type are the first given
law header_first:
  for +n: String
  for +m: String
  for +v: String
  for +hs: List<&2, H.Header>
  for e: {T.same(P.lows(n), P.lows(m), True{}) == True{} : Bool}
  {H.get(Con{H.Header{n, v}, hs}, m) == Some{v} : Maybe<&2, String>}

# a query key's first value is the one read
law query_first:
  for +k: String
  for +v: String
  for +ps: List<&2, Q.Param>
  {Q.get(Con{Q.Param{k, v}, ps}, k) == Some{v} : Maybe<&2, String>}
