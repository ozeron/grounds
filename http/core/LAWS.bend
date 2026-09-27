import Base
import ./method.bend as M
import ./headers.bend as H
import ./query.bend as Q
import ./text.bend as T

# Laws grounds-http-core must keep. `bend PROOF.bend` fails while any is open or false.

# a header's first value is the one read: Host and Content-Type are the
# first given, however many follow
law header_first:
  for +n: String
  for +v: String
  for +hs: List<&2, H.Header>
  {H.get(Con{H.Header{n, v}, hs}, n) == Some{v} : Maybe<&2, String>}

# the same for a query's pairs
law query_first:
  for +k: String
  for +v: String
  for +ps: List<&2, Q.Param>
  {Q.get(Con{Q.Param{k, v}, ps}, k) == Some{v} : Maybe<&2, String>}

law same_refl:
  for +s: String
  for +ok: Bool
  {T.same(s, s, ok) == ok : Bool}

def standard(m: M.Method) -> Bool:
  match m:
    case M.MOther{_}:
      False{}
    case _:
      True{}

# a standard method reads back from its name; MOther{"GET"} is MGet, so
# the law holds for the nine only
law method_round_trip:
  for +m: M.Method
  for e: {standard(m) == True{} : Bool}
  {M.parse(M.show(m)) == m : M.Method}

law other_name:
  for n: String
  {M.show(M.MOther{n}) == n : String}
