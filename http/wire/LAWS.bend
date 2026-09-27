import Base
import ./http1.bend as H1
import ./bytes.bend as B
import ../core/headers.bend as H
import ../core/method.bend as M

# Laws grounds-http-wire must keep. `bend PROOF.bend` fails while any is open or false.

def fte(fr: H1.Frame) -> Bool:
  match fr:
    case H1.Frame{_, te, _, _, _}:
      te

def te_of(s: H1.Scanned) -> Bool:
  match s:
    case H1.Scanned{_, fr}:
      fte(fr)

def is_err(f: H1.Fields) -> Bool:
  match f:
    case H1.FOk{_}:
      False{}
    case H1.FErr{_}:
      True{}

# Smuggling (RFC 9112 §6.1, §6.3)
# ----------

# once a Transfer-Encoding is seen, no later header clears it
law te_sticky:
  for +hs: List<&2, H.Header>
  for +fr: H1.Frame
  for +acc: List<&2, H.Header>
  for +e: {fte(fr) == True{} : Bool}
  {te_of(H1.scan(hs, fr, acc)) == True{} : Bool}

# a Transfer-Encoding anywhere among the headers is seen
law te_seen:
  for +pre: List<&2, H.Header>
  for +v: String
  for +post: List<&2, H.Header>
  for +fr: H1.Frame
  for +acc: List<&2, H.Header>
  {te_of(H1.scan(List.append(&2, H.Header, pre, Con{H.Header{"Transfer-Encoding", v}, post}), fr, acc)) == True{} : Bool}

# and a request that has one is refused: this server reads no chunked body
law te_refused:
  for +hosts: Bool
  for +cl: H1.CL
  for +close: Bool
  for +max: Nat
  for +rest: B.Bytes
  for +m: M.Method
  for +target: String
  for +hs: List<&2, H.Header>
  {H1.req.check(True{}, hosts, cl, close, max, rest, m, target, hs) == H1.Bad{H1.Unsupported{}} : H1.Parsed}

# two Content-Lengths that differ make the length bad
law cl_conflict:
  for +a: Nat
  for +b: Nat
  for +e: {Nat.is_eq(a, b) == False{} : Bool}
  {H1.cl_merge(H1.Len{a}, Some{b}) == H1.LenBad{} : H1.CL}

# a bad length stays bad, whatever follows
law cl_bad_sticky:
  for +m: Maybe<&2, Nat>
  {H1.cl_merge(H1.LenBad{}, m) == H1.LenBad{} : H1.CL}

# and a request with a bad length is refused
law cl_bad_refused:
  for +max: Nat
  for +rest: B.Bytes
  for +m: M.Method
  for +target: String
  for +hs: List<&2, H.Header>
  for +close: Bool
  {H1.req.len(H1.LenBad{}, max, rest, m, target, hs, close) == H1.Bad{H1.BadLength{}} : H1.Parsed}

# Obs-fold (RFC 9112 §5.2)
# --------

# a header line that starts with a space or tab, anywhere in the head,
# fails the head
law obs_fold:
  for +pre: List<&2, B.Bytes>
  for +w: U32
  for +l: B.Bytes
  for +post: List<&2, B.Bytes>
  for +acc: H1.Fields
  for +e: {B.is_ws(w) == True{} : Bool}
  {is_err(H1.fields(List.append(&2, B.Bytes, pre, Con{B.BCon{w, l}, post}), acc)) == True{} : Bool}

# Response splitting (RFC 9110 §5.5)
# ------------------

# a header whose value holds a CR, LF or NUL is not written
law unsafe_value_dropped:
  for +n: String
  for +v: String
  for +hs: List<&2, H.Header>
  for +out: String
  for +e: {H1.unsafe(v, False{}) == True{} : Bool}
  {H1.heads(Con{H.Header{n, v}, hs}, out) == H1.heads(hs, out) : String}

# nor one whose name does
law unsafe_name_dropped:
  for +n: String
  for +v: String
  for +hs: List<&2, H.Header>
  for +out: String
  for +e: {H1.unsafe(n, False{}) == True{} : Bool}
  {H1.heads(Con{H.Header{n, v}, hs}, out) == H1.heads(hs, out) : String}

# the framing headers are the writer's: a handler's are dropped
law framing_dropped:
  for +v: String
  for +hs: List<&2, H.Header>
  for +out: String
  {H1.heads(Con{H.Header{"Content-Length", v}, hs}, out) == H1.heads(hs, out) : String}

law te_dropped:
  for +v: String
  for +hs: List<&2, H.Header>
  for +out: String
  {H1.heads(Con{H.Header{"Transfer-Encoding", v}, hs}, out) == H1.heads(hs, out) : String}

law connection_dropped:
  for +v: String
  for +hs: List<&2, H.Header>
  for +out: String
  {H1.heads(Con{H.Header{"Connection", v}, hs}, out) == H1.heads(hs, out) : String}
