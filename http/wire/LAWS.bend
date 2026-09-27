import Base
import ./http1.bend as H1
import ./bytes.bend as B
import ../core/headers.bend as H
import ../core/method.bend as M
import ../core/proof/text.bend as P

# Laws grounds-http-wire must keep. `bend PROOF.bend` fails while any is open or false.
# A header name is matched ignoring case: the laws take any name n whose
# lowercase is the one meant, so they hold for "TRANSFER-encoding" too.

def fte(fr: H1.Frame) -> Bool:
  match fr:
    case H1.Frame{_, te, _, _, _}:
      te

def te_of(s: H1.Scanned) -> Bool:
  match s:
    case H1.Scanned{_, fr}:
      fte(fr)

def fcl(fr: H1.Frame) -> H1.CL:
  match fr:
    case H1.Frame{cl, _, _, _, _}:
      cl

def cl_of(s: H1.Scanned) -> H1.CL:
  match s:
    case H1.Scanned{_, fr}:
      fcl(fr)

def is_err(f: H1.Fields) -> Bool:
  match f:
    case H1.FOk{_}:
      False{}
    case H1.FErr{_}:
      True{}

def is_bad(p: H1.Parsed) -> Bool:
  match p:
    case H1.Bad{_}:
      True{}
    case _:
      False{}

# the Content-Length a header value gives, as the scan reads it
def digits(v: String) -> Maybe<&2, Nat>:
  H1.cl_digits.go(v, 0n, True{}, False{})

# Smuggling (RFC 9112 §6.1, §6.3)
# ----------

# a Transfer-Encoding anywhere among the headers is seen, and no later
# header clears it
law te_seen:
  for +pre: List<&2, H.Header>
  for +n: String
  for +v: String
  for +post: List<&2, H.Header>
  for +fr: H1.Frame
  for +acc: List<&2, H.Header>
  for e: {P.lows(n) == "transfer-encoding" : String}
  {te_of(H1.scan(List.append(&2, H.Header, pre, Con{H.Header{n, v}, post}), fr, acc)) == True{} : Bool}

# a bad Content-Length stays bad to the end of the headers
law cl_bad_stays:
  for +hs: List<&2, H.Header>
  for +fr: H1.Frame
  for +acc: List<&2, H.Header>
  for e: {fcl(fr) == H1.LenBad{} : H1.CL}
  {cl_of(H1.scan(hs, fr, acc)) == H1.LenBad{} : H1.CL}

# two Content-Lengths that differ, anywhere among the headers, make the
# length bad
law cl_twice:
  for +pre: List<&2, H.Header>
  for +n1: String
  for +v1: String
  for +mid: List<&2, H.Header>
  for +n2: String
  for +v2: String
  for +post: List<&2, H.Header>
  for +fr: H1.Frame
  for +acc: List<&2, H.Header>
  for +a: Nat
  for +b: Nat
  for e1: {P.lows(n1) == "content-length" : String}
  for e2: {P.lows(n2) == "content-length" : String}
  for d1: {digits(v1) == Some{a} : Maybe<&2, Nat>}
  for d2: {digits(v2) == Some{b} : Maybe<&2, Nat>}
  for ne: {Nat.is_eq(a, b) == False{} : Bool}
  {cl_of(H1.scan(List.append(&2, H.Header, pre, Con{H.Header{n1, v1}, List.append(&2, H.Header, mid, Con{H.Header{n2, v2}, post})}), fr, acc)) == H1.LenBad{} : H1.CL}

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
  for e: {B.is_ws(w) == True{} : Bool}
  {is_err(H1.fields(List.append(&2, B.Bytes, pre, Con{B.BCon{w, l}, post}), acc)) == True{} : Bool}

# End to end: the head of buf split into its request line and header lines
# ----------

# a request with a Transfer-Encoding is refused
law parse_te:
  for +buf: B.Bytes
  for +mh: U32
  for +mb: U32
  for +first: B.Bytes
  for +hl: List<&2, B.Bytes>
  for +rest: B.Bytes
  for +m: M.Method
  for +t: String
  for +ver: H1.Version
  for +hs: List<&2, H.Header>
  for +pre: List<&2, H.Header>
  for +n: String
  for +v: String
  for +post: List<&2, H.Header>
  for es: {H1.split.go(buf, B.BNil{}, [], 0, mh, False{}) == H1.Lines{Con{first, hl}, rest} : H1.Split}
  for el: {H1.request_line(H1.split_sp.go(first, B.BNil{}, [])) == H1.Line{m, t, ver} : H1.Line}
  for ef: {H1.fields(hl, H1.FOk{[]}) == H1.FOk{hs} : H1.Fields}
  for eo: {List.reverse(&2, H.Header, hs) == List.append(&2, H.Header, pre, Con{H.Header{n, v}, post}) : List<&2, H.Header>}
  for en: {P.lows(n) == "transfer-encoding" : String}
  {H1.parse(buf, mh, mb) == H1.Bad{H1.Unsupported{}} : H1.Parsed}

# a request with two differing Content-Lengths is refused
law parse_cl_twice:
  for +buf: B.Bytes
  for +mh: U32
  for +mb: U32
  for +first: B.Bytes
  for +hl: List<&2, B.Bytes>
  for +rest: B.Bytes
  for +m: M.Method
  for +t: String
  for +ver: H1.Version
  for +hs: List<&2, H.Header>
  for +pre: List<&2, H.Header>
  for +n1: String
  for +v1: String
  for +mid: List<&2, H.Header>
  for +n2: String
  for +v2: String
  for +post: List<&2, H.Header>
  for +a: Nat
  for +b: Nat
  for es: {H1.split.go(buf, B.BNil{}, [], 0, mh, False{}) == H1.Lines{Con{first, hl}, rest} : H1.Split}
  for el: {H1.request_line(H1.split_sp.go(first, B.BNil{}, [])) == H1.Line{m, t, ver} : H1.Line}
  for ef: {H1.fields(hl, H1.FOk{[]}) == H1.FOk{hs} : H1.Fields}
  for eo: {List.reverse(&2, H.Header, hs) == List.append(&2, H.Header, pre, Con{H.Header{n1, v1}, List.append(&2, H.Header, mid, Con{H.Header{n2, v2}, post})}) : List<&2, H.Header>}
  for e1: {P.lows(n1) == "content-length" : String}
  for e2: {P.lows(n2) == "content-length" : String}
  for d1: {digits(v1) == Some{a} : Maybe<&2, Nat>}
  for d2: {digits(v2) == Some{b} : Maybe<&2, Nat>}
  for ne: {Nat.is_eq(a, b) == False{} : Bool}
  {is_bad(H1.parse(buf, mh, mb)) == True{} : Bool}

# a request with a folded header line is refused
law parse_obs_fold:
  for +buf: B.Bytes
  for +mh: U32
  for +mb: U32
  for +first: B.Bytes
  for +pre: List<&2, B.Bytes>
  for +w: U32
  for +l: B.Bytes
  for +post: List<&2, B.Bytes>
  for +rest: B.Bytes
  for +m: M.Method
  for +t: String
  for +ver: H1.Version
  for es: {H1.split.go(buf, B.BNil{}, [], 0, mh, False{}) == H1.Lines{Con{first, List.append(&2, B.Bytes, pre, Con{B.BCon{w, l}, post})}, rest} : H1.Split}
  for el: {H1.request_line(H1.split_sp.go(first, B.BNil{}, [])) == H1.Line{m, t, ver} : H1.Line}
  for e: {B.is_ws(w) == True{} : Bool}
  {is_bad(H1.parse(buf, mh, mb)) == True{} : Bool}

# Response splitting (RFC 9110 §5.5)
# ------------------

# rok reads the header block as heads builds it, reversed: a CR, LF or NUL
# appears only as the CR LF that ends a line (seen as LF, then CR)
def ok_char(lf: Bool, +x: U32) -> Bool:
  match lf:
    case True{}:
      U32.is_eq(x, 13)
    case False{}:
      Bool.or(U32.is_eq(x, 10), Bool.not(H1.unsafe.char(x)))

def ok_next(lf: Bool, +x: U32) -> Bool:
  match lf:
    case True{}:
      False{}
    case False{}:
      U32.is_eq(x, 10)

def rok(s: String, +lf: Bool) -> Bool:
  match s:
    case SNil{}:
      Bool.not(lf)
    case SCon{Chr{+x}, t}:
      Bool.and(ok_char(lf, x), rok(t, ok_next(lf, x)))

# whatever headers a handler sets, the lines written for them hold a CR,
# LF or NUL only as line ends: no header can start another, or a body
law crlf_only:
  for +hs: List<&2, H.Header>
  for +out: String
  {rok(H1.heads(hs, out), False{}) == rok(out, False{}) : Bool}

law crlf_block:
  for +hs: List<&2, H.Header>
  {rok(H1.heads(hs, ""), False{}) == True{} : Bool}

# a header with a CR, LF or NUL in its name or value is not written
law unsafe_value_dropped:
  for +n: String
  for +v: String
  for +hs: List<&2, H.Header>
  for +out: String
  for e: {H1.unsafe(v, False{}) == True{} : Bool}
  {H1.heads(Con{H.Header{n, v}, hs}, out) == H1.heads(hs, out) : String}

law unsafe_name_dropped:
  for +n: String
  for +v: String
  for +hs: List<&2, H.Header>
  for +out: String
  for e: {H1.unsafe(n, False{}) == True{} : Bool}
  {H1.heads(Con{H.Header{n, v}, hs}, out) == H1.heads(hs, out) : String}

# the framing headers are the writer's: a handler's Content-Length,
# Transfer-Encoding or Connection, in any case, is not written
law framing_dropped:
  for +n: String
  for +v: String
  for +hs: List<&2, H.Header>
  for +out: String
  for e: {H1.framing(n) == True{} : Bool}
  {H1.heads(Con{H.Header{n, v}, hs}, out) == H1.heads(hs, out) : String}

law framing_cl:
  for +n: String
  for e: {P.lows(n) == "content-length" : String}
  {H1.framing(n) == True{} : Bool}

law framing_te:
  for +n: String
  for e: {P.lows(n) == "transfer-encoding" : String}
  {H1.framing(n) == True{} : Bool}

law framing_connection:
  for +n: String
  for e: {P.lows(n) == "connection" : String}
  {H1.framing(n) == True{} : Bool}
