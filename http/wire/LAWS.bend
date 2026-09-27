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

def has_len(cl: H1.CL) -> Bool:
  match cl:
    case H1.NoLen{}:
      False{}
    case _:
      True{}

# a Content-Length anywhere among the headers sets the length, or makes it
# bad; no later header clears it
law cl_seen:
  for +pre: List<&2, H.Header>
  for +n: String
  for +v: String
  for +post: List<&2, H.Header>
  for +fr: H1.Frame
  for +acc: List<&2, H.Header>
  for e: {P.lows(n) == "content-length" : String}
  {has_len(cl_of(H1.scan(List.append(&2, H.Header, pre, Con{H.Header{n, v}, post}), fr, acc))) == True{} : Bool}

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

# what a request with a Transfer-Encoding comes to: req.te's answer, which
# never reads a body by Content-Length
def by_te(s: H1.Scanned, m: M.Method, t: String, +ver: H1.Version, rest: B.Bytes, +max: Nat) -> H1.Parsed:
  match s:
    case H1.Scanned{hs, H1.Frame{cl, _, +h, +c, +k}}:
      H1.req.te(cl, H1.hosts_ok(ver, h), H1.close_of(ver, c, k), max, rest, m, t, hs)

def Frame0() -> H1.Frame:
  H1.Frame{H1.NoLen{}, False{}, 0, False{}, False{}}

# a request with a Transfer-Encoding is framed by it alone
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
  {H1.parse(buf, mh, mb) == by_te(H1.scan(List.append(&2, H.Header, pre, Con{H.Header{n, v}, post}), Frame0(), []), m, t, ver, rest, U32.to_nat(mb)) : H1.Parsed}

# a request with both a Transfer-Encoding and a Content-Length, anywhere and
# in either order, is refused: the two could frame its body two ways
law parse_te_cl:
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
  for +pre2: List<&2, H.Header>
  for +n2: String
  for +v2: String
  for +post2: List<&2, H.Header>
  for es: {H1.split.go(buf, B.BNil{}, [], 0, mh, False{}) == H1.Lines{Con{first, hl}, rest} : H1.Split}
  for el: {H1.request_line(H1.split_sp.go(first, B.BNil{}, [])) == H1.Line{m, t, ver} : H1.Line}
  for ef: {H1.fields(hl, H1.FOk{[]}) == H1.FOk{hs} : H1.Fields}
  for +eo: {List.reverse(&2, H.Header, hs) == List.append(&2, H.Header, pre, Con{H.Header{n, v}, post}) : List<&2, H.Header>}
  for eo2: {List.reverse(&2, H.Header, hs) == List.append(&2, H.Header, pre2, Con{H.Header{n2, v2}, post2}) : List<&2, H.Header>}
  for en: {P.lows(n) == "transfer-encoding" : String}
  for en2: {P.lows(n2) == "content-length" : String}
  {is_bad(H1.parse(buf, mh, mb)) == True{} : Bool}

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

# Request injection (RFC 9112 §2.1, §3)
# -----------------

# hok reads a request head as request.head builds it, reversed: lines of
# at least one char, no CR, LF or NUL among them, each ended by CR LF.
# State 0 wants a line's end (its LF, as the head is reversed), 1 its CR,
# 2 the line's first char, 3 more chars, a line's end, or the start; 4
# refuses
def hstep(+st: U32, +x: U32) -> U32:
  match st:
    case 0:
      Bool.pick(U32, U32.is_eq(x, 10), 1, 4)
    case 1:
      Bool.pick(U32, U32.is_eq(x, 13), 2, 4)
    case 2:
      Bool.pick(U32, H1.unsafe.char(x), 4, 3)
    case 3:
      Bool.pick(U32, U32.is_eq(x, 10), 1, Bool.pick(U32, H1.unsafe.char(x), 4, 3))
    case _:
      4

def hok(s: String, +st: U32) -> Bool:
  match s:
    case SNil{}:
      U32.is_eq(st, 3)
    case SCon{Chr{+x}, t}:
      hok(t, hstep(st, x))

# a head: the empty line that ends it, then its lines
def hdr(s: String) -> Bool:
  match s:
    case SCon{Chr{10}, SCon{Chr{13}, t}}:
      hok(t, 0)
    case _:
      False{}

# the head a client writes holds one empty line, at its end, and a CR or
# LF only where a line ends: whatever the headers, and whatever method,
# target and host without CR, LF or NUL, no header can start another and
# no request can start inside this one
law request_head:
  for +m: String
  for +target: String
  for +host: String
  for +hs: List<&2, H.Header>
  for +n: H1.Dec
  for +sized: Bool
  for +close: Bool
  for +em: {H1.unsafe(m, False{}) == False{} : Bool}
  for +et: {H1.unsafe(target, False{}) == False{} : Bool}
  for +eh: {H1.unsafe(host, False{}) == False{} : Bool}
  {hdr(H1.request.head(m, target, host, hs, n, sized, close)) == True{} : Bool}

# Chunked bodies read back (RFC 9112 §7.1)
# ------------------------

def blen(bs: B.Bytes) -> Nat:
  match bs:
    case B.BNil{}:
      0n
    case B.BCon{_, t}:
      1n+blen(t)

# what a streamed body puts on the wire: each piece as a chunk, then the
# last chunk, then whatever follows
def stream(ps: List<&2, B.Bytes>, rest: B.Bytes) -> B.Bytes:
  match ps:
    case Nil{}:
      B.cat(H1.last_chunk(), rest)
    case Con{p, t}:
      B.cat(H1.chunk(p), stream(t, rest))

def joined(ps: List<&2, B.Bytes>) -> B.Bytes:
  match ps:
    case Nil{}:
      B.BNil{}
    case Con{p, t}:
      B.cat(p, joined(t))

def total(ps: List<&2, B.Bytes>) -> Nat:
  match ps:
    case Nil{}:
      0n
    case Con{p, t}:
      Nat.add(blen(p), total(t))

# a hex digit's value, and a count's
def dv(x: H1.Hx) -> Nat:
  match x:
    case H1.X0{}:
      0n
    case H1.X1{}:
      1n
    case H1.X2{}:
      2n
    case H1.X3{}:
      3n
    case H1.X4{}:
      4n
    case H1.X5{}:
      5n
    case H1.X6{}:
      6n
    case H1.X7{}:
      7n
    case H1.X8{}:
      8n
    case H1.X9{}:
      9n
    case H1.XA{}:
      10n
    case H1.XB{}:
      11n
    case H1.XC{}:
      12n
    case H1.XD{}:
      13n
    case H1.XE{}:
      14n
    case H1.XF{}:
      15n

def hv(h: H1.Hc) -> Nat:
  match h:
    case H1.HNil{}:
      0n
    case H1.HCon{x, t}:
      Nat.add(Nat.mul(16n, hv(t)), dv(x))

def hlen(h: H1.Hc) -> Nat:
  match h:
    case H1.HNil{}:
      0n
    case H1.HCon{_, t}:
      1n+hlen(t)

# the framing bytes the decoder counts against its budget: a chunk's size
# digits and two CR LFs; five for the last chunk and the empty trailer
def piece(p: B.Bytes, +more: Nat) -> Nat:
  match p:
    case B.BNil{}:
      more
    case B.BCon{b, t}:
      Nat.add(hlen(H1.hc.count(B.BCon{b, t}, H1.HNil{})), Nat.add(4n, more))

def frames(ps: List<&2, B.Bytes>, +extra: Nat) -> Nat:
  match ps:
    case Nil{}:
      Nat.add(5n, extra)
    case Con{p, t}:
      piece(p, frames(t, extra))

# pieces sent as chunks read back as the same bytes, in order, and the
# bytes after the body are left for what follows: for any pieces within
# max, and a framing budget at least what they take
law chunked_reads_back:
  for +ps: List<&2, B.Bytes>
  for +rest: B.Bytes
  for +max: Nat
  for +extra: Nat
  for e: {Nat.is_le(total(ps), max) == True{} : Bool}
  {H1.chunks.go(stream(ps, rest), H1.CS{H1.CSize{0n, False{}}, B.BNil{}, 0n, frames(ps, extra)}, max) == H1.CDone{joined(ps), rest} : H1.Chunked}
