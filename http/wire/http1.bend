import Base
import ./bytes.bend as B
import ../core/text.bend as T
import ../core/method.bend as M
import ../core/status.bend as S
import ../core/headers.bend as H
import ../core/request.bend as Req
import ../core/response.bend as Res
import ../../utf8/utf8.bend as U

# HTTP/1.1 messages on the wire (RFC 9112): a request head parsed from
# bytes, a response written to bytes. Malformed input is rejected, not
# guessed at; the server answers each error with its status.

# why a request was refused
type Err is Data:
  BadLine{}           # bare CR or LF, or a request line that is not method SP target SP version
  BadVersion{}        # HTTP/x.y other than 1.0 and 1.1
  BadHeader{}         # a name that is not a token, a colon missing, a control char in a value
  ObsFold{}           # a header line continued on the next (§5.2)
  BadLength{}         # Content-Length not digits, or two that differ (§6.3)
  BadHost{}           # HTTP/1.1 without exactly one Host (§3.2)
  Unsupported{}       # a Transfer-Encoding other than one chunked
  HeadTooLarge{}      # past max_head_bytes
  BodyTooLarge{}      # past max_body_bytes

def status(e: Err) -> S.Status:
  match e:
    case BadVersion{}:
      S.version_not_supported()
    case Unsupported{}:
      S.not_implemented()
    case HeadTooLarge{}:
      S.header_fields_too_large()
    case BodyTooLarge{}:
      S.content_too_large()
    case _:
      S.bad_request()

# Lines
# -----

# the head, cut into lines at CRLF, up to the empty line
type Split is Data:
  Lines{lines: List<&2, B.Bytes>, rest: B.Bytes}
  SMore{}
  SBad{err: Err}

# line is the current line reversed, lines the ones before, reversed; n
# counts the bytes so far, and over is n past the limit
def split.go(buf: B.Bytes, line: B.Bytes, lines: List<&2, B.Bytes>, +n: U32, +max: U32, over: Bool) -> Split:
  match buf line lines over:
    case _ _ _ True{}:
      SBad{HeadTooLarge{}}
    case B.BCon{13, B.BCon{10, t}} B.BNil{} Nil{} False{}:
      split.go(t, B.BNil{}, [], (n + 2 : U32), max, U32.is_gt((n + 2 : U32), max))
    case B.BCon{13, B.BCon{10, t}} B.BNil{} Con{l, ls} False{}:
      Lines{List.reverse(&2, B.Bytes, Con{l, ls}), t}
    case B.BCon{13, B.BCon{10, t}} B.BCon{b, bs} ls False{}:
      split.go(t, B.BNil{}, Con{B.rev(B.BCon{b, bs}), ls}, (n + 2 : U32), max, U32.is_gt((n + 2 : U32), max))
    case B.BCon{13, B.BNil{}} _ _ False{}:
      SMore{}
    case B.BCon{13, _} _ _ False{}:
      SBad{BadLine{}}
    case B.BCon{10, _} _ _ False{}:
      SBad{BadLine{}}
    case B.BCon{b, t} l ls False{}:
      split.go(t, B.BCon{b, l}, ls, (n + 1 : U32), max, U32.is_gt((n + 1 : U32), max))
    case B.BNil{} _ _ False{}:
      SMore{}

# The request line
# ----------------

def split_sp.go(bs: B.Bytes, cur: B.Bytes, acc: List<&2, B.Bytes>) -> List<&2, B.Bytes>:
  match bs:
    case B.BNil{}:
      List.reverse(&2, B.Bytes, Con{B.rev(cur), acc})
    case B.BCon{32, t}:
      split_sp.go(t, B.BNil{}, Con{B.rev(cur), acc})
    case B.BCon{b, t}:
      split_sp.go(t, B.BCon{b, cur}, acc)

def latin1.go(bs: B.Bytes, acc: String) -> String:
  match bs:
    case B.BNil{}:
      String.reverse(acc)
    case B.BCon{b, t}:
      latin1.go(t, SCon{Chr{b}, acc})

# bytes as text, one char per byte: header text is ASCII, and any other
# byte (obs-text) is kept as the char of that value
def latin1(bs: B.Bytes) -> String:
  latin1.go(bs, "")

def bytes.char(small: Bool, +x: U32, out: B.Bytes) -> B.Bytes:
  match small:
    case True{}:
      B.BCon{x, out}
    case False{}:
      B.rev.go(B.of_list(U.encode(SCon{Chr{x}, SNil{}})), out)

def bytes.go(s: String, out: B.Bytes) -> B.Bytes:
  match s:
    case SNil{}:
      B.rev(out)
    case SCon{Chr{+x}, t}:
      bytes.go(t, bytes.char(U32.is_lt(x, 256), x, out))

# text as bytes, the inverse of latin1 for chars below 256; a larger char
# is written as UTF-8
def to_bytes(s: String) -> B.Bytes:
  bytes.go(s, B.BNil{})

def same_bytes(a: B.Bytes, b: B.Bytes, ok: Bool) -> Bool:
  match a b:
    case B.BNil{} B.BNil{}:
      ok
    case B.BCon{x, at} B.BCon{y, bt}:
      same_bytes(at, bt, Bool.and(ok, U32.is_eq(x, y)))
    case _ _:
      False{}

# HTTP/1.1, HTTP/1.0, some other HTTP/x.y, or not a version
type Version is Data:
  V11{}
  V10{}
  VOther{}
  VNone{}

# HTTP/d.d
def http_like(v: B.Bytes) -> Bool:
  match v:
    case B.BCon{72, B.BCon{84, B.BCon{84, B.BCon{80, B.BCon{47, B.BCon{+a, B.BCon{46, B.BCon{+b, B.BNil{}}}}}}}}}:
      Bool.and(B.is_digit(a), B.is_digit(b))
    case _:
      False{}

def version.go(v11: Bool, v10: Bool, like: Bool) -> Version:
  match v11 v10 like:
    case True{} _ _:
      V11{}
    case False{} True{} _:
      V10{}
    case False{} False{} True{}:
      VOther{}
    case False{} False{} False{}:
      VNone{}

def version(+v: B.Bytes) -> Version:
  version.go(same_bytes(v, to_bytes("HTTP/1.1"), True{}), same_bytes(v, to_bytes("HTTP/1.0"), True{}), http_like(v))

type Line is Data:
  Line{method: M.Method, target: String, v: Version}
  LBad{err: Err}

def line.parts(ok: Bool, m: B.Bytes, t: B.Bytes, v: Version) -> Line:
  match ok v:
    case False{} _:
      LBad{BadLine{}}
    case True{} VNone{}:
      LBad{BadLine{}}
    case True{} VOther{}:
      LBad{BadVersion{}}
    case True{} v:
      Line{M.parse(latin1(m)), latin1(t), v}

def request_line(parts: List<&2, B.Bytes>) -> Line:
  match parts:
    case Con{+m, Con{+t, Con{+v, Nil{}}}}:
      line.parts(Bool.and(B.is_token(m), Bool.and(B.nonempty(t), B.value_ok(t))), m, t, version(v))
    case _:
      LBad{BadLine{}}

# Header lines
# ------------

# a header line cut at its colon
type NV is Data:
  NV{name: B.Bytes, rest: B.Bytes}

type Field is Data:
  Field{h: H.Header}
  FBad{err: Err}

def cut_colon.go(bs: B.Bytes, name: B.Bytes) -> Maybe<&2, NV>:
  match bs:
    case B.BNil{}:
      None{}
    case B.BCon{58, t}:
      Some{NV{B.rev(name), t}}
    case B.BCon{b, t}:
      cut_colon.go(t, B.BCon{b, name})

def trim(bs: B.Bytes) -> B.Bytes:
  B.rev(B.drop_ws(B.rev(B.drop_ws(bs))))

def field.make(ok: Bool, n: B.Bytes, v: B.Bytes) -> Field:
  match ok:
    case True{}:
      Field{H.Header{latin1(n), latin1(v)}}
    case False{}:
      FBad{BadHeader{}}

def field.value(+n: B.Bytes, +v: B.Bytes) -> Field:
  field.make(Bool.and(B.is_token(n), B.value_ok(v)), n, v)

def field.pair(p: NV) -> Field:
  match p:
    case NV{n, rest}:
      field.value(n, trim(rest))

def field.of(m: Maybe<&2, NV>) -> Field:
  match m:
    case None{}:
      FBad{BadHeader{}}
    case Some{p}:
      field.pair(p)

def field.fold(folded: Bool, l: B.Bytes) -> Field:
  match folded:
    case True{}:
      FBad{ObsFold{}}
    case False{}:
      field.of(cut_colon.go(l, B.BNil{}))

# name ":" OWS value OWS; a line that starts with white space continues
# the one before (obs-fold), which a server must refuse or rewrite
def field(+l: B.Bytes) -> Field:
  field.fold(B.head_ws(l), l)


# Framing
# -------

# what the headers say about the message, gathered in one pass
type CL is Data:
  NoLen{}
  Len{n: Nat}
  LenBad{}

type Frame is Data:
  Frame{cl: CL, te: Bool, hosts: U32, close: Bool, keep: Bool}

def nat_le.pick(le: Bool, +a: Nat, +b: Nat) -> Nat:
  match le:
    case True{}:
      a
    case False{}:
      b

def cl_digits.end(ok: Bool, +n: Nat) -> Maybe<&2, Nat>:
  match ok:
    case True{}:
      Some{n}
    case False{}:
      None{}

# a Content-Length's digits, held at 2^32 - 1 once past it (any body that long is
# over the limit anyway); None unless all digits and at least one
def cl_digits.go(s: String, +acc: Nat, ok: Bool, any: Bool) -> Maybe<&2, Nat>:
  match s:
    case SNil{}:
      cl_digits.end(Bool.and(ok, any), acc)
    case SCon{Chr{+x}, t}:
      cl_digits.go(t, nat_le.pick(Nat.is_le(Nat.add(Nat.mul(10n, acc), Nat.sub(U32.to_nat(x), 48n)), 4294967295n), Nat.add(Nat.mul(10n, acc), Nat.sub(U32.to_nat(x), 48n)), 4294967295n), Bool.and(ok, B.is_digit(x)), True{})

def cl_merge.eq(same: Bool, +n: Nat) -> CL:
  match same:
    case True{}:
      Len{n}
    case False{}:
      LenBad{}

# two Content-Lengths must agree (RFC 9112 §6.3)
def cl_merge(cl: CL, m: Maybe<&2, Nat>) -> CL:
  match cl m:
    case NoLen{} Some{n}:
      Len{n}
    case Len{+a} Some{+b}:
      cl_merge.eq(Nat.is_eq(a, b), a)
    case _ _:
      LenBad{}

def lower(+b: U32) -> U32:
  Bool.pick(U32, Bool.and(U32.is_ge(b, 65), U32.is_le(b, 90)), (b + 32 : U32), b)

def tok.same(a: B.Bytes, b: B.Bytes, ok: Bool) -> Bool:
  match a b:
    case B.BNil{} B.BNil{}:
      ok
    case B.BCon{+x, at} B.BCon{+y, bt}:
      tok.same(at, bt, Bool.and(ok, U32.is_eq(lower(x), lower(y))))
    case _ _:
      False{}

def tok.is(a: B.Bytes, b: B.Bytes) -> Bool:
  tok.same(a, b, True{})

def tok.go(bs: B.Bytes, cur: B.Bytes, +want: B.Bytes, found: Bool) -> Bool:
  match bs:
    case B.BNil{}:
      Bool.or(found, tok.is(trim(B.rev(cur)), want))
    case B.BCon{44, t}:
      tok.go(t, B.BNil{}, want, Bool.or(found, tok.is(trim(B.rev(cur)), want)))
    case B.BCon{b, t}:
      tok.go(t, B.BCon{b, cur}, want, found)

# whether a comma list like "keep-alive, Upgrade" holds a token
def has_token(v: String, want: String) -> Bool:
  tok.go(to_bytes(v), B.BNil{}, to_bytes(want), False{})

def comma.go(s: String, found: Bool) -> Bool:
  match s:
    case SNil{}:
      found
    case SCon{Chr{+x}, t}:
      comma.go(t, Bool.or(found, U32.is_eq(x, 44)))

# whether a value is exactly one token: "chunked", not "gzip, chunked"
def is_token(+v: String, want: String) -> Bool:
  Bool.and(Bool.not(comma.go(v, False{})), has_token(v, want))

type HKind is Data:
  KLen{}
  KTe{}
  KHost{}
  KConn{}
  KOther{}

def kind.pick(hit: Bool, k: HKind, rest: HKind) -> HKind:
  match hit:
    case True{}:
      k
    case False{}:
      rest

def kind(+n: String) -> HKind:
  kind.pick(T.same_ci(n, "content-length", True{}), KLen{},
  kind.pick(T.same_ci(n, "transfer-encoding", True{}), KTe{},
  kind.pick(T.same_ci(n, "host", True{}), KHost{},
  kind.pick(T.same_ci(n, "connection", True{}), KConn{}, KOther{}))))

def frame.step(k: HKind, fr: Frame, +v: String) -> Frame:
  match k fr:
    case KLen{} Frame{cl, te, h, c, kp}:
      Frame{cl_merge(cl, cl_digits.go(v, 0n, True{}, False{})), te, h, c, kp}
    case KTe{} Frame{cl, _, h, c, kp}:
      Frame{cl, True{}, h, c, kp}
    case KHost{} Frame{cl, te, +h, c, kp}:
      Frame{cl, te, (h + 1 : U32), c, kp}
    case KConn{} Frame{cl, te, h, c, kp}:
      Frame{cl, te, h, Bool.or(c, has_token(v, "close")), Bool.or(kp, has_token(v, "keep-alive"))}
    case KOther{} f:
      f

type Scanned is Data:
  Scanned{hs: List<&2, H.Header>, fr: Frame}

def scan(hs: List<&2, H.Header>, fr: Frame, acc: List<&2, H.Header>) -> Scanned:
  match hs:
    case Nil{}:
      Scanned{List.reverse(&2, H.Header, acc), fr}
    case Con{H.Header{+n, +v}, t}:
      scan(t, frame.step(kind(n), fr, v), Con{H.Header{n, v}, acc})

# Requests
# --------

type Fields is Data:
  FOk{hs: List<&2, H.Header>}
  FErr{err: Err}

def fields.add(acc: Fields, f: Field) -> Fields:
  match acc f:
    case FOk{hs} Field{h}:
      FOk{Con{h, hs}}
    case FOk{_} FBad{e}:
      FErr{e}
    case bad _:
      bad

def fields(ls: List<&2, B.Bytes>, acc: Fields) -> Fields:
  match ls:
    case Nil{}:
      acc
    case Con{l, t}:
      fields(t, fields.add(acc, field(l)))

type Took is Data:
  Took{body: B.Bytes, rest: B.Bytes}
  Short{}

def take(bs: B.Bytes, n: Nat, acc: B.Bytes) -> Took:
  match bs n:
    case rest 0n:
      Took{B.rev(acc), rest}
    case B.BCon{b, t} 1n+p:
      take(t, p, B.BCon{b, acc})
    case B.BNil{} 1n+_:
      Short{}

# Chunked bodies (RFC 9112 §7.1)
# --------------

# where the decoder is: in a chunk's size (n so far, whether a digit came),
# its extension, the LF after the size line, a chunk's data (left bytes, at
# least 1), the CR LF after it, or the trailer lines (fresh: at a line's
# start, where an empty line ends the body)
type CM is Data:
  CSize{n: Nat, any: Bool}
  CExt{n: Nat}
  CSizeLF{n: Nat}
  CData{left: Nat}
  CDataCR{}
  CDataLF{}
  CTrail{fresh: Bool}
  CTrailLF{fresh: Bool}

# the decoder after a byte: acc is the body so far, reversed, and total its
# length; budget counts the framing bytes (sizes, extensions, CR LFs,
# trailers) still allowed
type CS is Data:
  CS{m: CM, acc: B.Bytes, total: Nat, budget: Nat}
  CEnd{acc: B.Bytes}
  CErr{err: Err}

type Chunked is Data:
  CDone{body: B.Bytes, rest: B.Bytes}
  CMore{}
  CBad{err: Err}

# a byte, as a size line reads it
type Cls is Data:
  KCR{}
  KLF{}
  KSemi{}
  KHex{v: U32}
  KElse{}

def hex.x(+b: U32) -> U32:
  Bool.pick(U32, B.is_digit(b), (b - 48 : U32),
    Bool.pick(U32, Bool.and(U32.is_ge(b, 97), U32.is_le(b, 102)), (b - 87 : U32),
      Bool.pick(U32, Bool.and(U32.is_ge(b, 65), U32.is_le(b, 70)), (b - 55 : U32), 16)))

def cls.hex(+v: U32) -> Cls:
  Bool.pick(Cls, U32.is_lt(v, 16), KHex{v}, KElse{})

def cls(+b: U32) -> Cls:
  Bool.pick(Cls, U32.is_eq(b, 13), KCR{},
    Bool.pick(Cls, U32.is_eq(b, 10), KLF{},
      Bool.pick(Cls, U32.is_eq(b, 59), KSemi{}, cls.hex(hex.x(b)))))

def c.bad() -> CS:
  CErr{BadLength{}}

def c.digit(over: Bool, +n: Nat, acc: B.Bytes, +total: Nat, +budget: Nat) -> CS:
  match over:
    case True{}:
      CErr{BodyTooLarge{}}
    case False{}:
      CS{CSize{n, True{}}, acc, total, budget}

def c.grow(+n: Nat, +v: U32) -> Nat:
  Nat.add(Nat.mul(16n, n), U32.to_nat(v))

# hex digits, then CR, or ; for an extension: no white space, no sign
def c.size(k: Cls, any: Bool, +n: Nat, acc: B.Bytes, +total: Nat, +budget: Nat, +max: Nat) -> CS:
  match k any:
    case KHex{+v} _:
      c.digit(Bool.not(Nat.is_le(c.grow(n, v), max)), c.grow(n, v), acc, total, budget)
    case KCR{} True{}:
      CS{CSizeLF{n}, acc, total, budget}
    case KSemi{} True{}:
      CS{CExt{n}, acc, total, budget}
    case _ _:
      c.bad()

# an extension runs to the CR; it is read and dropped
def c.ext(k: Cls, ctl: Bool, +n: Nat, acc: B.Bytes, +total: Nat, +budget: Nat) -> CS:
  match k ctl:
    case KCR{} _:
      CS{CSizeLF{n}, acc, total, budget}
    case KLF{} _:
      c.bad()
    case _ True{}:
      c.bad()
    case _ False{}:
      CS{CExt{n}, acc, total, budget}

def c.data(+left: Nat) -> CM:
  match left:
    case 0n:
      CDataCR{}
    case _:
      CData{left}

def c.start(zero: Bool, fits: Bool, +n: Nat, acc: B.Bytes, +total: Nat, +budget: Nat) -> CS:
  match zero fits:
    case True{} _:
      CS{CTrail{True{}}, acc, total, budget}
    case False{} True{}:
      CS{CData{n}, acc, Nat.add(total, n), budget}
    case False{} False{}:
      CErr{BodyTooLarge{}}

# the size line has ended: size 0 starts the trailers, any other the
# chunk's data, if the body stays within max
def c.sized(lf: Bool, +n: Nat, acc: B.Bytes, +total: Nat, +budget: Nat, +max: Nat) -> CS:
  match lf:
    case True{}:
      c.start(Nat.is_eq(n, 0n), Nat.is_le(Nat.add(total, n), max), n, acc, total, budget)
    case False{}:
      c.bad()

def c.expect(ok: Bool, m: CM, acc: B.Bytes, +total: Nat, +budget: Nat) -> CS:
  match ok:
    case True{}:
      CS{m, acc, total, budget}
    case False{}:
      c.bad()

# trailer lines are read and dropped
def c.trail(k: Cls, fresh: Bool, acc: B.Bytes, +total: Nat, +budget: Nat) -> CS:
  match k:
    case KCR{}:
      CS{CTrailLF{fresh}, acc, total, budget}
    case KLF{}:
      c.bad()
    case _:
      CS{CTrail{False{}}, acc, total, budget}

def c.trail_lf(lf: Bool, fresh: Bool, acc: B.Bytes, +total: Nat, +budget: Nat) -> CS:
  match lf fresh:
    case True{} True{}:
      CEnd{acc}
    case True{} False{}:
      CS{CTrail{True{}}, acc, total, budget}
    case False{} _:
      c.bad()

# a framing byte
def c.frame(m: CM, +b: U32, acc: B.Bytes, +total: Nat, +budget: Nat, +max: Nat) -> CS:
  match m:
    case CSize{+n, any}:
      c.size(cls(b), any, n, acc, total, budget, max)
    case CExt{+n}:
      c.ext(cls(b), B.is_ctl(b), n, acc, total, budget)
    case CSizeLF{+n}:
      c.sized(U32.is_eq(b, 10), n, acc, total, budget, max)
    case CData{left}:
      CS{CData{left}, acc, total, budget}
    case CDataCR{}:
      c.expect(U32.is_eq(b, 13), CDataLF{}, acc, total, budget)
    case CDataLF{}:
      c.expect(U32.is_eq(b, 10), CSize{0n, False{}}, acc, total, budget)
    case CTrail{fresh}:
      c.trail(cls(b), fresh, acc, total, budget)
    case CTrailLF{fresh}:
      c.trail_lf(U32.is_eq(b, 10), fresh, acc, total, budget)

# a data byte goes to the body; any other spends the budget
def c.step(m: CM, +budget: Nat, b: U32, acc: B.Bytes, +total: Nat, +max: Nat) -> CS:
  match m budget:
    case CData{1n+p} _:
      CS{c.data(p), B.BCon{b, acc}, total, budget}
    case _ 0n:
      CErr{BodyTooLarge{}}
    case other 1n+p:
      c.frame(other, b, acc, total, p, max)

# a byte at a time: the body ends at the empty line after the last chunk,
# and what follows is the next request
def chunks.go(bs: B.Bytes, st: CS, +max: Nat) -> Chunked:
  match bs st:
    case rest CEnd{acc}:
      CDone{B.rev(acc), rest}
    case _ CErr{e}:
      CBad{e}
    case B.BNil{} CS{_, _, _, _}:
      CMore{}
    case B.BCon{b, t} CS{m, acc, +total, +budget}:
      chunks.go(t, c.step(m, budget, b, acc, total, max), max)

# a chunked body of at most max bytes; its framing may take 64 KiB more
# than max, which bounds extensions, trailers and tiny chunks
def chunks(bs: B.Bytes, +max: Nat) -> Chunked:
  chunks.go(bs, CS{CSize{0n, False{}}, B.BNil{}, 0n, Nat.add(65536n, max)}, max)

# the Transfer-Encoding headers: how many, and whether one said chunked
type TE is Data:
  TE{hs: List<&2, H.Header>, count: U32, chunked: Bool}

def te.scan(hs: List<&2, H.Header>, +count: U32, chunked: Bool, acc: List<&2, H.Header>) -> TE:
  match hs:
    case Nil{}:
      TE{List.reverse(&2, H.Header, acc), count, chunked}
    case Con{H.Header{+n, +v}, t}:
      te.scan(t, Bool.pick(U32, T.same_ci(n, "transfer-encoding", True{}), (count + 1 : U32), count), Bool.or(chunked, Bool.and(T.same_ci(n, "transfer-encoding", True{}), is_token(v, "chunked"))), Con{H.Header{n, v}, acc})

# a request read off the wire: the request, whether to close the connection
# after answering it, and the bytes after it (the next request, pipelined)
type Parsed is Data:
  Parsed{req: Req.Request, close: Bool, rest: B.Bytes}
  More{}
  Bad{err: Err}

def req.body(t: Took, m: M.Method, target: String, hs: List<&2, H.Header>, close: Bool) -> Parsed:
  match t:
    case Took{body, rest}:
      Parsed{Req.Request{m, target, hs, B.to_list(body)}, close, rest}
    case Short{}:
      More{}

def req.len.fits(ok: Bool, n: Nat, rest: B.Bytes, m: M.Method, target: String, hs: List<&2, H.Header>, close: Bool) -> Parsed:
  match ok:
    case True{}:
      req.body(take(rest, n, B.BNil{}), m, target, hs, close)
    case False{}:
      Bad{BodyTooLarge{}}

def req.len(cl: CL, +max: Nat, rest: B.Bytes, m: M.Method, target: String, hs: List<&2, H.Header>, close: Bool) -> Parsed:
  match cl:
    case NoLen{}:
      Parsed{Req.Request{m, target, hs, []}, close, rest}
    case LenBad{}:
      Bad{BadLength{}}
    case Len{+n}:
      req.len.fits(Nat.is_le(n, max), n, rest, m, target, hs, close)

def hosts_ok(v: Version, +h: U32) -> Bool:
  match v:
    case V11{}:
      U32.is_eq(h, 1)
    case _:
      U32.is_le(h, 1)

def close_of(v: Version, +c: Bool, +k: Bool) -> Bool:
  match v:
    case V11{}:
      c
    case _:
      Bool.or(c, Bool.not(k))

def req.chunks(c: Chunked, m: M.Method, target: String, hs: List<&2, H.Header>, close: Bool) -> Parsed:
  match c:
    case CDone{body, rest}:
      Parsed{Req.Request{m, target, hs, B.to_list(body)}, close, rest}
    case CMore{}:
      More{}
    case CBad{e}:
      Bad{e}

def req.coded(one: Bool, hosts: Bool, close: Bool, +max: Nat, rest: B.Bytes, m: M.Method, target: String, hs: List<&2, H.Header>) -> Parsed:
  match one hosts:
    case False{} _:
      Bad{Unsupported{}}
    case True{} False{}:
      Bad{BadHost{}}
    case True{} True{}:
      req.chunks(chunks(rest, max), m, target, hs, close)

def req.te.of(t: TE, hosts: Bool, close: Bool, +max: Nat, rest: B.Bytes, m: M.Method, target: String) -> Parsed:
  match t:
    case TE{hs, +c, k}:
      req.coded(Bool.and(U32.is_eq(c, 1), k), hosts, close, max, rest, m, target, hs)

# a Transfer-Encoding: with a Content-Length too, the two could frame the
# body two ways, so it is refused (RFC 9112 §6.1); else it must be one
# header, chunked
def req.te(cl: CL, hosts: Bool, close: Bool, +max: Nat, rest: B.Bytes, m: M.Method, target: String, hs: List<&2, H.Header>) -> Parsed:
  match cl:
    case NoLen{}:
      req.te.of(te.scan(hs, 0, False{}, []), hosts, close, max, rest, m, target)
    case _:
      Bad{BadLength{}}

def req.check(te: Bool, hosts: Bool, cl: CL, close: Bool, +max: Nat, rest: B.Bytes, m: M.Method, target: String, hs: List<&2, H.Header>) -> Parsed:
  match te hosts:
    case True{} _:
      req.te(cl, hosts, close, max, rest, m, target, hs)
    case False{} False{}:
      Bad{BadHost{}}
    case False{} True{}:
      req.len(cl, max, rest, m, target, hs, close)

def req.frame(s: Scanned, m: M.Method, target: String, +v: Version, rest: B.Bytes, +max: Nat) -> Parsed:
  match s:
    case Scanned{hs, Frame{cl, te, +h, +c, +k}}:
      req.check(te, hosts_ok(v, h), cl, close_of(v, c, k), max, rest, m, target, hs)

def req.fields(f: Fields, m: M.Method, target: String, +v: Version, rest: B.Bytes, +max: Nat) -> Parsed:
  match f:
    case FErr{e}:
      Bad{e}
    case FOk{hs}:
      req.frame(scan(List.reverse(&2, H.Header, hs), Frame{NoLen{}, False{}, 0, False{}, False{}}, []), m, target, v, rest, max)

def req.line(l: Line, hl: List<&2, B.Bytes>, rest: B.Bytes, +max: Nat) -> Parsed:
  match l:
    case LBad{e}:
      Bad{e}
    case Line{m, t, +v}:
      req.fields(fields(hl, FOk{[]}), m, t, v, rest, max)

def req.lines(s: Split, +max: Nat) -> Parsed:
  match s:
    case SMore{}:
      More{}
    case SBad{e}:
      Bad{e}
    case Lines{Nil{}, _}:
      Bad{BadLine{}}
    case Lines{Con{first, hl}, rest}:
      req.line(request_line(split_sp.go(first, B.BNil{}, [])), hl, rest, max)

# a request from the bytes received so far: Parsed, More when it is not all
# here yet, or Bad with why
def parse(buf: B.Bytes, +max_head: U32, +max_body: U32) -> Parsed:
  req.lines(split.go(buf, B.BNil{}, [], 0, max_head, False{}), U32.to_nat(max_body))

# Responses
# ---------

def count(bs: B.Bytes, +n: U32) -> U32:
  match bs:
    case B.BNil{}:
      n
    case B.BCon{_, t}:
      count(t, (n + 1 : U32))

def framing(+n: String) -> Bool:
  Bool.or(T.same_ci(n, "content-length", True{}), Bool.or(T.same_ci(n, "transfer-encoding", True{}), T.same_ci(n, "connection", True{})))

def unsafe.char(+x: U32) -> Bool:
  Bool.or(U32.is_eq(x, 0), Bool.or(U32.is_eq(x, 10), U32.is_eq(x, 13)))

# a CR, LF or NUL: in a header a handler set, it would split the response
# (RFC 9110 §5.5)
def unsafe(s: String, bad: Bool) -> Bool:
  match s:
    case SNil{}:
      bad
    case SCon{Chr{+x}, t}:
      unsafe(t, Bool.or(bad, unsafe.char(x)))

def heads.keep(drop: Bool, n: String, v: String, out: String) -> String:
  match drop:
    case True{}:
      out
    case False{}:
      String.reverse.go("\r\n", String.reverse.go(v, String.reverse.go(": ", String.reverse.go(n, out))))

# the header lines, reversed onto out; the framing ones are the writer's,
# and one with a CR, LF or NUL is dropped
def heads(hs: List<&2, H.Header>, out: String) -> String:
  match hs:
    case Nil{}:
      out
    case Con{H.Header{+n, +v}, t}:
      heads(t, heads.keep(Bool.or(framing(n), Bool.or(unsafe(n, False{}), unsafe(v, False{}))), n, v, out))

# an HTTP/1.0 client keeps the connection only when told (RFC 9112 §9.3)
def closing(close: Bool) -> String:
  match close:
    case True{}:
      "connection: close\r\n"
    case False{}:
      "connection: keep-alive\r\n"

# to_bytes for the writer alone: the compiler decides once per def whether
# it takes its argument or only reads it, and has_token reads a header value
# it keeps, while the writer hands over a String it is done with; one def
# for both would share Strings
def head_bytes(s: String) -> B.Bytes:
  bytes.go(s, B.BNil{})

def write.go(+c: U32, hs: List<&2, H.Header>, +body: B.Bytes, close: Bool) -> B.Bytes:
  B.app(head_bytes(String.reverse(String.reverse.go("\r\n", String.reverse.go(closing(close), String.reverse.go("\r\n", String.reverse.go(U32.show(count(body, 0)), String.reverse.go("content-length: ", heads(hs, String.reverse.go("\r\n", String.reverse.go(S.reason(S.Status{c}), String.reverse.go(" ", String.reverse.go(U32.show(c), String.reverse.go("HTTP/1.1 ", ""))))))))))))), body)

# a response on the wire: status line, headers, Content-Length, and
# Connection: close when the server will close after it, else keep-alive
def write(r: Res.Response, close: Bool) -> B.Bytes:
  match r:
    case Res.Response{S.Status{+c}, hs, list}:
      write.go(c, hs, B.of_list(list), close)

# Streamed responses
# ------------------

def hex.digit(+d: U32) -> Char:
  Chr{Bool.pick(U32, U32.is_lt(d, 10), (d + 48 : U32), (d + 87 : U32))}

def hex.go(n: Nat, +x: U32, acc: String) -> String:
  match n:
    case 0n:
      acc
    case 1n+p:
      hex.go(p, (x >> 4n : U32), SCon{hex.digit((x .&. 15 : U32)), acc})

def hex.trim(s: String) -> String:
  match s:
    case SCon{Chr{48}, SCon{c, t}}:
      hex.trim(SCon{c, t})
    case other:
      other

# n in hex, without leading zeros
def hex(+n: U32) -> String:
  hex.trim(hex.go(8n, n, ""))

def chunk.go(+bs: B.Bytes) -> B.Bytes:
  B.app(head_bytes(hex(count(bs, 0)) ++ "\r\n"), B.app(bs, head_bytes("\r\n")))

# bytes as one chunk of a chunked body (RFC 9112 §7.1); an empty chunk
# would end the body, so it is left out
def chunk(bs: B.Bytes) -> B.Bytes:
  match bs:
    case B.BNil{}:
      B.BNil{}
    case B.BCon{b, t}:
      chunk.go(B.BCon{b, t})

# the empty chunk that ends a chunked body, with no trailers
def last_chunk() -> B.Bytes:
  head_bytes("0\r\n\r\n")

# a streamed response's head: its body follows in chunks. As in write, the
# handler's framing headers and unsafe ones are dropped
def write_head(+c: U32, hs: List<&2, H.Header>, close: Bool) -> B.Bytes:
  head_bytes(String.reverse(String.reverse.go("\r\n", String.reverse.go(closing(close), String.reverse.go("transfer-encoding: chunked\r\n", heads(hs, String.reverse.go("\r\n", String.reverse.go(S.reason(S.Status{c}), String.reverse.go(" ", String.reverse.go(U32.show(c), String.reverse.go("HTTP/1.1 ", "")))))))))))

# a response read off the wire (for clients, and to test write)
type RParsed is Data:
  RParsed{code: U32, hs: List<&2, H.Header>, body: B.Bytes, rest: B.Bytes}
  RMore{}
  RBad{err: Err}

def digit3.go(ok: Bool, +n: U32) -> Maybe<&2, U32>:
  match ok:
    case True{}:
      Some{n}
    case False{}:
      None{}

def digit3(+a: U32, +b: U32, +c: U32) -> Maybe<&2, U32>:
  digit3.go(Bool.and(B.is_digit(a), Bool.and(B.is_digit(b), B.is_digit(c))), (((a - 48 : U32) * 100 : U32) + (((b - 48 : U32) * 10 : U32) + (c - 48 : U32) : U32) : U32))

def status_line.ok(ok: Bool, m: Maybe<&2, U32>) -> Maybe<&2, U32>:
  match ok:
    case True{}:
      m
    case False{}:
      None{}

# HTTP/d.d SP ddd SP reason
def status_line(bs: B.Bytes) -> Maybe<&2, U32>:
  match bs:
    case B.BCon{72, B.BCon{84, B.BCon{84, B.BCon{80, B.BCon{47, B.BCon{_, B.BCon{46, B.BCon{_, B.BCon{32, B.BCon{+a, B.BCon{+b, B.BCon{+c, B.BCon{32, reason}}}}}}}}}}}}}:
      status_line.ok(B.value_ok(reason), digit3(a, b, c))
    case _:
      None{}

def res.body(t: Took, +code: U32, hs: List<&2, H.Header>) -> RParsed:
  match t:
    case Took{body, rest}:
      RParsed{code, hs, body, rest}
    case Short{}:
      RMore{}

def res.frame(s: Scanned, +code: U32, rest: B.Bytes) -> RParsed:
  match s:
    case Scanned{hs, Frame{Len{n}, False{}, _, _, _}}:
      res.body(take(rest, n, B.BNil{}), code, hs)
    case Scanned{hs, Frame{NoLen{}, False{}, _, _, _}}:
      RParsed{code, hs, rest, B.BNil{}}
    case Scanned{_, Frame{_, True{}, _, _, _}}:
      RBad{Unsupported{}}
    case Scanned{_, _}:
      RBad{BadLength{}}

def res.fields(f: Fields, +code: U32, rest: B.Bytes) -> RParsed:
  match f:
    case FErr{e}:
      RBad{e}
    case FOk{hs}:
      res.frame(scan(List.reverse(&2, H.Header, hs), Frame{NoLen{}, False{}, 0, False{}, False{}}, []), code, rest)

def res.line(m: Maybe<&2, U32>, hl: List<&2, B.Bytes>, rest: B.Bytes) -> RParsed:
  match m:
    case None{}:
      RBad{BadLine{}}
    case Some{+code}:
      res.fields(fields(hl, FOk{[]}), code, rest)

def res.lines(s: Split) -> RParsed:
  match s:
    case SMore{}:
      RMore{}
    case SBad{e}:
      RBad{e}
    case Lines{Nil{}, _}:
      RBad{BadLine{}}
    case Lines{Con{first, hl}, rest}:
      res.line(status_line(first), hl, rest)

# a response from bytes; with no Content-Length the body runs to the end
def parse_response(buf: B.Bytes, +max_head: U32) -> RParsed:
  res.lines(split.go(buf, B.BNil{}, [], 0, max_head, False{}))

# Responses, as a client reads them
# ---------------------------------

def rres.body(t: Took, +code: U32, hs: List<&2, H.Header>) -> RParsed:
  match t:
    case Took{body, rest}:
      RParsed{code, hs, body, rest}
    case Short{}:
      RMore{}

def rres.len(ok: Bool, +n: Nat, +code: U32, hs: List<&2, H.Header>, rest: B.Bytes) -> RParsed:
  match ok:
    case True{}:
      rres.body(take(rest, n, B.BNil{}), code, hs)
    case False{}:
      RBad{BodyTooLarge{}}

def rres.chunks(c: Chunked, +code: U32, hs: List<&2, H.Header>) -> RParsed:
  match c:
    case CDone{body, rest}:
      RParsed{code, hs, body, rest}
    case CMore{}:
      RMore{}
    case CBad{e}:
      RBad{e}

def rres.coded(one: Bool, +code: U32, hs: List<&2, H.Header>, rest: B.Bytes, +max: Nat) -> RParsed:
  match one:
    case True{}:
      rres.chunks(chunks(rest, max), code, hs)
    case False{}:
      RBad{Unsupported{}}

def rres.te(t: TE, +code: U32, rest: B.Bytes, +max: Nat) -> RParsed:
  match t:
    case TE{hs, +c, k}:
      rres.coded(Bool.and(U32.is_eq(c, 1), k), code, hs, rest, max)

# a body with no Content-Length runs to the close
def rres.eof(eof: Bool, +code: U32, hs: List<&2, H.Header>, rest: B.Bytes) -> RParsed:
  match eof:
    case True{}:
      RParsed{code, hs, rest, B.BNil{}}
    case False{}:
      RMore{}

def rres.frame(s: Scanned, none: Bool, +code: U32, rest: B.Bytes, +max: Nat, eof: Bool) -> RParsed:
  match s none:
    case Scanned{hs, _} True{}:
      RParsed{code, hs, B.BNil{}, rest}
    case Scanned{hs, Frame{_, True{}, _, _, _}} False{}:
      rres.te(te.scan(hs, 0, False{}, []), code, rest, max)
    case Scanned{hs, Frame{Len{+n}, False{}, _, _, _}} False{}:
      rres.len(Nat.is_le(n, max), n, code, hs, rest)
    case Scanned{hs, Frame{NoLen{}, False{}, _, _, _}} False{}:
      rres.eof(eof, code, hs, rest)
    case Scanned{_, Frame{LenBad{}, False{}, _, _, _}} False{}:
      RBad{BadLength{}}

# 1xx, 204 and 304 have no body, nor has the answer to a HEAD (RFC 9112 §6.3)
def no_body(+head: Bool, +code: U32) -> Bool:
  Bool.or(head, Bool.or(Bool.and(U32.is_ge(code, 100), U32.is_lt(code, 200)), Bool.or(U32.is_eq(code, 204), U32.is_eq(code, 304))))

def rres.fields(f: Fields, +code: U32, rest: B.Bytes, +max: Nat, eof: Bool, +head: Bool) -> RParsed:
  match f:
    case FErr{e}:
      RBad{e}
    case FOk{hs}:
      rres.frame(scan(List.reverse(&2, H.Header, hs), Frame{NoLen{}, False{}, 0, False{}, False{}}, []), no_body(head, code), code, rest, max, eof)

def rres.line(m: Maybe<&2, U32>, hl: List<&2, B.Bytes>, rest: B.Bytes, +max: Nat, eof: Bool, +head: Bool) -> RParsed:
  match m:
    case None{}:
      RBad{BadLine{}}
    case Some{+code}:
      rres.fields(fields(hl, FOk{[]}), code, rest, max, eof, head)

def rres.lines(s: Split, +max: Nat, eof: Bool, +head: Bool) -> RParsed:
  match s:
    case SMore{}:
      RMore{}
    case SBad{e}:
      RBad{e}
    case Lines{Nil{}, _}:
      RBad{BadLine{}}
    case Lines{Con{first, hl}, rest}:
      rres.line(status_line(first), hl, rest, max, eof, head)

# a response as a client reads it: framed by Content-Length, chunked, or
# (with neither) by the close, once eof says the server has closed; no
# body after a HEAD or for 1xx, 204 and 304; a body past max_body is
# refused. A 1xx is handed back as it is: the client reads on after it
def read_response(buf: B.Bytes, +max_head: U32, +max_body: U32, eof: Bool, +head: Bool) -> RParsed:
  rres.lines(split.go(buf, B.BNil{}, [], 0, max_head, False{}), U32.to_nat(max_body), eof, head)

# Lengths, in decimal, from a digit counter: each digit is a constructor,
# so a law sees it is a digit, where U32.show is opaque to the checker
type Dig is Data:
  D0{}
  D1{}
  D2{}
  D3{}
  D4{}
  D5{}
  D6{}
  D7{}
  D8{}
  D9{}

# a count, least significant digit first; DNil is 0
type Dec is Data:
  DNil{}
  DCon{d: Dig, t: Dec}

def dec.inc(d: Dec) -> Dec:
  match d:
    case DNil{}:
      DCon{D1{}, DNil{}}
    case DCon{D0{}, t}:
      DCon{D1{}, t}
    case DCon{D1{}, t}:
      DCon{D2{}, t}
    case DCon{D2{}, t}:
      DCon{D3{}, t}
    case DCon{D3{}, t}:
      DCon{D4{}, t}
    case DCon{D4{}, t}:
      DCon{D5{}, t}
    case DCon{D5{}, t}:
      DCon{D6{}, t}
    case DCon{D6{}, t}:
      DCon{D7{}, t}
    case DCon{D7{}, t}:
      DCon{D8{}, t}
    case DCon{D8{}, t}:
      DCon{D9{}, t}
    case DCon{D9{}, t}:
      DCon{D0{}, dec.inc(t)}

def dig.char(x: Dig) -> Char:
  match x:
    case D0{}:
      '0'
    case D1{}:
      '1'
    case D2{}:
      '2'
    case D3{}:
      '3'
    case D4{}:
      '4'
    case D5{}:
      '5'
    case D6{}:
      '6'
    case D7{}:
      '7'
    case D8{}:
      '8'
    case D9{}:
      '9'

# the digits, most significant first, before out
def dec.show.go(d: Dec, out: String) -> String:
  match d:
    case DNil{}:
      out
    case DCon{x, t}:
      dec.show.go(t, SCon{dig.char(x), out})

def dec.show(d: Dec) -> String:
  match d:
    case DNil{}:
      "0"
    case DCon{x, t}:
      dec.show.go(DCon{x, t}, "")

# the bytes of bs, counted onto d
def dec.count(bs: B.Bytes, d: Dec) -> Dec:
  match bs:
    case B.BNil{}:
      d
    case B.BCon{_, t}:
      dec.count(t, dec.inc(d))

def request.len(sized: Bool, n: Dec, out: String) -> String:
  match sized:
    case True{}:
      String.reverse.go("\r\n", String.reverse.go(dec.show(n), String.reverse.go("content-length: ", out)))
    case False{}:
      out

# Response heads, for a client that reads the body itself
# ---------------------------------------------------------

# how a response's body is framed: n bytes, chunked, to the close, or none
type Framing is Data:
  FLen{n: Nat}
  FChunked{}
  FClose{}
  FNone{}

# a response head: status, headers, framing, whether the connection may
# carry another request after this response, and the bytes after the head
type Head is Data:
  Head{code: U32, hs: List<&2, H.Header>, framing: Framing, reuse: Bool, rest: B.Bytes}
  HMore{}
  HBad{err: Err}

# HTTP/1.1 keeps the connection unless told; HTTP/1.0 closes it
def is_v11(bs: B.Bytes) -> Bool:
  match bs:
    case B.BCon{72, B.BCon{84, B.BCon{84, B.BCon{80, B.BCon{47, B.BCon{49, B.BCon{46, B.BCon{49, _}}}}}}}}:
      True{}
    case _:
      False{}

def head.coded(one: Bool, +code: U32, hs: List<&2, H.Header>, +reuse: Bool, rest: B.Bytes) -> Head:
  match one:
    case True{}:
      Head{code, hs, FChunked{}, reuse, rest}
    case False{}:
      HBad{Unsupported{}}

def head.te(t: TE, +code: U32, +reuse: Bool, rest: B.Bytes) -> Head:
  match t:
    case TE{hs, +c, k}:
      head.coded(Bool.and(U32.is_eq(c, 1), k), code, hs, reuse, rest)

def head.len(ok: Bool, +n: Nat, +code: U32, hs: List<&2, H.Header>, +reuse: Bool, rest: B.Bytes) -> Head:
  match ok:
    case True{}:
      Head{code, hs, FLen{n}, reuse, rest}
    case False{}:
      HBad{BodyTooLarge{}}

def head.frame(s: Scanned, none: Bool, +code: U32, +v11: Bool, rest: B.Bytes, +max: Nat) -> Head:
  match s none:
    case Scanned{hs, Frame{_, _, _, +c, _}} True{}:
      Head{code, hs, FNone{}, Bool.and(v11, Bool.not(c)), rest}
    case Scanned{hs, Frame{_, True{}, _, +c, _}} False{}:
      head.te(te.scan(hs, 0, False{}, []), code, Bool.and(v11, Bool.not(c)), rest)
    case Scanned{hs, Frame{Len{+n}, False{}, _, +c, _}} False{}:
      head.len(Nat.is_le(n, max), n, code, hs, Bool.and(v11, Bool.not(c)), rest)
    case Scanned{hs, Frame{NoLen{}, False{}, _, _, _}} False{}:
      Head{code, hs, FClose{}, False{}, rest}
    case Scanned{_, Frame{LenBad{}, False{}, _, _, _}} False{}:
      HBad{BadLength{}}

def head.fields(f: Fields, +code: U32, +v11: Bool, rest: B.Bytes, +max: Nat, +head: Bool) -> Head:
  match f:
    case FErr{e}:
      HBad{e}
    case FOk{hs}:
      head.frame(scan(List.reverse(&2, H.Header, hs), Frame{NoLen{}, False{}, 0, False{}, False{}}, []), no_body(head, code), code, v11, rest, max)

def head.line(m: Maybe<&2, U32>, +v11: Bool, hl: List<&2, B.Bytes>, rest: B.Bytes, +max: Nat, +head: Bool) -> Head:
  match m:
    case None{}:
      HBad{BadLine{}}
    case Some{+code}:
      head.fields(fields(hl, FOk{[]}), code, v11, rest, max, head)

def head.lines(s: Split, +max: Nat, +head: Bool) -> Head:
  match s:
    case SMore{}:
      HMore{}
    case SBad{e}:
      HBad{e}
    case Lines{Nil{}, _}:
      HBad{BadLine{}}
    case Lines{Con{+first, hl}, rest}:
      head.line(status_line(first), is_v11(first), hl, rest, max, head)

# a response's head, from the bytes so far; a Content-Length past max_body
# is refused. head says the request was a HEAD, so there is no body
def read_head(buf: B.Bytes, +max_head: U32, +max_body: Nat, +head: Bool) -> Head:
  head.lines(split.go(buf, B.BNil{}, [], 0, max_head, False{}), max_body, head)

# a chunked body, fed as it comes
type Fed is Data:
  Fed{st: CS}
  FedEnd{data: B.Bytes, rest: B.Bytes}
  FedBad{err: Err}

# where chunks.feed starts, for a body of at most max bytes
def chunks.start(+max: Nat) -> CS:
  CS{CSize{0n, False{}}, B.BNil{}, 0n, Nat.add(65536n, max)}

# the bytes of one read through the decoder: Fed with its state, whose acc
# holds this read's data, reversed, or FedEnd with the last data and the
# bytes after the body
def chunks.feed(bs: B.Bytes, st: CS, +max: Nat) -> Fed:
  match bs st:
    case rest CEnd{acc}:
      FedEnd{B.rev(acc), rest}
    case _ CErr{e}:
      FedBad{e}
    case B.BNil{} CS{m, acc, total, budget}:
      Fed{CS{m, acc, total, budget}}
    case B.BCon{b, t} CS{m, acc, +total, +budget}:
      chunks.feed(t, c.step(m, budget, b, acc, total, max), max)

# a request on the wire, as a client writes it: host first, the caller's
# headers (framing and unsafe ones dropped), Content-Length when there is
# a body or the method expects one, and connection: close unless the
# connection is to be kept
def request.close(close: Bool, out: String) -> String:
  match close:
    case True{}:
      String.reverse.go("connection: close\r\n", out)
    case False{}:
      out

def is_token.s.go(s: String, ok: Bool) -> Bool:
  match s:
    case SNil{}:
      ok
    case SCon{Chr{+x}, t}:
      is_token.s.go(t, Bool.and(ok, B.is_tchar(x)))

# whether a String is a token: one char or more, each a tchar (RFC 9110
# §5.6.2), as a method name must be
def is_token.s(s: String) -> Bool:
  match s:
    case SNil{}:
      False{}
    case SCon{Chr{+x}, t}:
      is_token.s.go(t, B.is_tchar(x))

# the request line and the host line, reversed
def request.start(m: String, target: String, host: String) -> String:
  String.reverse.go("\r\n", String.reverse.go(host, String.reverse.go("host: ", String.reverse.go(" HTTP/1.1\r\n", String.reverse.go(target, String.reverse.go(" ", String.reverse.go(m, "")))))))

# a request's head, reversed: the start, the caller's headers, the length
# when sized, connection: close when close, and the empty line
def request.head(m: String, target: String, host: String, hs: List<&2, H.Header>, n: Dec, sized: Bool, close: Bool) -> String:
  String.reverse.go("\r\n", request.close(close, request.len(sized, n, heads(hs, request.start(m, target, host)))))

def write_request(m: String, target: String, host: String, hs: List<&2, H.Header>, +body: B.Bytes, sized: Bool, close: Bool) -> B.Bytes:
  B.app(head_bytes(String.reverse(request.head(m, target, host, hs, dec.count(body, DNil{}), Bool.or(sized, B.nonempty(body)), close))), body)