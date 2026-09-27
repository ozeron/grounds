import Base
import ./bytes.bend as B
import ../http/text.bend as T
import ../http/method.bend as M
import ../http/status.bend as S
import ../http/headers.bend as H
import ../http/request.bend as Req
import ../http/response.bend as Res
import ../utf8/utf8.bend as U

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
  Unsupported{}       # Transfer-Encoding: chunked bodies are not read yet
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

def req.check(te: Bool, hosts: Bool, cl: CL, close: Bool, +max: Nat, rest: B.Bytes, m: M.Method, target: String, hs: List<&2, H.Header>) -> Parsed:
  match te hosts:
    case True{} _:
      Bad{Unsupported{}}
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
