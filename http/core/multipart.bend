import Base
import ./content_type.bend as Ct
import ./headers.bend as H
import ./text.bend as T
import ./cookie.bend as Ck
import ../../utf8/utf8.bend as U

# multipart/form-data (RFC 7578), with byte-exact bodies.
type Part is Data:
  Part{name: String, filename: Maybe<&2, String>, kind: Maybe<&2, String>, body: List<&2, U32>}

type Limits is Data:
  Limits{max_parts: Nat, max_header_bytes: Nat, max_headers: Nat}

type Error is Data:
  BadContentType{}
  BadBoundary{}
  Malformed{}
  TooManyParts{}
  HeadersTooLarge{}
  TooManyHeaders{}

def Parsed() -> Type:
  Result<&2, &2, Error, List<&2, Part>>

def filename_header(filename: Maybe<&2, String>) -> String:
  match filename:
    case Some{name}:
      "; filename=\"" ++ Ck.escape(name, True{}) ++ "\""
    case None{}:
      ""

def safe_header(s: String) -> String:
  match s:
    case SNil{}:
      ""
    case SCon{Chr{+c}, tail}:
      SCon{Chr{Bool.pick(U32, Bool.or(U32.is_lt(c, 32), U32.is_eq(c, 127)), 63, c)}, safe_header(tail)}

def kind_header(kind: Maybe<&2, String>) -> String:
  match kind:
    case Some{value}:
      "Content-Type: " ++ safe_header(value) ++ "\r\n"
    case None{}:
      ""

def part_head(name: String, filename: Maybe<&2, String>, kind: Maybe<&2, String>) -> String:
  "Content-Disposition: form-data; name=\"" ++ Ck.escape(name, True{}) ++ "\"" ++ filename_header(filename) ++ "\r\n" ++ kind_header(kind) ++ "\r\n"

def write.go(parts: List<&2, Part>, +boundary: String) -> List<&2, U32>:
  match parts:
    case Nil{}:
      U.encode("--" ++ boundary ++ "--\r\n")
    case Con{Part{name, filename, kind, body}, tail}:
      List.append(&2, U32, U.encode("--" ++ boundary ++ "\r\n" ++ part_head(name, filename, kind)),
        List.append(&2, U32, body, List.append(&2, U32, U.encode("\r\n"), write.go(tail, boundary))))

def write(boundary: String, parts: List<&2, Part>) -> List<&2, U32>:
  write.go(parts, boundary)

def prefix(pattern: List<&2, U32>, source: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match pattern source:
    case Nil{} rest:
      Some{rest}
    case Con{+want, tail} Con{+got, more}:
      Bool.pick(Maybe<&2, List<&2, U32>>, U32.is_eq(want, got), prefix(tail, more), None{})
    case _ _:
      None{}

type Marker is Data:
  NoMarker{}
  Next{rest: List<&2, U32>}
  Final{rest: List<&2, U32>}

def final_suffix(rest: List<&2, U32>) -> Marker:
  match rest:
    case Nil{}:
      Final{[]}
    case Con{13, Con{10, tail}}:
      Final{tail}
    case _:
      NoMarker{}

def marker_suffix(rest: List<&2, U32>) -> Marker:
  match rest:
    case Con{13, Con{10, tail}}:
      Next{tail}
    case Con{45, Con{45, tail}}:
      final_suffix(tail)
    case _:
      NoMarker{}

def marker(found: Maybe<&2, List<&2, U32>>) -> Marker:
  match found:
    case Some{rest}:
      marker_suffix(rest)
    case None{}:
      NoMarker{}

type Located is Data:
  Located{body: List<&2, U32>, rest: List<&2, U32>, final: Bool}
  NotLocated{}

def locate.step(mark: Marker, acc: List<&2, U32>, later: Located) -> Located:
  match mark:
    case Next{rest}:
      Located{List.reverse(&2, U32, acc), rest, False{}}
    case Final{rest}:
      Located{List.reverse(&2, U32, acc), rest, True{}}
    case NoMarker{}:
      later

# A marker must be at the start of a line and followed by CRLF or "--".
# A marker-like byte sequence with another suffix is part data.
def locate(source: List<&2, U32>, +between: List<&2, U32>, +acc: List<&2, U32>) -> Located:
  match source:
    case Nil{}:
      NotLocated{}
    case Con{+byte, +tail}:
      locate.step(marker(prefix(between, Con{byte, tail})), acc,
        locate(tail, between, Con{byte, acc}))

def marker_absent(mark: Marker) -> Bool:
  match mark:
    case NoMarker{}:
      True{}
    case _:
      False{}

# The data before a delimiter contains no complete delimiter line. This is
# the precondition for a writer/parser round trip with an explicit boundary.
def clean_prefixes(data: List<&2, U32>, +suffix: List<&2, U32>, +between: List<&2, U32>) -> Bool:
  match data:
    case Nil{}:
      True{}
    case Con{+byte, +tail}:
      Bool.and(marker_absent(marker(prefix(between, List.append(&2, U32, Con{byte, tail}, suffix)))),
        clean_prefixes(tail, suffix, between))

type HeaderBlock is Data:
  HeaderBlock{bytes: List<&2, U32>, rest: List<&2, U32>}
  HeaderLimit{}
  NoHeaderEnd{}

def header.step(found: Maybe<&2, List<&2, U32>>, source: List<&2, U32>, acc: List<&2, U32>, next: List<&2, U32> -> List<&2, U32> -> HeaderBlock) -> HeaderBlock:
  match found:
    case Some{rest}:
      HeaderBlock{List.reverse(&2, U32, acc), rest}
    case None{}:
      match source:
        case Con{b, tail}:
          next(tail, Con{b, acc})
        case Nil{}:
          NoHeaderEnd{}

def header_block(fuel: Nat, +source: List<&2, U32>, acc: List<&2, U32>) -> HeaderBlock:
  match fuel:
    case 0n:
      HeaderLimit{}
    case 1n+p:
      header.step(prefix([13, 10, 13, 10], source), source, acc,
        rest => bytes => header_block(p, rest, bytes))

type Headers is Data:
  Headers{fields: List<&2, H.Header>}
  BadHeaders{}
  HeaderCount{}

def field.both(name: Maybe<&2, String>, value: String) -> Maybe<&2, H.Header>:
  match name:
    case Some{n}:
      Some{H.Header{n, value}}
    case None{}:
      None{}

def field.cut(cut: T.Cut) -> Maybe<&2, H.Header>:
  match cut:
    case T.Cut{name, Some{value}}:
      field.both(Ct.token(Ct.trim(name), True{}), Ct.trim(value))
    case _:
      None{}

def field(s: String) -> Maybe<&2, H.Header>:
  field.cut(T.cut(s, 58))

def headers.last(last: Maybe<&2, H.Header>, acc: List<&2, H.Header>) -> Headers:
  match last:
    case Some{h}:
      Headers{List.reverse(&2, H.Header, Con{h, acc})}
    case None{}:
      BadHeaders{}

def headers.next(line: Maybe<&2, H.Header>, rest: String, acc: List<&2, H.Header>, next: String -> List<&2, H.Header> -> Headers) -> Headers:
  match line:
    case Some{h}:
      next(rest, Con{h, acc})
    case None{}:
      BadHeaders{}

def headers.rest(rest: String, line: String, acc: List<&2, H.Header>, next: String -> List<&2, H.Header> -> Headers) -> Headers:
  match rest:
    case SCon{Chr{10}, tail}:
      headers.next(field(line), tail, acc, next)
    case _:
      BadHeaders{}

def headers.cut(cut: T.Cut, acc: List<&2, H.Header>, next: String -> List<&2, H.Header> -> Headers) -> Headers:
  match cut:
    case T.Cut{line, Some{rest}}:
      headers.rest(rest, line, acc, next)
    case T.Cut{line, None{}}:
      headers.last(field(line), acc)

def headers.go(fuel: Nat, s: String, acc: List<&2, H.Header>) -> Headers:
  match fuel s:
    case _ SNil{}:
      Headers{List.reverse(&2, H.Header, acc)}
    case 0n _:
      HeaderCount{}
    case 1n+p other:
      headers.cut(T.cut(other, 13), acc, rest => more => headers.go(p, rest, more))

def headers.text(text: U.Text, +limit: Nat) -> Headers:
  match text:
    case U.TOk{value}:
      headers.go(limit, value, [])
    case U.TBad{_, _}:
      BadHeaders{}

type Slot is Data:
  NoValue{}
  OneValue{value: String}
  Duplicate{}

type Picked is Data:
  Picked{disposition: Slot, kind: Slot}

def slot.add(slot: Slot, value: String) -> Slot:
  match slot:
    case NoValue{}:
      OneValue{value}
    case _:
      Duplicate{}

def pick.go(hs: List<&2, H.Header>, disposition: Slot, kind: Slot) -> Picked:
  match hs:
    case Nil{}:
      Picked{disposition, kind}
    case Con{H.Header{name, value}, tail}:
      match name:
        case "content-disposition":
          pick.go(tail, slot.add(disposition, value), kind)
        case "content-type":
          pick.go(tail, disposition, slot.add(kind, value))
        case _:
          pick.go(tail, disposition, kind)

def optional(slot: Slot) -> Maybe<&2, Maybe<&2, String>>:
  match slot:
    case NoValue{}:
      Some{None{}}
    case OneValue{value}:
      Some{Some{value}}
    case Duplicate{}:
      None{}

type Names is Data:
  Names{name: Slot, filename: Slot}

def names.go(params: List<&2, Ct.Param>, name: Slot, filename: Slot) -> Names:
  match params:
    case Nil{}:
      Names{name, filename}
    case Con{Ct.Param{key, value}, tail}:
      match key:
        case "name":
          names.go(tail, slot.add(name, value), filename)
        case "filename":
          names.go(tail, name, slot.add(filename, value))
        case _:
          names.go(tail, name, filename)

def names.finish(name: Maybe<&2, String>, filename: Maybe<&2, Maybe<&2, String>>, kind: Maybe<&2, String>, body: List<&2, U32>) -> Maybe<&2, Part>:
  match name filename:
    case Some{n} Some{f}:
      Some{Part{n, f, kind, body}}
    case _ _:
      None{}

def decoded_filename(found: Maybe<&2, String>) -> Maybe<&2, Maybe<&2, String>>:
  match found:
    case Some{decoded}:
      Some{Some{decoded}}
    case None{}:
      None{}

def filename_decode(filename: Maybe<&2, String>) -> Maybe<&2, Maybe<&2, String>>:
  match filename:
    case Some{value}:
      decoded_filename(Ck.unescape(value))
    case None{}:
      Some{None{}}

def names.part(names: Names, kind: Maybe<&2, String>, body: List<&2, U32>) -> Maybe<&2, Part>:
  match names:
    case Names{OneValue{name}, NoValue{}}:
      names.finish(Ck.unescape(name), Some{None{}}, kind, body)
    case Names{OneValue{name}, OneValue{filename}}:
      names.finish(Ck.unescape(name), filename_decode(Some{filename}), kind, body)
    case _:
      None{}

def disposition_part(params: List<&2, Ct.Param>, kind: Maybe<&2, String>, body: List<&2, U32>) -> Maybe<&2, Part>:
  names.part(names.go(params, NoValue{}, NoValue{}), kind, body)

def disposition_parsed(params: Maybe<&2, List<&2, Ct.Param>>, kind: Maybe<&2, String>, body: List<&2, U32>) -> Maybe<&2, Part>:
  match params:
    case Some{ps}:
      disposition_part(ps, kind, body)
    case None{}:
      None{}

def picked.kind(kind: Maybe<&2, Maybe<&2, String>>, value: String, body: List<&2, U32>) -> Maybe<&2, Part>:
  match kind:
    case Some{k}:
      disposition_parsed(Ct.disposition(value), k, body)
    case None{}:
      None{}

def picked(p: Picked, body: List<&2, U32>) -> Maybe<&2, Part>:
  match p:
    case Picked{OneValue{value}, kind}:
      picked.kind(optional(kind), value, body)
    case _:
      None{}

def part(headers: Headers, body: List<&2, U32>) -> Maybe<&2, Part>:
  match headers:
    case Headers{hs}:
      picked(pick.go(hs, NoValue{}, NoValue{}), body)
    case _:
      None{}

def boundary_punct(+c: U32) -> Bool:
  match c:
    case 39: True{}
    case 40: True{}
    case 41: True{}
    case 43: True{}
    case 44: True{}
    case 45: True{}
    case 46: True{}
    case 47: True{}
    case 58: True{}
    case 61: True{}
    case 63: True{}
    case 95: True{}
    case _: False{}

def boundary_char(+c: U32) -> Bool:
  Bool.or(Bool.or(Bool.and(U32.is_ge(c, 48), U32.is_le(c, 57)),
    Bool.and(U32.is_ge(c, 65), U32.is_le(c, 90))),
    Bool.or(Bool.and(U32.is_ge(c, 97), U32.is_le(c, 122)),
      Bool.or(U32.is_eq(c, 32), boundary_punct(c))))

type CheckedBoundary is Data:
  CheckedBoundary{valid: Bool, value: String}

def boundary.go(s: String, +n: Nat, ok: Bool, last_space: Bool, acc: String) -> CheckedBoundary:
  match s:
    case SNil{}:
      CheckedBoundary{Bool.and(ok, Bool.and(Nat.is_le(1n, n), Bool.not(last_space))), String.reverse(acc)}
    case SCon{Chr{+c}, tail}:
      boundary.go(tail, Nat.add(n, 1n),
        Bool.and(ok, Bool.and(Nat.is_le(n, 69n), boundary_char(c))),
        U32.is_eq(c, 32), SCon{Chr{c}, acc})

def checked_boundary(check: CheckedBoundary) -> Maybe<&2, String>:
  match check:
    case CheckedBoundary{True{}, value}:
      Some{value}
    case CheckedBoundary{False{}, _}:
      None{}

def boundary(value: String) -> Maybe<&2, String>:
  checked_boundary(boundary.go(value, 0n, True{}, False{}, ""))

type Boundary is Data:
  Boundary{value: String}

def made_boundary(found: Maybe<&2, String>) -> Maybe<&2, Boundary>:
  match found:
    case Some{value}:
      Some{Boundary{value}}
    case None{}:
      None{}

def make_boundary(value: String) -> Maybe<&2, Boundary>:
  made_boundary(boundary(value))

type Piece is Data:
  Piece{part: Part, rest: List<&2, U32>, final: Bool}
  PieceError{err: Error}

def piece.part(found: Maybe<&2, Part>, rest: List<&2, U32>, final: Bool) -> Piece:
  match found:
    case Some{p}:
      Piece{p, rest, final}
    case None{}:
      PieceError{Malformed{}}

def piece.located(located: Located, headers: Headers) -> Piece:
  match located:
    case Located{body, rest, final}:
      piece.part(part(headers, body), rest, final)
    case NotLocated{}:
      PieceError{Malformed{}}

def piece.headers(headers: Headers, rest: List<&2, U32>, +boundary: String) -> Piece:
  match headers:
    case HeaderCount{}:
      PieceError{TooManyHeaders{}}
    case BadHeaders{}:
      PieceError{Malformed{}}
    case good:
      piece.located(locate(rest, U.encode("\r\n--" ++ boundary), []), good)

def piece.block(block: HeaderBlock, +boundary: String, +max_headers: Nat) -> Piece:
  match block:
    case HeaderBlock{bytes, rest}:
      piece.headers(headers.text(U.decode(bytes), max_headers), rest, boundary)
    case HeaderLimit{}:
      PieceError{HeadersTooLarge{}}
    case NoHeaderEnd{}:
      PieceError{Malformed{}}

def piece(source: List<&2, U32>, +boundary: String, +max_header_bytes: Nat, +max_headers: Nat) -> Piece:
  piece.block(header_block(Nat.add(max_header_bytes, 1n), source, []), boundary, max_headers)

def parse.step(step: Piece, acc: List<&2, Part>, next: List<&2, U32> -> List<&2, Part> -> Parsed()) -> Parsed():
  match step:
    case Piece{part, rest, True{}}:
      Done{List.reverse(&2, Part, Con{part, acc})}
    case Piece{part, rest, False{}}:
      next(rest, Con{part, acc})
    case PieceError{err}:
      Fail{err}

def parse.go(fuel: Nat, source: List<&2, U32>, +boundary: String, +max_header_bytes: Nat, +max_headers: Nat, acc: List<&2, Part>) -> Parsed():
  match fuel:
    case 0n:
      Fail{TooManyParts{}}
    case 1n+p:
      parse.step(piece(source, boundary, max_header_bytes, max_headers), acc,
        rest => parts => parse.go(p, rest, boundary, max_header_bytes, max_headers, parts))

def parse.started(start: Marker, +boundary: String, limits: Limits) -> Parsed():
  match start limits:
    case Final{_} _:
      Done{[]}
    case Next{rest} Limits{max_parts, max_header_bytes, max_headers}:
      parse.go(max_parts, rest, boundary, max_header_bytes, max_headers, [])
    case NoMarker{} _:
      Fail{Malformed{}}

def parse.boundary(+boundary: String, body: List<&2, U32>, limits: Limits) -> Parsed():
  parse.started(marker(prefix(U.encode("--" ++ boundary), body)), boundary, limits)

def parse.checked(found: Maybe<&2, String>, body: List<&2, U32>, limits: Limits) -> Parsed():
  match found:
    case Some{boundary}:
      parse.boundary(boundary, body, limits)
    case None{}:
      Fail{BadBoundary{}}

def parse.boundary_value(found: Maybe<&2, String>, body: List<&2, U32>, limits: Limits) -> Parsed():
  match found:
    case Some{value}:
      parse.checked(boundary(value), body, limits)
    case None{}:
      Fail{BadBoundary{}}

def parse.outer(media: Maybe<&2, Ct.Media>, body: List<&2, U32>, limits: Limits) -> Parsed():
  match media:
    case Some{Ct.Media{"multipart/form-data", params}}:
      parse.boundary_value(Ct.one(params, "boundary"), body, limits)
    case _:
      Fail{BadContentType{}}

def parse(kind: String, body: List<&2, U32>, limits: Limits) -> Parsed():
  parse.outer(Ct.parse(kind), body, limits)
