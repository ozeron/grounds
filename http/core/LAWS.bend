import Base
import ./headers.bend as H
import ./query.bend as Q
import ./text.bend as T
import ./event.bend as Ev
import ./cookie.bend as Ck
import ./cors.bend as Cors
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

# Set-Cookie's value never contains CR or LF, even with arbitrary input text.
law set_cookie_clean:
  for +name: String
  for +value: String
  {Ck.no_crlf(Ck.set_value(name, value)) == True{} : Bool}

# CORS never selects an unlisted origin; "*" requires an explicit wildcard
# policy entry and credentials disabled.
law cors_safe:
  for +origins: List<&2, String>
  for +credentials: Bool
  for +origin: String
  {Cors.safe(Cors.decide(origins, credentials, origin), origins, credentials) == True{} : Bool}

# Server-sent events (WHATWG HTML, the event stream format)
# ------------------

# no CR and no LF (a name, an id), and no CR (data, whose LFs split it
# into data: lines)
def line.clean(s: String) -> Bool:
  match s:
    case SNil{}:
      True{}
    case SCon{Chr{+x}, t}:
      Bool.and(Bool.and(Bool.not(U32.is_eq(x, 10)), Bool.not(U32.is_eq(x, 13))), line.clean(t))

def data.clean(s: String) -> Bool:
  match s:
    case SNil{}:
      True{}
    case SCon{Chr{+x}, t}:
      Bool.and(Bool.not(U32.is_eq(x, 13)), data.clean(t))

def id.clean(i: Maybe<&2, String>) -> Bool:
  match i:
    case Some{s}:
      line.clean(s)
    case None{}:
      True{}

def msg.ok(m: Ev.Message) -> Bool:
  match m:
    case Ev.Message{n, d, i}:
      Bool.and(line.clean(n), Bool.and(data.clean(d), id.clean(i)))

def writable(ms: List<&2, Ev.Message>) -> Bool:
  match ms:
    case Nil{}:
      True{}
    case Con{m, t}:
      Bool.and(msg.ok(m), writable(t))

# what the server writes for events, one after another
def stream(ms: List<&2, Ev.Message>) -> String:
  match ms:
    case Nil{}:
      ""
    case Con{m, t}:
      Ev.write.to(m, stream(t))

# the id an event is read with: its own, or the last one before it (an id
# with a NUL is ignored)
def next.id(i: Maybe<&2, String>, +last: Maybe<&2, String>) -> Maybe<&2, String>:
  match i:
    case Some{s}:
      Ev.keep.id.of(s, last)
    case None{}:
      last

# what a client reads for them: the same names (message for none), data
# and ids, an id carried over to the events after it
def read(ms: List<&2, Ev.Message>, +last: Maybe<&2, String>) -> List<&2, Ev.Message>:
  match ms:
    case Nil{}:
      []
    case Con{Ev.Message{n, d, +i}, t}:
      Con{Ev.Message{Ev.name.or(n), d, next.id(i, last)}, read(t, next.id(i, last))}

def events(f: Ev.Fed) -> List<&2, Ev.Message>:
  match f:
    case Ev.Fed{_, es}:
      es

# events written read back as the same events, for any names and ids with
# no CR or LF and any data with no CR: data with LFs, and data holding text
# like data: or id:, included
law sse_reads_back:
  for +ms: List<&2, Ev.Message>
  for e: {writable(ms) == True{} : Bool}
  {events(Ev.feed(stream(ms), Ev.start())) == read(ms, None{}) : List<&2, Ev.Message>}

# events sent one write at a time make the same stream
law write_joins:
  for +m: Ev.Message
  for +r: String
  {String.append(Ev.write(m), r) == Ev.write.to(m, r) : String}
