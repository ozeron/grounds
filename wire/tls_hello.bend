import Base
import ./tls_extensions.bend as E
import ../crypto/bytes.bend as B

# TLS 1.3 ClientHello/ServerHello encodings (RFC 9846 4.2.2-4.2.4).
# Read exact handshake header+body bytes. Negotiation, extension body/context
# rules, session echo, share validation and transcript/state are caller-owned.

type Error is Data:
  Decode{}
  Version{}
  Compression{}
  Overflow{}

type Hello is Data:
  Client{random: List<&2, U32>, session: List<&2, U32>, suites: List<&2, U32>, extensions: List<&2, E.Extension>}
  Server{random: List<&2, U32>, session: List<&2, U32>, suite: U32, extensions: List<&2, E.Extension>}

type Fields is Data:
  Fields{kind: U32, random: List<&2, U32>, session: List<&2, U32>, suites: List<&2, U32>}

def suites(bytes: List<&2, U32>, reversed: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match bytes:
    case Nil{}: Some{List.reverse(&2, U32, reversed)}
    case Con{high, Con{low, rest}}: suites(rest, Con{E.number(high, low), reversed})
    case _: None{}

def finish(fields: Fields, extensions: Maybe<&2, List<&2, E.Extension>>) -> Result<&2, &2, Error, Hello>:
  match fields extensions:
    case _ None{}: Fail{Decode{}}
    case Fields{1, random, session, offered} Some{values}:
      Done{Client{random, session, offered, values}}
    case Fields{2, random, session, Con{selected, Nil{}}} Some{values}:
      Done{Server{random, session, selected, values}}
    case _ _: Fail{Decode{}}

def extensions_checked(enough: Bool, fields: Fields, bytes: List<&2, U32>) -> Result<&2, &2, Error, Hello>:
  match enough:
    case False{}: Fail{Decode{}}
    case True{}: finish(fields, E.parse(bytes))

def client_compression(fields: Fields, bytes: List<&2, U32>) -> Result<&2, &2, Error, Hello>:
  match bytes:
    case Nil{}: Fail{Decode{}}
    case Con{1, Nil{}}: Fail{Decode{}}
    case Con{1, Con{0, +extensions}}:
      extensions_checked(Nat.is_ge(B.length(extensions), 9n), fields, extensions)
    case _: Fail{Compression{}}

def client_suites(random: List<&2, U32>, session: List<&2, U32>, rest: List<&2, U32>, values: Maybe<&2, List<&2, U32>>) -> Result<&2, &2, Error, Hello>:
  match values:
    case None{}: Fail{Decode{}}
    case Some{offered}: client_compression(Fields{1, random, session, offered}, rest)

def client_parts(random: List<&2, U32>, session: List<&2, U32>, value: Maybe<&2, E.Parts>) -> Result<&2, &2, Error, Hello>:
  match value:
    case None{}: Fail{Decode{}}
    case Some{E.Parts{bytes, rest}}: client_suites(random, session, rest, suites(bytes, []))

def client_size(valid: Bool, random: List<&2, U32>, session: List<&2, U32>, size: Nat, bytes: List<&2, U32>) -> Result<&2, &2, Error, Hello>:
  match valid:
    case False{}: Fail{Decode{}}
    case True{}: client_parts(random, session, E.take(size, bytes, []))

def client(random: List<&2, U32>, session: List<&2, U32>, bytes: List<&2, U32>) -> Result<&2, &2, Error, Hello>:
  match bytes:
    case Con{high, Con{low, rest}}:
      +size = U32.to_nat(E.number(high, low))
      client_size(Bool.and(Nat.is_ge(size, 2n), Bool.and(Nat.is_le(size, 65534n),
        Nat.is_eq(Nat.mod(size, 2n), 0n))), random, session, size, rest)
    case _: Fail{Decode{}}

def server_compression(valid: Bool, fields: Fields, +extensions: List<&2, U32>) -> Result<&2, &2, Error, Hello>:
  match valid:
    case False{}: Fail{Compression{}}
    case True{}: extensions_checked(Nat.is_ge(B.length(extensions), 8n), fields, extensions)

def server(random: List<&2, U32>, session: List<&2, U32>, bytes: List<&2, U32>) -> Result<&2, &2, Error, Hello>:
  match bytes:
    case Con{high, Con{low, Con{compression, extensions}}}:
      server_compression(U32.is_eq(compression, 0), Fields{2, random, session, [E.number(high, low)]}, extensions)
    case _: Fail{Decode{}}

def session_parts(kind: U32, random: List<&2, U32>, value: Maybe<&2, E.Parts>) -> Result<&2, &2, Error, Hello>:
  match kind value:
    case _ None{}: Fail{Decode{}}
    case 1 Some{E.Parts{session, rest}}: client(random, session, rest)
    case 2 Some{E.Parts{session, rest}}: server(random, session, rest)
    case _ _: Fail{Decode{}}

def session_size(valid: Bool, kind: U32, random: List<&2, U32>, size: Nat, bytes: List<&2, U32>) -> Result<&2, &2, Error, Hello>:
  match valid:
    case False{}: Fail{Decode{}}
    case True{}: session_parts(kind, random, E.take(size, bytes, []))

def random_parts(kind: U32, value: Maybe<&2, E.Parts>) -> Result<&2, &2, Error, Hello>:
  match value:
    case Some{E.Parts{random, Con{+size, rest}}}:
      session_size(U32.is_le(size, 32), kind, random, U32.to_nat(size), rest)
    case _: Fail{Decode{}}

def version(valid: Bool, kind: U32, bytes: List<&2, U32>) -> Result<&2, &2, Error, Hello>:
  match valid:
    case False{}: Fail{Version{}}
    case True{}: random_parts(kind, E.take(32n, bytes, []))

def body(kind: U32, bytes: List<&2, U32>) -> Result<&2, &2, Error, Hello>:
  match bytes:
    case Con{high, Con{low, rest}}:
      version(U32.is_eq(E.number(high, low), 771), kind, rest)
    case _: Fail{Decode{}}

def frame_size(exact: Bool, bounded: Bool, kind: U32, bytes: List<&2, U32>) -> Result<&2, &2, Error, Hello>:
  match exact bounded:
    case False{} _: Fail{Decode{}}
    case True{} False{}: Fail{Overflow{}}
    case True{} True{}: body(kind, bytes)

def frame_kind(kind: U32, +size: Nat, +bytes: List<&2, U32>) -> Result<&2, &2, Error, Hello>:
  match kind:
    case 1: frame_size(Nat.is_eq(size, B.length(bytes)), Nat.is_le(size, 131142n), 1, bytes)
    case 2: frame_size(Nat.is_eq(size, B.length(bytes)), Nat.is_le(size, 65607n), 2, bytes)
    case _: Fail{Decode{}}

def frame(bytes: List<&2, U32>) -> Result<&2, &2, Error, Hello>:
  match bytes:
    case Con{kind, Con{a, Con{b, Con{c, rest}}}}:
      frame_kind(kind, Nat.add(Nat.mul(U32.to_nat(a), 65536n), U32.to_nat(E.number(b, c))), rest)
    case _: Fail{Decode{}}

def admitted(valid: Bool, bounded: Bool, bytes: List<&2, U32>) -> Result<&2, &2, Error, Hello>:
  match valid bounded:
    case False{} _: Fail{Decode{}}
    case True{} False{}: Fail{Overflow{}}
    case True{} True{}: frame(bytes)

def parse(+bytes: List<&2, U32>) -> Result<&2, &2, Error, Hello>:
  admitted(B.valid(bytes), Nat.is_le(B.length(bytes), 131146n), bytes)

def retry_random() -> List<&2, U32>:
  [207, 33, 173, 116, 229, 154, 97, 17, 190, 29, 140, 2, 30, 101, 184, 145,
   194, 162, 17, 22, 122, 187, 140, 94, 7, 158, 9, 226, 200, 168, 51, 156]

def same(first: List<&2, U32>, second: List<&2, U32>, equal: Bool) -> Bool:
  match first second:
    case Nil{} Nil{}: equal
    case Con{a, at} Con{b, bt}: same(at, bt, Bool.and(equal, U32.is_eq(a, b)))
    case _ _: False{}

def is_retry(value: Hello) -> Bool:
  match value:
    case Server{random, _, _, _}: same(random, retry_random(), True{})
    case _: False{}
