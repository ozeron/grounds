import Base
import ../core/request.bend as Req
import ../core/method.bend as M
import ../core/headers.bend as H
import ../core/text.bend as T
import ../core/auth.bend as Auth
import ../wire/http1.bend as H1
import ../../crypto/sha1.bend as Sha1
import ../../crypto/bytes.bend as B
import ../../utf8/utf8.bend as U

# RFC 6455 server handshake. The accept hash uses SHA-1 only for the
# protocol's fixed challenge; it authenticates neither peer nor content.

def b64char(+n: U32) -> Char:
  code = Bool.pick(U32, U32.is_lt(n, 26), U32.add(n, 65),
    Bool.pick(U32, U32.is_lt(n, 52), U32.add(n, 71),
      Bool.pick(U32, U32.is_lt(n, 62), U32.sub(n, 4),
        Bool.pick(U32, U32.is_eq(n, 62), 43, 47))))
  Char.from_u32(code)

def encode64(bytes: List<&2, U32>) -> String:
  match bytes:
    case Nil{}:
      ""
    case Con{+a, Con{+b, Con{+c, tail}}}:
      SCon{b64char(U32.shrn(a, 2n)),
        SCon{b64char(U32.or(U32.shln(U32.and(a, 3), 4n), U32.shrn(b, 4n))),
          SCon{b64char(U32.or(U32.shln(U32.and(b, 15), 2n), U32.shrn(c, 6n))),
            SCon{b64char(U32.and(c, 63)), encode64(tail)}}}}
    case Con{+a, Con{+b, Nil{}}}:
      SCon{b64char(U32.shrn(a, 2n)),
        SCon{b64char(U32.or(U32.shln(U32.and(a, 3), 4n), U32.shrn(b, 4n))),
          SCon{b64char(U32.shln(U32.and(b, 15), 2n)), "="}}}
    case Con{+a, Nil{}}:
      SCon{b64char(U32.shrn(a, 2n)),
        SCon{b64char(U32.shln(U32.and(a, 3), 4n)), "=="}}

def one(values: List<&2, String>) -> Maybe<&2, String>:
  match values:
    case Con{value, Nil{}}:
      Some{value}
    case _:
      None{}

def any_token(values: List<&2, String>, +want: String) -> Bool:
  match values:
    case Nil{}:
      False{}
    case Con{value, tail}:
      Bool.or(H1.has_token(value, want), any_token(tail, want))

def not_empty(value: String) -> Bool:
  match value:
    case SNil{}:
      False{}
    case _:
      True{}

def accept_hash(result: Maybe<&2, List<&2, U32>>) -> Maybe<&2, String>:
  match result:
    case None{}:
      None{}
    case Some{bytes}:
      Some{encode64(bytes)}

def accept_key(key: String) -> Maybe<&2, String>:
  accept_hash(Sha1.digest(U.encode(key ++ "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")))

def accept_valid(ok: Bool, key: String) -> Maybe<&2, String>:
  match ok:
    case True{}:
      accept_key(key)
    case False{}:
      None{}

def accept_decoded(decoded: Maybe<&2, List<&2, U32>>, key: String) -> Maybe<&2, String>:
  match decoded:
    case Some{bytes}:
      accept_valid(Nat.is_eq(B.length(bytes), 16n), key)
    case None{}:
      None{}

def accept_fields.valid(ok: Bool, +key: String) -> Maybe<&2, String>:
  match ok:
    case True{}:
      accept_decoded(Auth.b64_go(24n, key, []), key)
    case False{}:
      None{}

def accept_fields(host: Maybe<&2, String>, key: Maybe<&2, String>, version: Maybe<&2, String>,
                  upgrade: Bool, connection: Bool) -> Maybe<&2, String>:
  match host key version:
    case Some{h} Some{+k} Some{v}:
      ok = Bool.and(Bool.and(not_empty(h), T.same(v, "13", True{})),
        Bool.and(upgrade, connection))
      accept_fields.valid(ok, k)
    case _ _ _:
      None{}

def accept_headers(+hs: List<&2, H.Header>) -> Maybe<&2, String>:
  accept_fields(one(H.all(hs, "host")), one(H.all(hs, "sec-websocket-key")),
    one(H.all(hs, "sec-websocket-version")),
    any_token(H.all(hs, "upgrade"), "websocket"),
    any_token(H.all(hs, "connection"), "upgrade"))

def accept(req: Req.Request) -> Maybe<&2, String>:
  match req:
    case Req.Request{M.MGet{}, _, hs, Nil{}}:
      accept_headers(hs)
    case _:
      None{}
