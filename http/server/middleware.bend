import Base
import ../core/method.bend as M
import ../core/status.bend as S
import ../core/request.bend as Req
import ../core/headers.bend as H
import ../core/response.bend as Res
import ../core/auth.bend as Auth

# middleware as compile-time wrappers: each takes the next handler as a
# template, so a stack is one expression the compiler inlines:
#
#   Server.serve(~Mw.logger(~Mw.request_id(~Mw.recover(~app))), cfg)
#
# A wrapper that needs a number takes it as a template too: a def with no
# arguments, e.g. def small() -> U32: 1024, as Mw.body_limit(~small, ~app)

def RS() -> Type:
  Result<&1, &1, String, Res.Response>

# Recover
# -------

def recover.go(r: RS()) -> IO(Res.Response):
  match r:
    case Done{res}:
      IO.pure(Res.Response, res)
    case Fail{why}:
      do IO<Res.Response>:
        x : Unit <- IO.print_err("error: " ++ why)
        return Res.text(S.internal_error(), "Internal Server Error")

# a handler that may fail: Fail{why} logs why to stderr and answers 500,
# so a handler's error never reaches the client
def recover(~next: Req.Request -> IO(RS()), r: Req.Request) -> IO(Res.Response):
  IO.bind(RS(), Res.Response, next(r), recover.go)

# Body limit
# ----------

# a body and its length, counted in one read
type Sized is Data:
  Sized{n: U32, body: List<&2, U32>}

def count(bs: List<&2, U32>, +n: U32, acc: List<&2, U32>) -> Sized:
  match bs:
    case Nil{}:
      Sized{n, List.reverse(&2, U32, acc)}
    case Con{b, t}:
      count(t, (n + 1 : U32), Con{b, acc})

def body_limit.go(~next: Req.Request -> IO(Res.Response), ok: Bool, m: M.Method, t: String, hs: List<&2, H.Header>, b: List<&2, U32>) -> IO(Res.Response):
  match ok:
    case True{}:
      next(Req.Request{m, t, hs, b})
    case False{}:
      IO.pure(Res.Response, Res.text(S.content_too_large(), "Content Too Large"))

def body_limit.sized(~max: U32, ~next: Req.Request -> IO(Res.Response), s: Sized, m: M.Method, t: String, hs: List<&2, H.Header>) -> IO(Res.Response):
  match s:
    case Sized{n, b}:
      body_limit.go(~next, U32.is_le(n, max), m, t, hs, b)

# a body over max bytes answers 413 before next sees it; the server's
# max_body_bytes bounds every body, this one a handler's
def body_limit(~max: U32, ~next: Req.Request -> IO(Res.Response), r: Req.Request) -> IO(Res.Response):
  match r:
    case Req.Request{m, t, hs, b}:
      body_limit.sized(~max, ~next, count(b, 0, []), m, t, hs)

# Request id
# ----------

def hex.digit(+d: U32) -> Char:
  Chr{Bool.pick(U32, U32.is_lt(d, 10), (d + 48 : U32), (d + 87 : U32))}

def hex.go(n: Nat, +x: U32, acc: String) -> String:
  match n:
    case 0n:
      acc
    case 1n+p:
      hex.go(p, (x >> 4n : U32), SCon{hex.digit((x .&. 15 : U32)), acc})

def hex(+x: U32) -> String:
  hex.go(8n, x, "")

def random(r: Result<&1, &1, U32 & String, U32>) -> U32:
  match r:
    case Done{x}:
      x
    case Fail{_}:
      0

# every response gets x-request-id: 16 random hex digits
def request_id(~next: Req.Request -> IO(Res.Response), r: Req.Request) -> IO(Res.Response):
  do IO<Res.Response>:
    a : Result<&1, &1, U32 & String, U32> <- IO.random_u32()
    b : Result<&1, &1, U32 & String, U32> <- IO.random_u32()
    res : Res.Response <- next(r)
    return Res.header(res, "x-request-id", hex(random(a)) ++ hex(random(b)))

# Add HSTS to responses from an HTTPS listener. Browsers disregard this
# header over plain HTTP.
def hsts(~next: Req.Request -> IO(Res.Response), r: Req.Request) -> IO(Res.Response):
  do IO<Res.Response>:
    res : Res.Response <- next(r)
    return Res.header(res, "strict-transport-security", "max-age=31536000")

# Authentication
# --------------

def auth.bearer_missing() -> Res.Response:
  Res.header(Res.text(S.unauthorized(), "Unauthorized"), "www-authenticate", "Bearer realm=\"grounds\"")

def auth.basic_missing() -> Res.Response:
  Res.header(Res.text(S.unauthorized(), "Unauthorized"), "www-authenticate", "Basic realm=\"grounds\", charset=\"UTF-8\"")

def auth.missing() -> Res.Response:
  Res.header(auth.bearer_missing(), "www-authenticate", "Basic realm=\"grounds\", charset=\"UTF-8\"")

def auth.bearer_invalid() -> Res.Response:
  Res.header(Res.text(S.unauthorized(), "Unauthorized"), "www-authenticate", "Bearer realm=\"grounds\", error=\"invalid_token\"")

def auth.bearer_bad() -> Res.Response:
  Res.header(Res.text(S.bad_request(), "Bad Request"), "www-authenticate", "Bearer realm=\"grounds\", error=\"invalid_request\"")

def auth.rejected(bearer: Bool) -> IO(Res.Response):
  match bearer:
    case True{}:
      IO.pure(Res.Response, auth.bearer_invalid())
    case False{}:
      IO.pure(Res.Response, auth.basic_missing())

def auth.checked(~next: Auth.Principal -> Req.Request -> IO(Res.Response), principal: Maybe<&2, Auth.Principal>, r: Req.Request, bearer: Bool) -> IO(Res.Response):
  match principal:
    case Some{p}:
      next(p, r)
    case None{}:
      auth.rejected(bearer)

def auth.attempt(~verify: Auth.Credential -> IO(Maybe<&2, Auth.Principal>), ~next: Auth.Principal -> Req.Request -> IO(Res.Response), attempt: Auth.Attempt, r: Req.Request) -> IO(Res.Response):
  match attempt:
    case Auth.Got{Auth.Bearer{token}}:
      IO.bind(Maybe<&2, Auth.Principal>, Res.Response, verify(Auth.Bearer{token}), p => auth.checked(~next, p, r, True{}))
    case Auth.Got{Auth.Basic{user, password}}:
      IO.bind(Maybe<&2, Auth.Principal>, Res.Response, verify(Auth.Basic{user, password}), p => auth.checked(~next, p, r, False{}))
    case Auth.BadBearer{}:
      IO.pure(Res.Response, auth.bearer_bad())
    case Auth.BadBasic{}:
      IO.pure(Res.Response, auth.basic_missing())
    case Auth.Duplicate{}:
      IO.pure(Res.Response, auth.bearer_bad())
    case Auth.Missing{}:
      IO.pure(Res.Response, auth.missing())
    case Auth.Unsupported{}:
      IO.pure(Res.Response, auth.missing())

def auth.taken(~verify: Auth.Credential -> IO(Maybe<&2, Auth.Principal>), ~next: Auth.Principal -> Req.Request -> IO(Res.Response), taken: Auth.Taken) -> IO(Res.Response):
  match taken:
    case Auth.Taken{attempt, req}:
      auth.attempt(~verify, ~next, attempt, req)

# Verifier returns Some{principal} to admit the request; next receives that
# principal and a request with Authorization removed. Rejection has a 401
# challenge; malformed Bearer credentials and duplicates have a 400 challenge.
def auth(~verify: Auth.Credential -> IO(Maybe<&2, Auth.Principal>), ~next: Auth.Principal -> Req.Request -> IO(Res.Response), r: Req.Request) -> IO(Res.Response):
  auth.taken(~verify, ~next, Auth.take(r))

# Logger
# ------

def copy(s: String, acc: String) -> String:
  match s:
    case SNil{}:
      String.reverse(acc)
    case SCon{Chr{x}, t}:
      copy(t, SCon{Chr{(x + 0 : U32)}, acc})

# the method's name, copied: M.show hands back MOther's own String, which
# would take the method the request still needs
def method_name(m: M.Method) -> String:
  match m:
    case M.MOther{x}:
      copy(x, "")
    case M.MGet{}:
      "GET"
    case M.MHead{}:
      "HEAD"
    case M.MPost{}:
      "POST"
    case M.MPut{}:
      "PUT"
    case M.MDelete{}:
      "DELETE"
    case M.MConnect{}:
      "CONNECT"
    case M.MOptions{}:
      "OPTIONS"
    case M.MTrace{}:
      "TRACE"
    case M.MPatch{}:
      "PATCH"

def logged(line: String, +start: Nat, res: Res.Response) -> IO(Res.Response):
  match res:
    case Res.Response{S.Status{+c}, hs, b}:
      do IO<Res.Response>:
        +now : Nat <- IO.now()
        x : Unit <- IO.print(line ++ " " ++ U32.show(c) ++ " " ++ Nat.show(Nat.sub(now, start)) ++ "ms")
        return Res.Response{S.Status{c}, hs, b}

def logger.go(~next: Req.Request -> IO(Res.Response), line: String, r: Req.Request) -> IO(Res.Response):
  do IO<Res.Response>:
    +start : Nat <- IO.now()
    res : Res.Response <- next(r)
    logged(line, start, res)

# one line per request on stdout: "GET /todos/2 200 0ms"
def logger(~next: Req.Request -> IO(Res.Response), r: Req.Request) -> IO(Res.Response):
  match r:
    case Req.Request{+m, +t, hs, b}:
      logger.go(~next, method_name(m) ++ " " ++ copy(t, ""), Req.Request{m, t, hs, b})
