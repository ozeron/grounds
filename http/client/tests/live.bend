import Base
import ../client.bend as C
import ../../core/method.bend as M
import ../../core/headers.bend as H
import ../../core/response.bend as Res
import ../../core/status.bend as S

# the client against tests/fake.py (7301 on) and examples/stream (8086):
# one line per case, which check.sh compares with tests/live.out

def count(bs: List<&2, U32>, +n: U32) -> U32:
  match bs:
    case Nil{}:
      n
    case Con{_, t}:
      count(t, (n + 1 : U32))

def line.text(+code: U32, m: Maybe<&2, String>) -> String:
  match m:
    case Some{t}:
      U32.show(code) ++ " " ++ t
    case None{}:
      U32.show(code) ++ " (not UTF-8)"

# a response as its status and body text, or its status and body size
def says(r: C.R(), +size: Bool) -> String:
  match r size:
    case Done{Res.Response{S.Status{+c}, _, b}} True{}:
      U32.show(c) ++ ", " ++ U32.show(count(b, 0)) ++ " bytes"
    case Done{Res.Response{S.Status{+c}, hs, b}} False{}:
      line.text(c, C.text(Res.Response{S.Status{c}, hs, b}))
    case Fail{e} _:
      "error: " ++ C.show(e)

def one(name: String, +size: Bool, act: IO(C.R())) -> IO(Unit):
  IO.bind(C.R(), Unit, act, r => IO.print(name ++ ": " ++ says(r, size)))

def short() -> C.Config:
  C.with_timeout(C.default(), 500)

def main() -> IO(Unit):
  do IO<Unit>:
    a : Unit <- one("chunked", False{}, C.get("http://127.0.0.1:7301/"))
    b : Unit <- one("to close", False{}, C.get("http://127.0.0.1:7302/"))
    c : Unit <- one("stall", False{}, C.request(short(), M.MGet{}, "http://127.0.0.1:7303/", [], []))
    d : Unit <- one("cut", False{}, C.get("http://127.0.0.1:7304/"))
    e : Unit <- one("huge", False{}, C.get("http://127.0.0.1:7305/"))
    f : Unit <- one("continue", False{}, C.get("http://127.0.0.1:7306/"))
    g : Unit <- one("echo", False{}, C.request(C.default(), M.MPut{}, "http://localhost:7307/p?q=1", [H.Header{"Host", "evil"}, H.Header{"x-a", "1"}, H.Header{"Content-Length", "99"}, H.Header{"x-bad", "a\r\nx-injected: 1"}], [104, 105]))
    h : Unit <- one("garbage", False{}, C.get("http://127.0.0.1:7308/"))
    i : Unit <- one("big", True{}, C.get("http://127.0.0.1:7309/"))
    j : Unit <- one("split head", False{}, C.get("http://127.0.0.1:7310/"))
    k : Unit <- one("refused", False{}, C.get("http://127.0.0.1:7399/"))
    l : Unit <- one("no host", False{}, C.get("http://no-such-host.invalid/"))
    n : Unit <- one("https", False{}, C.get("https://example.com/"))
    o : Unit <- one("server stream", True{}, C.get("http://127.0.0.1:8086/big?n=64"))
    p : Unit <- one("server sse", False{}, C.get("http://localhost:8086/events"))
    q : Unit <- one("server head", True{}, C.request(C.default(), M.MHead{}, "http://127.0.0.1:8086/healthz", [], []))
    one("too large for the config", False{}, C.request(C.with_max_body(C.default(), 1000), M.MGet{}, "http://127.0.0.1:8086/big?n=1", [], []))
