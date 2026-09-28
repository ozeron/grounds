import Base
import ../client.bend as C
import ../../../json/json.bend as J

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

# a reply as its status and body text, or its status and body size
def says(r: C.R(C.Reply), +size: Bool) -> String:
  match r size:
    case Done{C.Reply{+c, _, b}} True{}:
      U32.show(c) ++ ", " ++ U32.show(count(b, 0)) ++ " bytes"
    case Done{C.Reply{+c, hs, b}} False{}:
      line.text(c, C.utf8(C.Reply{c, hs, b}))
    case Fail{e} _:
      "error: " ++ C.show(e)

def one(name: String, +size: Bool, act: IO(C.R(C.Reply))) -> IO(Unit):
  IO.bind(C.R(C.Reply), Unit, act, r => IO.print(name ++ ": " ++ says(r, size)))

def cfg() -> C.Config:
  C.default()

def short() -> C.Config:
  C.with_timeout(C.default(), 500)

def get(u: String) -> IO(C.R(C.Reply)):
  C.send(cfg(), C.get(u))

def main() -> IO(Unit):
  do IO<Unit>:
    a : Unit <- one("chunked", False{}, get("http://127.0.0.1:7301/"))
    b : Unit <- one("to close", False{}, get("http://127.0.0.1:7302/"))
    c : Unit <- one("stall", False{}, C.send(short(), C.get("http://127.0.0.1:7303/")))
    d : Unit <- one("cut", False{}, get("http://127.0.0.1:7304/"))
    e : Unit <- one("huge", False{}, get("http://127.0.0.1:7305/"))
    f : Unit <- one("continue", False{}, get("http://127.0.0.1:7306/"))
    g : Unit <- one("echo", False{}, C.send(cfg(), C.with(C.put("http://localhost:7307/p?q=1", C.bytes("application/octet-stream", [104, 105])), [("Host", "evil"), ("x-a", "1"), ("Content-Length", "99"), ("x-bad", "a\r\nx-injected: 1")])))
    h : Unit <- one("garbage", False{}, get("http://127.0.0.1:7308/"))
    i : Unit <- one("big", True{}, get("http://127.0.0.1:7309/"))
    j : Unit <- one("split head", False{}, get("http://127.0.0.1:7310/"))
    k : Unit <- one("refused", False{}, get("http://127.0.0.1:7399/"))
    l : Unit <- one("no host", False{}, get("http://no-such-host.invalid/"))
    o : Unit <- one("server stream", True{}, get("http://127.0.0.1:8086/big?n=64"))
    p : Unit <- one("server sse", False{}, get("http://localhost:8086/events"))
    q : Unit <- one("server head", True{}, C.send(cfg(), C.head("http://127.0.0.1:8086/healthz")))
    r : Unit <- one("too large for the config", False{}, C.send(C.with_max_body(C.default(), 1000), C.get("http://127.0.0.1:8086/big?n=1")))
    s : Unit <- one("form", False{}, C.send(cfg(), C.post("http://localhost:7307/f", C.form([("q", "cups & mugs"), ("n", "2")]))))
    t : Unit <- one("query", False{}, C.send(cfg(), C.query(C.get("http://localhost:7307/p?x=1"), [("a b", "\u{fc}"), ("k", "=&")])))
    u : Unit <- one("query on a bare path", False{}, C.send(cfg(), C.query(C.get("http://localhost:7307/p"), [("a", "1")])))
    v : Unit <- one("bearer", False{}, C.send(cfg(), C.bearer(C.get("http://localhost:7307/b"), "t0ken")))
    w : Unit <- one("method PURGE", False{}, C.send(cfg(), C.method("PURGE", "http://localhost:7307/c", C.empty())))
    x : Unit <- one("bad method", False{}, C.send(cfg(), C.method("BAD METHOD", "http://localhost:7307/c", C.empty())))
    y : Unit <- one("text", False{}, C.send(cfg(), C.post("http://localhost:7307/t", C.text("h\u{e9}llo"))))
    z : Unit <- one("json", False{}, C.send(cfg(), C.patch("http://localhost:7307/j", C.json(J.JObj{[J.Field{"a", J.JBool{True{}}}]}))))
    za : Unit <- one("json, the caller's Accept", False{}, C.send(cfg(), C.with(C.put("http://localhost:7307/j", C.json(J.JNull{})), [("Accept", "text/plain"), ("Content-Type", "application/vnd.x+json")])))
    zb : Unit <- one("delete", False{}, C.send(cfg(), C.delete("http://localhost:7307/d")))
    one("idempotency key", False{}, C.send(cfg(), C.idempotent(C.post("http://localhost:7307/i", C.empty()), "k-42")))
