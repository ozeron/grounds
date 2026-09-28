import Base
import ../client.bend as C
import ../../../wire/wire.bend as W
import ../../../json/json.bend as J

# retries, redirects, JSON, streams and TLS, against tests/fake.py (7311
# on, TLS on 7315) and examples/stream (8086): one line per case, which
# check.sh compares with tests/more.out

def line.text(+code: U32, m: Maybe<&2, String>) -> String:
  match m:
    case Some{t}:
      U32.show(code) ++ " " ++ t
    case None{}:
      U32.show(code) ++ " (not UTF-8)"

def says(r: C.R(C.Reply)) -> String:
  match r:
    case Done{C.Reply{+c, hs, b}}:
      line.text(c, C.utf8(C.Reply{c, hs, b}))
    case Fail{e}:
      "error: " ++ C.show(e)

def one(name: String, act: IO(C.R(C.Reply))) -> IO(Unit):
  IO.bind(C.R(C.Reply), Unit, act, r => IO.print(name ++ ": " ++ says(r)))

def cfg() -> C.Config:
  C.with_timeout(C.default(), 3000)

def retrying() -> C.Config:
  C.with_retries(cfg(), 3, 50)

def secret() -> C.Kv():
  [("Authorization", "secret")]

def x() -> C.Body:
  C.bytes("text/plain", [120])

def hi() -> C.Body:
  C.bytes("text/plain", [104, 105])

# JSON
# ----

def name(j: J.Json) -> Result<&2, &2, J.Access, String>:
  J.string_at(j, [J.Name{"name"}])

def as_json(j: J.Json) -> Result<&2, &2, J.Access, J.Json>:
  Done{j}

def jsaid(r: C.R(String)) -> String:
  match r:
    case Done{s}:
      s
    case Fail{e}:
      "error: " ++ C.show(e)

def jechoed(r: C.R(J.Json)) -> String:
  match r:
    case Done{j}:
      J.encode(j)
    case Fail{e}:
      "error: " ++ C.show(e)

def order(n: U32) -> J.Json:
  J.JObj{[J.Field{"n", J.num_u32(n)}, J.Field{"item", J.JStr{"cup"}}]}

def jone(label: String, act: IO(C.R(String))) -> IO(Unit):
  IO.bind(C.R(String), Unit, act, r => IO.print(label ++ ": " ++ jsaid(r)))

# Streams
# -------

def count(bs: List<&2, U32>, +n: U32) -> U32:
  match bs:
    case Nil{}:
      n
    case Con{_, t}:
      count(t, (n + 1 : U32))

# counts the bytes on wire's process-wide counter: a callback has no state
# of its own
def tally(bs: List<&2, U32>) -> IO(Bool):
  IO.bind(U32, Bool, W.wire_live(count(bs, 0)), n => IO.pure(Bool, True{}))

def first(bs: List<&2, U32>) -> IO(Bool):
  IO.pure(Bool, False{})

def streamed(r: C.R(C.Head), +n: U32) -> String:
  match r:
    case Done{C.Head{+c, _}}:
      U32.show(c) ++ ", " ++ U32.show(n) ++ " bytes streamed"
    case Fail{e}:
      "error: " ++ C.show(e)

def main() -> IO(Unit):
  do IO<Unit>:
    e : Unit <- one("retry GET on 503", C.send(retrying(), C.get("http://127.0.0.1:7313/2/a")))
    f : Unit <- one("no retry for POST", C.send(retrying(), C.post("http://127.0.0.1:7313/2/b", C.empty())))
    fa : Unit <- one("retry an idempotent POST", C.send(retrying(), C.idempotent(C.post("http://127.0.0.1:7313/2/e", C.empty()), "k1")))
    g : Unit <- one("retries run out", C.send(retrying(), C.get("http://127.0.0.1:7313/9/c")))
    h : Unit <- one("off by default", C.send(cfg(), C.get("http://127.0.0.1:7313/1/d")))
    ha : Unit <- one("send_ok on a 503", C.send_ok(cfg(), C.get("http://127.0.0.1:7313/1/f")))
    i : Unit <- one("301", C.send(cfg(), C.with(C.get("http://127.0.0.1:7314/r/301"), secret())))
    j : Unit <- one("302 POST", C.send(cfg(), C.post("http://127.0.0.1:7314/r/302", x())))
    k : Unit <- one("303 POST", C.send(cfg(), C.post("http://127.0.0.1:7314/r/303", x())))
    l : Unit <- one("307 POST", C.send(cfg(), C.post("http://127.0.0.1:7314/r/307", hi())))
    m : Unit <- one("308 PUT", C.send(cfg(), C.put("http://127.0.0.1:7314/r/308", hi())))
    n : Unit <- one("to another url", C.send(cfg(), C.with(C.get("http://127.0.0.1:7314/abs"), secret())))
    o : Unit <- one("redirect loop", C.send(cfg(), C.get("http://127.0.0.1:7314/loop")))
    q : Unit <- one("not followed with 0", C.send(C.with_redirects(cfg(), 0), C.get("http://127.0.0.1:7314/r/301")))
    r : Unit <- one("http to https followed", C.send(cfg(), C.get("http://127.0.0.1:7314/tls")))
    rr : Unit <- one("never from https to http", C.send(cfg(), C.get("https://localhost:7315/down")))
    s : Unit <- jone("send_json", C.fetch_json(String, "http://127.0.0.1:7316/item", name))
    u : Unit <- jone("send_json, not JSON", C.fetch_json(String, "http://127.0.0.1:7316/bad", name))
    w : Unit <- jone("send_json, 404", C.fetch_json(String, "http://127.0.0.1:7316/missing", name))
    aa : String <- IO.bind(C.R(J.Json), String, C.send_json(J.Json, cfg(), C.post("http://127.0.0.1:7316/echo", C.json(order(3))), as_json), y => IO.pure(String, jechoed(y)))
    ab : Unit <- IO.print("send_json POST: " ++ aa)
    ac : U32 <- W.wire_live(0)
    ad : C.R(C.Head) <- C.stream(~tally, cfg(), C.get("http://127.0.0.1:8086/big?n=160"))
    +ae : U32 <- W.wire_live(0)
    af : Unit <- IO.print("stream 10 MiB, past max_body: " ++ streamed(ad, (ae - ac : U32)))
    ag : C.R(C.Head) <- C.stream(~first, cfg(), C.get("http://127.0.0.1:8086/big?n=160"))
    ah : Unit <- IO.print("stream, stopped at once: " ++ streamed(ag, 0))
    ai : C.R(C.Head) <- C.stream(~tally, cfg(), C.get("http://127.0.0.1:7314/missing"))
    aj : Unit <- IO.print("stream of a 404: " ++ streamed(ai, 0))
    one("https", C.send(cfg(), C.get("https://localhost:7315/")))
