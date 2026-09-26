import Base
import ./bjson.bend as J

# big inputs through parse and print: nothing here may overflow the stack
# printing recurses on nesting, so deep values print up to about 5k levels

def rep.go(n: Nat, +s: String, acc: String) -> String:
  match n:
    case 0n:
      acc
    case 1n+p:
      rep.go(p, s, s ++ acc)

def rep(n: Nat, s: String) -> String:
  rep.go(n, s, "")

def parsed(r: Result<&2, &2, J.Error, J.Json>) -> String:
  match r:
    case Done{_}:
      "ok"
    case Fail{J.Error{_, o, _, _}}:
      "error at " ++ U32.show(o)

def len(r: Result<&2, &2, J.Error, J.Json>) -> String:
  match r:
    case Done{j}:
      "ok, " ++ U32.show(U32.from_nat(String.length(J.stringify(j)))) ++ " chars printed"
    case Fail{J.Error{_, o, _, _}}:
      "error at " ++ U32.show(o)

def pretty_deep(r: Result<&2, &2, J.Error, J.Json>) -> String:
  match r:
    case Done{j}:
      J.pretty(j, " ")
    case Fail{_}:
      ""

def main() -> IO(Unit):
  do IO<Unit>:
    IO.print("string 100k escapes: " ++ len(J.parse("\"" ++ rep(50000n, "\\n\\u00e9") ++ "\"")))
    IO.print("array 100k items:    " ++ len(J.parse("[" ++ rep(99999n, "1,") ++ "1]")))
    IO.print("object 20k fields:   " ++ len(J.parse("{" ++ rep(19999n, "\"k\": null, ") ++ "\"z\": 0}")))
    IO.print("number 100k digits:  " ++ len(J.parse(rep(100000n, "7"))))
    IO.print("parse 100k deep:     " ++ parsed(J.parse(rep(100000n, "[") ++ rep(100000n, "]"))))
    IO.print("print 5k deep:       " ++ len(J.parse(rep(5000n, "[") ++ rep(5000n, "]"))))
    IO.print("pretty 2k deep:      " ++ U32.show(U32.from_nat(String.length(pretty_deep(J.parse(rep(2000n, "[") ++ rep(2000n, "]")))))) ++ " chars")
