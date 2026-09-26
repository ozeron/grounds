import Base
import ../bjson.bend as J

# What the printer writes, said simply: each function writes its part in
# front of the text k. Only proofs use these.

def esc_char(k: J.Class, c: Char, rest: String) -> String:
  match k:
    case J.KQuote{}:
      SCon{'\\', SCon{c, rest}}
    case J.KBack{}:
      SCon{'\\', SCon{c, rest}}
    case J.KCtrl{}:
      J.ctrl_text(c) ++ rest
    case J.KPlain{}:
      SCon{c, rest}

def esc(s: String, k: String) -> String:
  match s:
    case SNil{}:
      k
    case SCon{+c, t}:
      esc_char(J.class(c), c, esc(t, k))

def str(s: String, k: String) -> String:
  SCon{'"', esc(s, SCon{'"', k})}

def op(more: Bool, c: Char) -> Char:
  match more:
    case True{}:
      ','
    case False{}:
      c

def text(j: J.Json, more: Bool, k: String) -> String:
  match j:
    case J.JNull{}:
      "null" ++ k
    case J.JBool{True{}}:
      "true" ++ k
    case J.JBool{False{}}:
      "false" ++ k
    case J.JNum{n}:
      J.num_k(n, k)
    case J.JStr{s}:
      str(s, k)
    case J.JArr{Nil{}}:
      match more:
        case True{}:
          SCon{']', k}
        case False{}:
          SCon{'[', SCon{']', k}}
    case J.JArr{Con{h, t}}:
      SCon{op(more, '['), text(h, False{}, text(J.JArr{t}, True{}, k))}
    case J.JObj{Nil{}}:
      match more:
        case True{}:
          SCon{'}', k}
        case False{}:
          SCon{'{', SCon{'}', k}}
    case J.JObj{Con{J.Field{key, v}, t}}:
      SCon{op(more, '{'), str(key, SCon{':', text(v, False{}, text(J.JObj{t}, True{}, k))})}

# the same text laid out: with pretty, each item starts on its own line,
# indented by u per level, and a colon has a space after it

def ind(n: Nat, +u: String) -> String:
  match n:
    case 0n:
      ""
    case 1n+p:
      u ++ ind(p, u)

def bw(p: Bool, u: String, n: Nat) -> String:
  match p:
    case True{}:
      SCon{'\n', ind(n, u)}
    case False{}:
      ""

def sp(p: Bool) -> String:
  match p:
    case True{}:
      " "
    case False{}:
      ""

def lay(j: J.Json, more: Bool, +p: Bool, +u: String, +d: Nat, k: String) -> String:
  match j:
    case J.JNull{}:
      "null" ++ k
    case J.JBool{True{}}:
      "true" ++ k
    case J.JBool{False{}}:
      "false" ++ k
    case J.JNum{n}:
      J.num_k(n, k)
    case J.JStr{s}:
      str(s, k)
    case J.JArr{Nil{}}:
      match more:
        case True{}:
          bw(p, u, d) ++ SCon{']', k}
        case False{}:
          SCon{'[', SCon{']', k}}
    case J.JArr{Con{h, t}}:
      SCon{op(more, '['), bw(p, u, 1n+d) ++ lay(h, False{}, p, u, 1n+d, lay(J.JArr{t}, True{}, p, u, d, k))}
    case J.JObj{Nil{}}:
      match more:
        case True{}:
          bw(p, u, d) ++ SCon{'}', k}
        case False{}:
          SCon{'{', SCon{'}', k}}
    case J.JObj{Con{J.Field{key, v}, t}}:
      SCon{op(more, '{'), bw(p, u, 1n+d) ++ str(key, SCon{':', sp(p) ++ lay(v, False{}, p, u, 1n+d, lay(J.JObj{t}, True{}, p, u, d, k))})}

# an indent unit made of white space, built so proofs can see it is
type WsC is Data:
  WSpace{}
  WTab{}

def wstr(cs: List<&2, WsC>) -> String:
  match cs:
    case Nil{}:
      ""
    case Con{WSpace{}, t}:
      SCon{' ', wstr(t)}
    case Con{WTab{}, t}:
      SCon{'\t', wstr(t)}
