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
