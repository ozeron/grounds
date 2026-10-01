import Base

# request methods (RFC 9110 §9); names are case-sensitive
type Method is Data:
  MGet{}
  MHead{}
  MPost{}
  MPut{}
  MDelete{}
  MConnect{}
  MOptions{}
  MTrace{}
  MPatch{}
  MOther{name: String}

def show(m: Method) -> String:
  match m:
    case MGet{}:
      "GET"
    case MHead{}:
      "HEAD"
    case MPost{}:
      "POST"
    case MPut{}:
      "PUT"
    case MDelete{}:
      "DELETE"
    case MConnect{}:
      "CONNECT"
    case MOptions{}:
      "OPTIONS"
    case MTrace{}:
      "TRACE"
    case MPatch{}:
      "PATCH"
    case MOther{name}:
      name

# Consume the suffix once. Keep the consumed prefix reversed so a mismatch
# can restore the original spelling without sharing any String.
def parse.step(equal: Bool, c: Char, tail: String, seen: String, next: String -> String -> Method) -> Method:
  match equal:
    case True{}:
      next(tail, SCon{c, seen})
    case False{}:
      MOther{String.reverse(SCon{c, seen}) ++ tail}

def parse.word(word: String, s: String, known: Method, seen: String) -> Method:
  match word s:
    case SNil{} SNil{}:
      known
    case SCon{expected, rest} SCon{+c, tail}:
      parse.step(Char.is_eq(c, expected), c, tail, seen, t => prefix => parse.word(rest, t, known, prefix))
    case SNil{} remaining:
      MOther{String.reverse(seen) ++ remaining}
    case SCon{_, _} SNil{}:
      MOther{String.reverse(seen)}

def parse.p(code: U32, tail: String) -> Method:
  match code:
    case 79: parse.word("ST", tail, MPost{}, "OP")
    case 85: parse.word("T", tail, MPut{}, "UP")
    case 65: parse.word("TCH", tail, MPatch{}, "AP")
    case other: MOther{SCon{'P', SCon{Chr{other}, tail}}}

def parse.after_p(s: String) -> Method:
  match s:
    case SNil{}: MOther{"P"}
    case SCon{Chr{code}, tail}: parse.p(code, tail)

def parse.first(code: U32, tail: String) -> Method:
  match code:
    case 71: parse.word("ET", tail, MGet{}, "G")
    case 72: parse.word("EAD", tail, MHead{}, "H")
    case 68: parse.word("ELETE", tail, MDelete{}, "D")
    case 67: parse.word("ONNECT", tail, MConnect{}, "C")
    case 79: parse.word("PTIONS", tail, MOptions{}, "O")
    case 84: parse.word("RACE", tail, MTrace{}, "T")
    case 80: parse.after_p(tail)
    case other: MOther{SCon{Chr{other}, tail}}

def parse(s: String) -> Method:
  match s:
    case SNil{}: MOther{""}
    case SCon{Chr{code}, tail}: parse.first(code, tail)
