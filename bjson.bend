import Base

type Json is Data:
  JNull{}
  JBool{value: Bool}
  JNum{value: F32}
  JStr{value: String}
  JArr{items: List<&2, Json>}
  JObj{fields: List<&2, Field>}

type Field is Data:
  Field{key: String, value: Json}

type Error is Data:
  UnexpectedEnd{}
  UnexpectedChar{char: Char}
  TrailingInput{}

# a value and the input left after it
type Parsed is Data:
  Ok{value: Json, rest: String}
  Err{error: Error}

# a word matched at the head of the input
type Expect is Data:
  Matched{rest: String}
  Mismatch{error: Error}

def is_null(j: Json) -> Bool:
  match j:
    case JNull{}:
      True{}
    case _:
      False{}

# RFC 8259 §2: only space, tab, LF and CR
def skip_ws(s: String) -> String:
  match s:
    case SCon{' ', t}:
      skip_ws(t)
    case SCon{'\t', t}:
      skip_ws(t)
    case SCon{'\n', t}:
      skip_ws(t)
    case SCon{'\r', t}:
      skip_ws(t)
    case rest:
      rest

def expect(word: String, s: String) -> Expect:
  match word s:
    case SNil{} rest:
      Matched{rest}
    case SCon{_, _} SNil{}:
      Mismatch{UnexpectedEnd{}}
    case SCon{+w, wt} SCon{+c, st}:
      Bool.pick(Expect, Char.is_eq(w, c), expect(wt, st), Mismatch{UnexpectedChar{c}})

def literal(value: Json, e: Expect) -> Parsed:
  match e:
    case Matched{rest}:
      Ok{value, rest}
    case Mismatch{err}:
      Err{err}

# RFC 8259 §3: lowercase true, false, null
def parse_value(s: String) -> Parsed:
  match s:
    case SNil{}:
      Err{UnexpectedEnd{}}
    case SCon{'t', t}:
      literal(JBool{True{}}, expect("rue", t))
    case SCon{'f', t}:
      literal(JBool{False{}}, expect("alse", t))
    case SCon{'n', t}:
      literal(JNull{}, expect("ull", t))
    case SCon{c, _}:
      Err{UnexpectedChar{c}}

def finish.end(value: Json, rest: String) -> Result<&2, &2, Error, Json>:
  match rest:
    case SNil{}:
      Done{value}
    case SCon{_, _}:
      Fail{TrailingInput{}}

def finish(p: Parsed) -> Result<&2, &2, Error, Json>:
  match p:
    case Err{err}:
      Fail{err}
    case Ok{value, rest}:
      finish.end(value, skip_ws(rest))

# RFC 8259 §2: JSON-text = ws value ws
def parse(s: String) -> Result<&2, &2, Error, Json>:
  finish(parse_value(skip_ws(s)))
