import Base
import ./text.bend as T

# Content-Type's media type and semicolon parameters. Quoted parameter values
# may contain semicolons and quoted-pair escapes (RFC 9110 §8.3).
type Param is Data:
  Param{name: String, value: String}

type Media is Data:
  Media{kind: String, params: List<&2, Param>}

type Segments is Data:
  Segments{items: List<&2, String>, ok: Bool}

def segment.end(current: String, acc: List<&2, String>, ok: Bool) -> Segments:
  Segments{List.reverse(&2, String, Con{String.reverse(current), acc}), ok}

def segments.go(s: String, quote: Bool, escape: Bool, current: String, acc: List<&2, String>) -> Segments:
  match s quote escape:
    case SNil{} False{} False{}:
      segment.end(current, acc, True{})
    case SNil{} _ _:
      segment.end(current, acc, False{})
    case SCon{Chr{59}, tail} False{} False{}:
      segments.go(tail, False{}, False{}, "", Con{String.reverse(current), acc})
    case SCon{Chr{34}, tail} False{} False{}:
      segments.go(tail, True{}, False{}, SCon{'"', current}, acc)
    case SCon{Chr{34}, tail} True{} False{}:
      segments.go(tail, False{}, False{}, SCon{'"', current}, acc)
    case SCon{Chr{92}, tail} True{} False{}:
      segments.go(tail, True{}, True{}, SCon{'\\', current}, acc)
    case SCon{c, tail} q True{}:
      segments.go(tail, q, False{}, SCon{c, current}, acc)
    case SCon{c, tail} q False{}:
      segments.go(tail, q, False{}, SCon{c, current}, acc)

def drop_space(s: String) -> String:
  match s:
    case SCon{Chr{32}, tail}:
      drop_space(tail)
    case SCon{Chr{9}, tail}:
      drop_space(tail)
    case other:
      other

def trim(s: String) -> String:
  String.reverse(drop_space(String.reverse(drop_space(s))))

def tpunct(+c: U32) -> Bool:
  match c:
    case 33: True{}
    case 35: True{}
    case 36: True{}
    case 37: True{}
    case 38: True{}
    case 39: True{}
    case 42: True{}
    case 43: True{}
    case 45: True{}
    case 46: True{}
    case 94: True{}
    case 95: True{}
    case 96: True{}
    case 124: True{}
    case 126: True{}
    case _: False{}

def tchar(+c: U32) -> Bool:
  Bool.or(Bool.or(Bool.and(U32.is_ge(c, 48), U32.is_le(c, 57)),
    Bool.and(U32.is_ge(c, 65), U32.is_le(c, 90))),
    Bool.or(Bool.and(U32.is_ge(c, 97), U32.is_le(c, 122)), tpunct(c)))

type Checked is Data:
  Checked{ok: Bool, text: String}

def token.go(s: String, seen: Bool, ok: Bool, +lower: Bool, acc: String) -> Checked:
  match s:
    case SNil{}:
      Checked{Bool.and(seen, ok), String.reverse(acc)}
    case SCon{Chr{+c}, tail}:
      token.go(tail, True{}, Bool.and(ok, tchar(c)), lower,
        SCon{Chr{Bool.pick(U32, lower, T.lower(c), c)}, acc})

def checked(c: Checked) -> Maybe<&2, String>:
  match c:
    case Checked{True{}, text}:
      Some{text}
    case Checked{False{}, _}:
      None{}

def token(s: String, lower: Bool) -> Maybe<&2, String>:
  checked(token.go(s, False{}, True{}, lower, ""))

def is_empty(s: String) -> Bool:
  match s:
    case SNil{}: True{}
    case _: False{}

def quoted.empty(rest: String, acc: String) -> Maybe<&2, String>:
  match rest:
    case SNil{}:
      Some{String.reverse(acc)}
    case _:
      None{}

def quoted.end(rest: String, acc: String) -> Maybe<&2, String>:
  quoted.empty(trim(rest), acc)

def quoted.go(s: String, escape: Bool, acc: String) -> Maybe<&2, String>:
  match s escape:
    case SNil{} _:
      None{}
    case SCon{Chr{34}, tail} False{}:
      quoted.end(tail, acc)
    case SCon{Chr{92}, tail} False{}:
      quoted.go(tail, True{}, acc)
    case SCon{Chr{+c}, tail} _:
      Bool.pick(Maybe<&2, String>, Bool.and(U32.is_ge(c, 32), Bool.not(U32.is_eq(c, 127))),
        quoted.go(tail, False{}, SCon{Chr{c}, acc}), None{})

def value(s: String) -> Maybe<&2, String>:
  match s:
    case SCon{Chr{34}, tail}:
      quoted.go(tail, False{}, "")
    case other:
      token(other, False{})

def param.both(name: Maybe<&2, String>, value: Maybe<&2, String>) -> Maybe<&2, Param>:
  match name value:
    case Some{n} Some{v}:
      Some{Param{n, v}}
    case _ _:
      None{}

def param.cut(cut: T.Cut) -> Maybe<&2, Param>:
  match cut:
    case T.Cut{name, Some{v}}:
      param.both(token(trim(name), True{}), value(trim(v)))
    case _:
      None{}

def parse_param(s: String) -> Maybe<&2, Param>:
  param.cut(T.cut(s, 61))

def kind.both(a: Maybe<&2, String>, b: Maybe<&2, String>) -> Maybe<&2, String>:
  match a b:
    case Some{type_name} Some{subtype}:
      Some{type_name ++ "/" ++ subtype}
    case _ _:
      None{}

def kind.cut(cut: T.Cut) -> Maybe<&2, String>:
  match cut:
    case T.Cut{type_name, Some{subtype}}:
      kind.both(token(trim(type_name), True{}), token(trim(subtype), True{}))
    case _:
      None{}

def kind(s: String) -> Maybe<&2, String>:
  kind.cut(T.cut(s, 47))

def params.join(a: Maybe<&2, Param>, rest: Maybe<&2, List<&2, Param>>) -> Maybe<&2, List<&2, Param>>:
  match a rest:
    case Some{param} Some{ps}:
      Some{Con{param, ps}}
    case _ _:
      None{}

def params(ps: List<&2, String>) -> Maybe<&2, List<&2, Param>>:
  match ps:
    case Nil{}:
      Some{[]}
    case Con{p, tail}:
      params.join(parse_param(p), params(tail))

def media.join(kind: Maybe<&2, String>, params: Maybe<&2, List<&2, Param>>) -> Maybe<&2, Media>:
  match kind params:
    case Some{k} Some{ps}:
      Some{Media{k, ps}}
    case _ _:
      None{}

def parse.items(items: List<&2, String>) -> Maybe<&2, Media>:
  match items:
    case Con{head, tail}:
      media.join(kind(head), params(tail))
    case Nil{}:
      None{}

def parsed(segments: Segments) -> Maybe<&2, Media>:
  match segments:
    case Segments{items, True{}}:
      parse.items(items)
    case Segments{_, False{}}:
      None{}

def parse(s: String) -> Maybe<&2, Media>:
  parsed(segments.go(s, False{}, False{}, "", []))

def disposition.token(head: Maybe<&2, String>, ps: List<&2, String>) -> Maybe<&2, List<&2, Param>>:
  match head:
    case Some{"form-data"}:
      params(ps)
    case _:
      None{}

def disposition.head(head: String, ps: List<&2, String>) -> Maybe<&2, List<&2, Param>>:
  disposition.token(token(trim(head), True{}), ps)

def disposition.items(items: List<&2, String>) -> Maybe<&2, List<&2, Param>>:
  match items:
    case Con{head, tail}:
      disposition.head(head, tail)
    case Nil{}:
      None{}

def disposition.parsed(segments: Segments) -> Maybe<&2, List<&2, Param>>:
  match segments:
    case Segments{items, True{}}:
      disposition.items(items)
    case Segments{_, False{}}:
      None{}

def disposition(s: String) -> Maybe<&2, List<&2, Param>>:
  disposition.parsed(segments.go(s, False{}, False{}, "", []))

def param_hit(hit: Bool, value: String, later: Maybe<&2, String>) -> Maybe<&2, String>:
  match hit:
    case True{}:
      Some{value}
    case False{}:
      later

def get(params: List<&2, Param>, +name: String) -> Maybe<&2, String>:
  match params:
    case Nil{}:
      None{}
    case Con{Param{key, value}, tail}:
      param_hit(T.same_ci(key, name, True{}), value, get(tail, name))

type OneValue is Data:
  NotSeen{}
  Saw{value: String}
  Repeated{}

def one.step(hit: Bool, value: String, seen: OneValue) -> OneValue:
  match hit seen:
    case True{} NotSeen{}:
      Saw{value}
    case True{} _:
      Repeated{}
    case False{} other:
      other

def one.go(params: List<&2, Param>, +name: String, seen: OneValue) -> OneValue:
  match params:
    case Nil{}:
      seen
    case Con{Param{key, value}, tail}:
      one.go(tail, name, one.step(T.same_ci(key, name, True{}), value, seen))

def one.value(v: OneValue) -> Maybe<&2, String>:
  match v:
    case Saw{value}:
      Some{value}
    case _:
      None{}

def one(params: List<&2, Param>, name: String) -> Maybe<&2, String>:
  one.value(one.go(params, name, NotSeen{}))
