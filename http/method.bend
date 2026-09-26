import Base
import ./text.bend as T

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

def pick(hit: Bool, m: Method, rest: Method) -> Method:
  match hit:
    case True{}:
      m
    case False{}:
      rest

def parse(+s: String) -> Method:
  pick(T.same(s, "GET", True{}), MGet{},
  pick(T.same(s, "HEAD", True{}), MHead{},
  pick(T.same(s, "POST", True{}), MPost{},
  pick(T.same(s, "PUT", True{}), MPut{},
  pick(T.same(s, "DELETE", True{}), MDelete{},
  pick(T.same(s, "CONNECT", True{}), MConnect{},
  pick(T.same(s, "OPTIONS", True{}), MOptions{},
  pick(T.same(s, "TRACE", True{}), MTrace{},
  pick(T.same(s, "PATCH", True{}), MPatch{}, MOther{s})))))))))
