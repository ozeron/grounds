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

# a literal match compares nothing through a shared helper, so it reads s
# without sharing it
def parse(s: String) -> Method:
  match s:
    case "GET":
      MGet{}
    case "HEAD":
      MHead{}
    case "POST":
      MPost{}
    case "PUT":
      MPut{}
    case "DELETE":
      MDelete{}
    case "CONNECT":
      MConnect{}
    case "OPTIONS":
      MOptions{}
    case "TRACE":
      MTrace{}
    case "PATCH":
      MPatch{}
    case other:
      MOther{other}
