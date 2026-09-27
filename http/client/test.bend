import Base
import ./client.bend as C

# each def is a test: it checks only if both sides compute to the same value

def plain() -> {C.url("http://localhost/a?b=1") == C.Url{"localhost", 80, "/a?b=1", "localhost"} : C.Url}:
  {==}

def port() -> {C.url("http://10.0.0.7:8080") == C.Url{"10.0.0.7", 8080, "/", "10.0.0.7:8080"} : C.Url}:
  {==}

def query_only() -> {C.url("http://h:81?x") == C.Url{"h", 81, "/?x", "h:81"} : C.Url}:
  {==}

def https() -> {C.url("https://h/") == C.UBad{C.Https{}} : C.Url}:
  {==}

def no_scheme() -> {C.url("h/") == C.UBad{C.BadUrl{}} : C.Url}:
  {==}

def no_host() -> {C.url("http:///x") == C.UBad{C.BadUrl{}} : C.Url}:
  {==}

def user_info() -> {C.url("http://u@h/") == C.UBad{C.BadUrl{}} : C.Url}:
  {==}

def port_zero() -> {C.url("http://h:0/") == C.UBad{C.BadUrl{}} : C.Url}:
  {==}

def port_big() -> {C.url("http://h:65536/") == C.UBad{C.BadUrl{}} : C.Url}:
  {==}

def port_empty() -> {C.url("http://h:/") == C.UBad{C.BadUrl{}} : C.Url}:
  {==}

def space_in_target() -> {C.url("http://h/a b") == C.UBad{C.BadUrl{}} : C.Url}:
  {==}

def crlf_in_target() -> {C.url("http://h/a\r\nX: y") == C.UBad{C.BadUrl{}} : C.Url}:
  {==}
