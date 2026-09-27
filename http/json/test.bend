import Base
import ./http_json.bend as HJ
import ../../json/json.bend as J
import ../../utf8/utf8.bend as U
import ../core/method.bend as M
import ../core/headers.bend as H
import ../core/request.bend as Req

# each def is a test: it checks only if both sides compute to the same value

def post(ct: String, body: String) -> Req.Request:
  Req.Request{M.MPost{}, "/", [H.Header{"Content-Type", ct}], U.encode(body)}

def name(+j: J.Json) -> Result<&2, &2, J.Access, String>:
  J.string_at(j, [J.Name{"name"}])

def R() -> Type:
  Result<&2, &2, HJ.DecodeError, String>

def json_type() -> {HJ.is_json(Some{"application/json"}) == True{} : Bool}:
  {==}

def json_params() -> {HJ.is_json(Some{" Application/JSON ; charset=utf-8"}) == True{} : Bool}:
  {==}

def json_suffix() -> {HJ.is_json(Some{"application/problem+json"}) == True{} : Bool}:
  {==}

def json_not() -> {HJ.is_json(Some{"application/jsonx"}) == False{} : Bool}:
  {==}

def json_text() -> {HJ.is_json(Some{"text/plain"}) == False{} : Bool}:
  {==}

def json_none() -> {HJ.is_json(None{}) == False{} : Bool}:
  {==}

def decode_ok() -> {HJ.decode(String, j => name(j), post("application/json", "{\"name\": \"a\"}")) == Done{"a"} : R()}:
  {==}

def decode_type() -> {HJ.decode(String, j => name(j), post("text/plain", "{\"name\": \"a\"}")) == Fail{HJ.UnsupportedContentType{}} : R()}:
  {==}

def decode_bad() -> {HJ.decode(String, j => name(j), post("application/json", "{")) == Fail{HJ.InvalidJson{J.Error{J.UnexpectedEnd{}, 1, 1, 2}}} : R()}:
  {==}

def decode_value() -> {HJ.decode(String, j => name(j), post("application/json", "{\"name\": 1}")) == Fail{HJ.InvalidValue{J.Expected{[J.Name{"name"}], J.KString{}, J.KNumber{}}}} : R()}:
  {==}
