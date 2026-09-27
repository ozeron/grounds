import Base
import ./http_json.bend as HJ
import ../../json/json.bend as J
import ../core/method.bend as M
import ../core/headers.bend as H
import ../core/request.bend as Req

# Laws grounds-http-json must keep. `bend PROOF.bend` fails while any is open or false.

def R(-A: Data) -> Type:
  Result<&2, &2, HJ.DecodeError, A>

# media-type parameters never change the decision: what follows ; is not read
law json_params:
  for params: String
  {HJ.is_json(Some{"application/json;" ++ params}) == True{} : Bool}

law suffix_params:
  for params: String
  {HJ.is_json(Some{"application/problem+json;" ++ params}) == True{} : Bool}

law text_params:
  for params: String
  {HJ.is_json(Some{"text/plain;" ++ params}) == False{} : Bool}

# a body sent as another type, or with no type, is never parsed
law other_type_refused:
  for -A: Data
  for f: J.Json -> Result<&2, &2, J.Access, A>
  for m: M.Method
  for t: String
  for body: List<&2, U32>
  {HJ.decode(A, f, Req.Request{m, t, [H.Header{"Content-Type", "text/plain"}], body}) == Fail{HJ.UnsupportedContentType{}} : R(A)}

law no_type_refused:
  for -A: Data
  for f: J.Json -> Result<&2, &2, J.Access, A>
  for m: M.Method
  for t: String
  for body: List<&2, U32>
  {HJ.decode(A, f, Req.Request{m, t, [], body}) == Fail{HJ.UnsupportedContentType{}} : R(A)}
