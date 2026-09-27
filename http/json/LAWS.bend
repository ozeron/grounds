import Base
import ./http_json.bend as HJ
import ../../json/json.bend as J
import ../core/method.bend as M
import ../core/headers.bend as H
import ../core/request.bend as Req

# Laws grounds-http-json must keep. `bend PROOF.bend` fails while any is open or false.

# whatever the headers, a body whose content type is not JSON is never parsed
law not_json_refused:
  for -A: Data
  for f: J.Json -> Result<&2, &2, J.Access, A>
  for +m: M.Method
  for +t: String
  for +hs: List<&2, H.Header>
  for +body: List<&2, U32>
  for e: {HJ.is_json(H.get(hs, "content-type")) == False{} : Bool}
  {HJ.decode(A, f, Req.Request{m, t, hs, body}) == Fail{HJ.UnsupportedContentType{}} : Result<&2, &2, HJ.DecodeError, A>}
