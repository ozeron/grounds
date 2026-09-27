import Base
import ./LAWS.bend as Laws
import ./http_json.bend as HJ
import ../core/headers.bend as H

def Laws.not_json_refused(A, f, m, t, hs, body, e):
  %Equal.sym(Bool, HJ.is_json(H.get(hs, "content-type")), False{}, e) : {HJ.decode.typed(A, f, _, body) == Fail{HJ.UnsupportedContentType{}} : Result<&2, &2, HJ.DecodeError, A>}
  {==}
