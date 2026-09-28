import Base
import ./websocket.bend as Ws
import ../core/request.bend as Req
import ../core/method.bend as M
import ../core/headers.bend as H

def rfc_request() -> Req.Request:
  Req.Request{M.MGet{}, "/chat", [
    H.Header{"Host", "server.example.com"},
    H.Header{"Upgrade", "websocket"},
    H.Header{"Connection", "Upgrade"},
    H.Header{"Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="},
    H.Header{"Sec-WebSocket-Version", "13"}], []}

def rfc_accept() -> {Ws.accept(rfc_request()) == Some{"s3pPLMBiTxaQ9kYGzzhZRbK+xOo="} : Maybe<&2, String>}:
  {==}

def rejects_bad_version() -> {Ws.accept(Req.Request{M.MGet{}, "/chat", [
    H.Header{"Host", "server.example.com"}, H.Header{"Upgrade", "websocket"},
    H.Header{"Connection", "Upgrade"}, H.Header{"Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="},
    H.Header{"Sec-WebSocket-Version", "12"}], []}) == None{} : Maybe<&2, String>}:
  {==}

def rejects_short_key() -> {Ws.accept(Req.Request{M.MGet{}, "/chat", [
    H.Header{"Host", "server.example.com"}, H.Header{"Upgrade", "websocket"},
    H.Header{"Connection", "Upgrade"}, H.Header{"Sec-WebSocket-Key", "YQ=="},
    H.Header{"Sec-WebSocket-Version", "13"}], []}) == None{} : Maybe<&2, String>}:
  {==}
