import Base
import ./signaling.bend as S
import ./signaling_auth.bend as Auth
import ../json/json.bend as J
import ../http/core/request.bend as Req
import ../http/core/method.bend as M
import ../http/core/headers.bend as H

def denied(kind: J.Json) -> S.Command:
  S.command.json(Done{J.JArr{[kind, J.JBool{True{}}, J.JStr{""}]}})

def offer_exact() -> {denied(J.JStr{"offer"}) == S.Bad{"invalid offer revision"} : S.Command}:
  {==}

def offer_suffix() -> {denied(J.JStr{"offerx"}) == S.Bad{"expected [offer, revision, SDP]"} : S.Command}:
  {==}

def offer_case() -> {denied(J.JStr{"OFFER"}) == S.Bad{"expected [offer, revision, SDP]"} : S.Command}:
  {==}

def offer_prefix() -> {denied(J.JStr{"offe"}) == S.Bad{"expected [offer, revision, SDP]"} : S.Command}:
  {==}

def offer_not_text() -> {denied(J.JBool{True{}}) == S.Bad{"expected [offer, revision, SDP]"} : S.Command}:
  {==}

def fields() -> List<&2, H.Header>:
  [H.Header{"Host", "fixture"}, H.Header{"Origin", "local"}, H.Header{"Cookie", "synthetic"}]

def authorize(path: String) -> Auth.Decision:
  Auth.authorize(Req.Request{M.MGet{}, path, fields(), []}, "fixture", "local", "synthetic")

def path_exact() -> {authorize("/signal") == Auth.Allowed{} : Auth.Decision}:
  {==}

def path_suffix() -> {authorize("/signalx") == Auth.BadRequest{} : Auth.Decision}:
  {==}

def path_case() -> {authorize("/Signal") == Auth.BadRequest{} : Auth.Decision}:
  {==}

def path_slash() -> {authorize("/signal/") == Auth.BadRequest{} : Auth.Decision}:
  {==}

def path_query() -> {authorize("/signal?x=1") == Auth.BadRequest{} : Auth.Decision}:
  {==}

def wrong_method() -> {Auth.authorize(Req.Request{M.MPost{}, "/signal", fields(), []}, "fixture", "local", "synthetic") == Auth.BadRequest{} : Auth.Decision}:
  {==}

def nonempty_body() -> {Auth.authorize(Req.Request{M.MGet{}, "/signal", fields(), [0]}, "fixture", "local", "synthetic") == Auth.BadRequest{} : Auth.Decision}:
  {==}

def path_precedence() -> {Auth.authorize(Req.Request{M.MGet{}, "/signalx", [], []}, "fixture", "local", "synthetic") == Auth.BadRequest{} : Auth.Decision}:
  {==}
