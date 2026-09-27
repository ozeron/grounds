import Base
import ./LAWS.bend as Laws
import ./client.bend as C
import ../wire/http1.bend as H1
import ../wire/LAWS.bend as WL
import ../wire/PROOF.bend as WP
import ../core/proof/text.bend as P

def is_url(u: C.Url) -> Bool:
  match u:
    case C.Url{_, _, _, _, _}:
      True{}
    case C.UBad{_}:
      False{}

def target_of(u: C.Url) -> String:
  match u:
    case C.Url{_, _, _, t, _}:
      t
    case C.UBad{_}:
      ""

def authority_of(u: C.Url) -> String:
  match u:
    case C.Url{_, _, _, _, a}:
      a
    case C.UBad{_}:
      ""

law final_target:
  for +bad: Bool
  for +tls: Bool
  for +h: String
  for +p: U32
  for +t: String
  for +a: String
  for +tls2: Bool
  for +h2: String
  for +p2: U32
  for +t2: String
  for +a2: String
  for +eb: {Bool.or(H1.unsafe(t, False{}), H1.unsafe(a, False{})) == bad : Bool}
  for +e: {C.url.final(bad, tls, h, p, t, a) == C.Url{tls2, h2, p2, t2, a2} : C.Url}
  {H1.unsafe(t2, False{}) == False{} : Bool}

def final_target(bad, tls, h, p, t, a, tls2, h2, p2, t2, a2, eb, e):
  match bad:
    case True{}:
      P.absurd({H1.unsafe(t2, False{}) == False{} : Bool}, Equal.cong(C.Url, Bool, is_url, C.UBad{C.BadUrl{}}, C.Url{tls2, h2, p2, t2, a2}, e))
    case False{}:
      %Equal.cong(C.Url, String, target_of, C.Url{tls, h, p, t, a}, C.Url{tls2, h2, p2, t2, a2}, e) : {H1.unsafe(_, False{}) == False{} : Bool}
      P.or_false_l(H1.unsafe(t, False{}), H1.unsafe(a, False{}), eb)

law final_authority:
  for +bad: Bool
  for +tls: Bool
  for +h: String
  for +p: U32
  for +t: String
  for +a: String
  for +tls2: Bool
  for +h2: String
  for +p2: U32
  for +t2: String
  for +a2: String
  for +eb: {Bool.or(H1.unsafe(t, False{}), H1.unsafe(a, False{})) == bad : Bool}
  for +e: {C.url.final(bad, tls, h, p, t, a) == C.Url{tls2, h2, p2, t2, a2} : C.Url}
  {H1.unsafe(a2, False{}) == False{} : Bool}

def final_authority(bad, tls, h, p, t, a, tls2, h2, p2, t2, a2, eb, e):
  match bad:
    case True{}:
      P.absurd({H1.unsafe(a2, False{}) == False{} : Bool}, Equal.cong(C.Url, Bool, is_url, C.UBad{C.BadUrl{}}, C.Url{tls2, h2, p2, t2, a2}, e))
    case False{}:
      %Equal.cong(C.Url, String, authority_of, C.Url{tls, h, p, t, a}, C.Url{tls2, h2, p2, t2, a2}, e) : {H1.unsafe(_, False{}) == False{} : Bool}
      P.or_false_r(H1.unsafe(t, False{}), H1.unsafe(a, False{}), eb)

def Laws.check_target(u, tls2, h2, p2, t2, a2, e):
  match u:
    case C.Url{+tls, h, +p, +t, +a}:
      final_target(Bool.or(H1.unsafe(t, False{}), H1.unsafe(a, False{})), tls, h, p, t, a, tls2, h2, p2, t2, a2, {==}, e)
    case C.UBad{x}:
      P.absurd({H1.unsafe(t2, False{}) == False{} : Bool}, Equal.cong(C.Url, Bool, is_url, C.UBad{x}, C.Url{tls2, h2, p2, t2, a2}, e))

def Laws.check_authority(u, tls2, h2, p2, t2, a2, e):
  match u:
    case C.Url{+tls, h, +p, +t, +a}:
      final_authority(Bool.or(H1.unsafe(t, False{}), H1.unsafe(a, False{})), tls, h, p, t, a, tls2, h2, p2, t2, a2, {==}, e)
    case C.UBad{x}:
      P.absurd({H1.unsafe(a2, False{}) == False{} : Bool}, Equal.cong(C.Url, Bool, is_url, C.UBad{x}, C.Url{tls2, h2, p2, t2, a2}, e))

def Laws.url_target(s, tls, h, p, t, a, e):
  Laws.check_target(C.url.raw(s), tls, h, p, t, a, e)

def Laws.url_authority(s, tls, h, p, t, a, e):
  Laws.check_authority(C.url.raw(s), tls, h, p, t, a, e)

def is_some(m: Maybe<&2, C.Verb>) -> Bool:
  match m:
    case Some{_}:
      True{}
    case None{}:
      False{}

def name_of(m: Maybe<&2, C.Verb>) -> String:
  match m:
    case Some{C.Verb{n, _, _, _}}:
      n
    case None{}:
      ""

law final_name:
  for +ok: Bool
  for +n0: String
  for +h0: Bool
  for +z0: Bool
  for +g0: Bool
  for +n: String
  for +hd: Bool
  for +z: Bool
  for +g: Bool
  for +eo: {Bool.and(Bool.not(H1.unsafe(n0, False{})), H1.is_token.s(n0)) == ok : Bool}
  for +e: {C.verb.final(ok, n0, h0, z0, g0) == Some{C.Verb{n, hd, z, g}} : Maybe<&2, C.Verb>}
  {H1.unsafe(n, False{}) == False{} : Bool}

def final_name(ok, n0, h0, z0, g0, n, hd, z, g, eo, e):
  match ok:
    case False{}:
      P.absurd({H1.unsafe(n, False{}) == False{} : Bool}, Equal.cong(Maybe<&2, C.Verb>, Bool, is_some, None{}, Some{C.Verb{n, hd, z, g}}, e))
    case True{}:
      %Equal.cong(Maybe<&2, C.Verb>, String, name_of, Some{C.Verb{n0, h0, z0, g0}}, Some{C.Verb{n, hd, z, g}}, e) : {H1.unsafe(_, False{}) == False{} : Bool}
      P.not_true(H1.unsafe(n0, False{}), P.and_true_l(Bool.not(H1.unsafe(n0, False{})), H1.is_token.s(n0), eo))

def Laws.method_clean(v, n, hd, z, g, e):
  match v:
    case C.Verb{+n0, +h0, +z0, +g0}:
      final_name(Bool.and(Bool.not(H1.unsafe(n0, False{})), H1.is_token.s(n0)), n0, h0, z0, g0, n, hd, z, g, {==}, e)

def Laws.request_safe(m, s, hs, len, sized, close, n, hd, z, g, tls, host, p, t, a, ev, eu):
  WL.request_head(n, t, a, hs, len, sized, close, Laws.method_clean(C.verb(m), n, hd, z, g, ev), Laws.url_target(s, tls, host, p, t, a, eu), Laws.url_authority(s, tls, host, p, t, a, eu))
