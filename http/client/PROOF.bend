import Base
import ./LAWS.bend as Laws
import ./client.bend as C
import ../wire/http1.bend as H1
import ../wire/LAWS.bend as WL
import ../wire/PROOF.bend as WP
import ../core/proof/text.bend as P
import ../../utf8/utf8.bend as U
import ../core/PROOF.bend as CP
import ../core/query.bend as Q

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

# Forms
# -----

# a form char's facts, one at a time

law fu:
  for +x: U32
  for +h: {Laws.form.ch(x) == True{} : Bool}
  {C.unreserved(x) == True{} : Bool}

def fu(x, h):
  P.and_true_l(C.unreserved(x), Bool.and(U32.is_lt(x, 128), Bool.and(Bool.not(U32.is_eq(x, 37)), Bool.and(Bool.not(U32.is_eq(x, 43)), Bool.and(Bool.not(U32.is_eq(x, 38)), Bool.not(U32.is_eq(x, 61)))))), h)

law f128:
  for +x: U32
  for +h: {Laws.form.ch(x) == True{} : Bool}
  {U32.is_lt(x, 128) == True{} : Bool}

def f128(x, h):
  P.and_true_l(U32.is_lt(x, 128), Bool.and(Bool.not(U32.is_eq(x, 37)), Bool.and(Bool.not(U32.is_eq(x, 43)), Bool.and(Bool.not(U32.is_eq(x, 38)), Bool.not(U32.is_eq(x, 61))))), P.and_true_r(C.unreserved(x), Bool.and(U32.is_lt(x, 128), Bool.and(Bool.not(U32.is_eq(x, 37)), Bool.and(Bool.not(U32.is_eq(x, 43)), Bool.and(Bool.not(U32.is_eq(x, 38)), Bool.not(U32.is_eq(x, 61)))))), h))

law f37:
  for +x: U32
  for +h: {Laws.form.ch(x) == True{} : Bool}
  {U32.is_eq(x, 37) == False{} : Bool}

def f37(x, h):
  P.not_true(U32.is_eq(x, 37), P.and_true_l(Bool.not(U32.is_eq(x, 37)), Bool.and(Bool.not(U32.is_eq(x, 43)), Bool.and(Bool.not(U32.is_eq(x, 38)), Bool.not(U32.is_eq(x, 61)))), P.and_true_r(U32.is_lt(x, 128), Bool.and(Bool.not(U32.is_eq(x, 37)), Bool.and(Bool.not(U32.is_eq(x, 43)), Bool.and(Bool.not(U32.is_eq(x, 38)), Bool.not(U32.is_eq(x, 61))))), P.and_true_r(C.unreserved(x), Bool.and(U32.is_lt(x, 128), Bool.and(Bool.not(U32.is_eq(x, 37)), Bool.and(Bool.not(U32.is_eq(x, 43)), Bool.and(Bool.not(U32.is_eq(x, 38)), Bool.not(U32.is_eq(x, 61)))))), h))))

law f43:
  for +x: U32
  for +h: {Laws.form.ch(x) == True{} : Bool}
  {U32.is_eq(x, 43) == False{} : Bool}

def f43(x, h):
  P.not_true(U32.is_eq(x, 43), P.and_true_l(Bool.not(U32.is_eq(x, 43)), Bool.and(Bool.not(U32.is_eq(x, 38)), Bool.not(U32.is_eq(x, 61))), P.and_true_r(Bool.not(U32.is_eq(x, 37)), Bool.and(Bool.not(U32.is_eq(x, 43)), Bool.and(Bool.not(U32.is_eq(x, 38)), Bool.not(U32.is_eq(x, 61)))), P.and_true_r(U32.is_lt(x, 128), Bool.and(Bool.not(U32.is_eq(x, 37)), Bool.and(Bool.not(U32.is_eq(x, 43)), Bool.and(Bool.not(U32.is_eq(x, 38)), Bool.not(U32.is_eq(x, 61))))), P.and_true_r(C.unreserved(x), Bool.and(U32.is_lt(x, 128), Bool.and(Bool.not(U32.is_eq(x, 37)), Bool.and(Bool.not(U32.is_eq(x, 43)), Bool.and(Bool.not(U32.is_eq(x, 38)), Bool.not(U32.is_eq(x, 61)))))), h)))))

law f38:
  for +x: U32
  for +h: {Laws.form.ch(x) == True{} : Bool}
  {U32.is_eq(x, 38) == False{} : Bool}

def f38(x, h):
  P.not_true(U32.is_eq(x, 38), P.and_true_l(Bool.not(U32.is_eq(x, 38)), Bool.not(U32.is_eq(x, 61)), P.and_true_r(Bool.not(U32.is_eq(x, 43)), Bool.and(Bool.not(U32.is_eq(x, 38)), Bool.not(U32.is_eq(x, 61))), P.and_true_r(Bool.not(U32.is_eq(x, 37)), Bool.and(Bool.not(U32.is_eq(x, 43)), Bool.and(Bool.not(U32.is_eq(x, 38)), Bool.not(U32.is_eq(x, 61)))), P.and_true_r(U32.is_lt(x, 128), Bool.and(Bool.not(U32.is_eq(x, 37)), Bool.and(Bool.not(U32.is_eq(x, 43)), Bool.and(Bool.not(U32.is_eq(x, 38)), Bool.not(U32.is_eq(x, 61))))), P.and_true_r(C.unreserved(x), Bool.and(U32.is_lt(x, 128), Bool.and(Bool.not(U32.is_eq(x, 37)), Bool.and(Bool.not(U32.is_eq(x, 43)), Bool.and(Bool.not(U32.is_eq(x, 38)), Bool.not(U32.is_eq(x, 61)))))), h))))))

law f61:
  for +x: U32
  for +h: {Laws.form.ch(x) == True{} : Bool}
  {U32.is_eq(x, 61) == False{} : Bool}

def f61(x, h):
  P.not_true(U32.is_eq(x, 61), P.and_true_r(Bool.not(U32.is_eq(x, 38)), Bool.not(U32.is_eq(x, 61)), P.and_true_r(Bool.not(U32.is_eq(x, 43)), Bool.and(Bool.not(U32.is_eq(x, 38)), Bool.not(U32.is_eq(x, 61))), P.and_true_r(Bool.not(U32.is_eq(x, 37)), Bool.and(Bool.not(U32.is_eq(x, 43)), Bool.and(Bool.not(U32.is_eq(x, 38)), Bool.not(U32.is_eq(x, 61)))), P.and_true_r(U32.is_lt(x, 128), Bool.and(Bool.not(U32.is_eq(x, 37)), Bool.and(Bool.not(U32.is_eq(x, 43)), Bool.and(Bool.not(U32.is_eq(x, 38)), Bool.not(U32.is_eq(x, 61))))), P.and_true_r(C.unreserved(x), Bool.and(U32.is_lt(x, 128), Bool.and(Bool.not(U32.is_eq(x, 37)), Bool.and(Bool.not(U32.is_eq(x, 43)), Bool.and(Bool.not(U32.is_eq(x, 38)), Bool.not(U32.is_eq(x, 61)))))), h))))))

def fw.go(kv: List<&2, Q.Param>) -> String:
  match kv:
    case Nil{}:
      ""
    case Con{Q.Param{+k, +v}, t}:
      SCon{'&', String.append(k, SCon{'=', String.append(v, fw.go(t))})}

# a form, written forward
def fw(kv: List<&2, Q.Param>) -> String:
  match kv:
    case Nil{}:
      ""
    case Con{Q.Param{+k, +v}, t}:
      String.append(k, SCon{'=', String.append(v, fw.go(t))})

def fwf(kv: List<&2, Q.Param>, first: Bool) -> String:
  match first:
    case True{}:
      fw(kv)
    case False{}:
      fw.go(kv)

def codes(s: String) -> List<&2, U32>:
  match s:
    case SNil{}:
      []
    case SCon{Chr{+x}, t}:
      Con{x, codes(t)}

# form_reads_back's plain chars are exactly the unreserved ones: no
# unreserved char is past ASCII, or %, +, & or =
def bool.same(a: Bool, b: Bool) -> Bool:
  match a:
    case True{}:
      b
    case False{}:
      Bool.not(b)

def form.ch.same(n: Nat, +x: U32) -> Bool:
  match n:
    case 0n:
      True{}
    case 1n+m:
      Bool.and(bool.same(Laws.form.ch(x), C.unreserved(x)), form.ch.same(m, (x + 1 : U32)))

law form_ch_unreserved:
  {form.ch.same(1024n, 0) == True{} : Bool}

def form_ch_unreserved():
  {==}

# a form's chars go out as they are
law enc_plain:
  for +s: String
  for +o: String
  for +h: {Laws.form.s(s) == True{} : Bool}
  {String.reverse.go(s, o) == C.enc.go(s, o) : String}

def enc_plain(s, o, h):
  match s:
    case SNil{}:
      {==}
    case SCon{Chr{+x}, t}:
      %Equal.sym(Bool, C.unreserved(x), True{}, fu(x, P.and_true_l(Laws.form.ch(x), Laws.form.s(t), h))) : {String.reverse.go(t, SCon{Chr{x}, o}) == C.enc.go(t, C.enc.char(_, U32.is_eq(x, 32), x, o)) : String}
      enc_plain(t, SCon{Chr{x}, o}, P.and_true_r(Laws.form.ch(x), Laws.form.s(t), h))

# the form the client writes is the pairs, forward
law form_enc:
  for +kv: List<&2, Q.Param>
  for +first: Bool
  for +out: String
  for +h: {Laws.form.plain(kv) == True{} : Bool}
  {C.form.go(Laws.kv.of(kv), first, out) == String.reverse.go(out, fwf(kv, first)) : String}

def form_enc(kv, first, out, h):
  match kv:
    case Nil{}:
      match first:
        case True{}:
          {==}
        case False{}:
          {==}
    case Con{Q.Param{+k, +v}, t}:
      match first:
        case True{}:
          %enc_plain(k, out, P.and_true_l(Laws.form.s(k), Bool.and(Laws.form.s(v), Laws.form.plain(t)), h)) : {C.form.go(Laws.kv.of(t), False{}, C.enc.go(v, SCon{'=', _})) == String.reverse.go(out, fwf(Con{Q.Param{k, v}, t}, True{})) : String}
          %enc_plain(v, SCon{'=', String.reverse.go(k, out)}, P.and_true_l(Laws.form.s(v), Laws.form.plain(t), P.and_true_r(Laws.form.s(k), Bool.and(Laws.form.s(v), Laws.form.plain(t)), h))) : {C.form.go(Laws.kv.of(t), False{}, _) == String.reverse.go(out, fwf(Con{Q.Param{k, v}, t}, True{})) : String}
          Equal.trans(String, C.form.go(Laws.kv.of(t), False{}, String.reverse.go(v, SCon{'=', String.reverse.go(k, out)})), String.reverse.go(String.reverse.go(v, SCon{'=', String.reverse.go(k, out)}), fw.go(t)), String.reverse.go(out, String.append(k, SCon{'=', String.append(v, fw.go(t))})), form_enc(t, False{}, String.reverse.go(v, SCon{'=', String.reverse.go(k, out)}), P.and_true_r(Laws.form.s(v), Laws.form.plain(t), P.and_true_r(Laws.form.s(k), Bool.and(Laws.form.s(v), Laws.form.plain(t)), h))), Equal.trans(String, String.reverse.go(String.reverse.go(v, SCon{'=', String.reverse.go(k, out)}), fw.go(t)), String.reverse.go(SCon{'=', String.reverse.go(k, out)}, String.append(v, fw.go(t))), String.reverse.go(out, String.append(k, SCon{'=', String.append(v, fw.go(t))})), CP.srev_rev(v, SCon{'=', String.reverse.go(k, out)}, fw.go(t)), CP.srev_rev(k, out, SCon{'=', String.append(v, fw.go(t))})))
        case False{}:
          %enc_plain(k, SCon{'&', out}, P.and_true_l(Laws.form.s(k), Bool.and(Laws.form.s(v), Laws.form.plain(t)), h)) : {C.form.go(Laws.kv.of(t), False{}, C.enc.go(v, SCon{'=', _})) == String.reverse.go(out, fwf(Con{Q.Param{k, v}, t}, False{})) : String}
          %enc_plain(v, SCon{'=', String.reverse.go(k, SCon{'&', out})}, P.and_true_l(Laws.form.s(v), Laws.form.plain(t), P.and_true_r(Laws.form.s(k), Bool.and(Laws.form.s(v), Laws.form.plain(t)), h))) : {C.form.go(Laws.kv.of(t), False{}, _) == String.reverse.go(out, fwf(Con{Q.Param{k, v}, t}, False{})) : String}
          Equal.trans(String, C.form.go(Laws.kv.of(t), False{}, String.reverse.go(v, SCon{'=', String.reverse.go(k, SCon{'&', out})})), String.reverse.go(String.reverse.go(v, SCon{'=', String.reverse.go(k, SCon{'&', out})}), fw.go(t)), String.reverse.go(SCon{'&', out}, String.append(k, SCon{'=', String.append(v, fw.go(t))})), form_enc(t, False{}, String.reverse.go(v, SCon{'=', String.reverse.go(k, SCon{'&', out})}), P.and_true_r(Laws.form.s(v), Laws.form.plain(t), P.and_true_r(Laws.form.s(k), Bool.and(Laws.form.s(v), Laws.form.plain(t)), h))), Equal.trans(String, String.reverse.go(String.reverse.go(v, SCon{'=', String.reverse.go(k, SCon{'&', out})}), fw.go(t)), String.reverse.go(SCon{'=', String.reverse.go(k, SCon{'&', out})}, String.append(v, fw.go(t))), String.reverse.go(SCon{'&', out}, String.append(k, SCon{'=', String.append(v, fw.go(t))})), CP.srev_rev(v, SCon{'=', String.reverse.go(k, SCon{'&', out})}, fw.go(t)), CP.srev_rev(k, SCon{'&', out}, SCon{'=', String.append(v, fw.go(t))})))

# a key's chars, then its =
law q_key:
  for +k: String
  for +R: String
  for +K: String
  for +V: String
  for +any: Bool
  for +acc: List<&2, Q.Param>
  for +h: {Laws.form.s(k) == True{} : Bool}
  {Q.parse.go(String.append(k, SCon{Chr{61}, R}), Q.QS{K, V, False{}, any, acc}) == Q.parse.go(R, Q.QS{String.reverse.go(k, K), V, True{}, True{}, acc}) : List<&2, Q.Param>}

def q_key(k, R, K, V, any, acc, h):
  match k:
    case SNil{}:
      {==}
    case SCon{Chr{+x}, t}:
      %Equal.sym(Bool, U32.is_eq(x, 38), False{}, f38(x, P.and_true_l(Laws.form.ch(x), Laws.form.s(t), h))) : {Q.parse.go(String.append(t, SCon{Chr{61}, R}), Q.step(_, U32.is_eq(x, 61), x, Q.QS{K, V, False{}, any, acc})) == Q.parse.go(R, Q.QS{String.reverse.go(t, SCon{Chr{x}, K}), V, True{}, True{}, acc}) : List<&2, Q.Param>}
      %Equal.sym(Bool, U32.is_eq(x, 61), False{}, f61(x, P.and_true_l(Laws.form.ch(x), Laws.form.s(t), h))) : {Q.parse.go(String.append(t, SCon{Chr{61}, R}), Q.step(False{}, _, x, Q.QS{K, V, False{}, any, acc})) == Q.parse.go(R, Q.QS{String.reverse.go(t, SCon{Chr{x}, K}), V, True{}, True{}, acc}) : List<&2, Q.Param>}
      q_key(t, R, SCon{Chr{x}, K}, V, True{}, acc, P.and_true_r(Laws.form.ch(x), Laws.form.s(t), h))

# a value's chars
law q_val:
  for +v: String
  for +R: String
  for +K: String
  for +V: String
  for +acc: List<&2, Q.Param>
  for +h: {Laws.form.s(v) == True{} : Bool}
  {Q.parse.go(String.append(v, R), Q.QS{K, V, True{}, True{}, acc}) == Q.parse.go(R, Q.QS{K, String.reverse.go(v, V), True{}, True{}, acc}) : List<&2, Q.Param>}

def q_val(v, R, K, V, acc, h):
  match v:
    case SNil{}:
      {==}
    case SCon{Chr{+x}, t}:
      %Equal.sym(Bool, U32.is_eq(x, 38), False{}, f38(x, P.and_true_l(Laws.form.ch(x), Laws.form.s(t), h))) : {Q.parse.go(String.append(t, R), Q.step(_, U32.is_eq(x, 61), x, Q.QS{K, V, True{}, True{}, acc})) == Q.parse.go(R, Q.QS{K, String.reverse.go(t, SCon{Chr{x}, V}), True{}, True{}, acc}) : List<&2, Q.Param>}
      q_val(t, R, K, SCon{Chr{x}, V}, acc, P.and_true_r(Laws.form.ch(x), Laws.form.s(t), h))

law lapp_nil_u:
  for +a: List<&2, U32>
  {List.append(&2, U32, a, []) == a : List<&2, U32>}

def lapp_nil_u(a):
  match a:
    case Nil{}:
      {==}
    case Con{+x, t}:
      Equal.cong(List<&2, U32>, List<&2, U32>, y => Con{x, y}, List.append(&2, U32, t, []), t, lapp_nil_u(t))

law lrev_rev_u:
  for +a: List<&2, U32>
  for +b: List<&2, U32>
  for +c: List<&2, U32>
  {List.reverse.go(&2, U32, List.reverse.go(&2, U32, a, b), c) == List.reverse.go(&2, U32, b, List.append(&2, U32, a, c)) : List<&2, U32>}

def lrev_rev_u(a, b, c):
  match a:
    case Nil{}:
      {==}
    case Con{+x, t}:
      lrev_rev_u(t, Con{x, b}, c)

law lrevrev_u:
  for +a: List<&2, U32>
  {List.reverse(&2, U32, List.reverse.go(&2, U32, a, [])) == a : List<&2, U32>}

def lrevrev_u(a):
  Equal.trans(List<&2, U32>, List.reverse.go(&2, U32, List.reverse.go(&2, U32, a, []), []), List.append(&2, U32, a, []), a, lrev_rev_u(a, [], []), lapp_nil_u(a))

law lapp_nil_p:
  for +a: List<&2, Q.Param>
  {List.append(&2, Q.Param, a, []) == a : List<&2, Q.Param>}

def lapp_nil_p(a):
  match a:
    case Nil{}:
      {==}
    case Con{+x, t}:
      Equal.cong(List<&2, Q.Param>, List<&2, Q.Param>, y => Con{x, y}, List.append(&2, Q.Param, t, []), t, lapp_nil_p(t))

law lrev_rev_p:
  for +a: List<&2, Q.Param>
  for +b: List<&2, Q.Param>
  for +c: List<&2, Q.Param>
  {List.reverse.go(&2, Q.Param, List.reverse.go(&2, Q.Param, a, b), c) == List.reverse.go(&2, Q.Param, b, List.append(&2, Q.Param, a, c)) : List<&2, Q.Param>}

def lrev_rev_p(a, b, c):
  match a:
    case Nil{}:
      {==}
    case Con{+x, t}:
      lrev_rev_p(t, Con{x, b}, c)

law lrevrev_p:
  for +a: List<&2, Q.Param>
  {List.reverse(&2, Q.Param, List.reverse.go(&2, Q.Param, a, [])) == a : List<&2, Q.Param>}

def lrevrev_p(a):
  Equal.trans(List<&2, Q.Param>, List.reverse.go(&2, Q.Param, List.reverse.go(&2, Q.Param, a, []), []), List.append(&2, Q.Param, a, []), a, lrev_rev_p(a, [], []), lapp_nil_p(a))

# a component's plain chars are its bytes
law q_bytes:
  for +s: String
  for +out: List<&2, U32>
  for +h: {Laws.form.s(s) == True{} : Bool}
  {Q.bytes.go(s, Q.BO{Q.N{}, out}) == List.reverse(&2, U32, List.reverse.go(&2, U32, codes(s), out)) : List<&2, U32>}

def q_bytes(s, out, h):
  match s:
    case SNil{}:
      {==}
    case SCon{Chr{+x}, t}:
      %Equal.sym(Bool, U32.is_eq(x, 37), False{}, f37(x, P.and_true_l(Laws.form.ch(x), Laws.form.s(t), h))) : {Q.bytes.go(t, Q.b.norm(_, U32.is_eq(x, 43), x, out)) == List.reverse(&2, U32, List.reverse.go(&2, U32, codes(t), Con{x, out})) : List<&2, U32>}
      %Equal.sym(Bool, U32.is_eq(x, 43), False{}, f43(x, P.and_true_l(Laws.form.ch(x), Laws.form.s(t), h))) : {Q.bytes.go(t, Q.b.norm(False{}, _, x, out)) == List.reverse(&2, U32, List.reverse.go(&2, U32, codes(t), Con{x, out})) : List<&2, U32>}
      %Equal.sym(Bool, U32.is_lt(x, 128), True{}, f128(x, P.and_true_l(Laws.form.ch(x), Laws.form.s(t), h))) : {Q.bytes.go(t, Q.BO{Q.N{}, U.enc.width(_, U32.is_lt(x, 2048), U32.is_lt(x, 65536), x, out)}) == List.reverse(&2, U32, List.reverse.go(&2, U32, codes(t), Con{x, out})) : List<&2, U32>}
      q_bytes(t, Con{x, out}, P.and_true_r(Laws.form.ch(x), Laws.form.s(t), h))

# ASCII bytes decode to their chars
law q_utf8:
  for +s: String
  for +at: U32
  for +out: String
  for +h: {Laws.form.s(s) == True{} : Bool}
  {U.decode.go(codes(s), U.U8{0, 0, 128, 191, at, out}) == U.TOk{String.reverse(String.reverse.go(s, out))} : U.Text}

def q_utf8(s, at, out, h):
  match s:
    case SNil{}:
      {==}
    case SCon{Chr{+x}, t}:
      %Equal.sym(Bool, U32.is_lt(x, 128), True{}, f128(x, P.and_true_l(Laws.form.ch(x), Laws.form.s(t), h))) : {U.decode.go(codes(t), U.u8.start(_, x, at, out)) == U.TOk{String.reverse(String.reverse.go(t, SCon{Chr{x}, out}))} : U.Text}
      q_utf8(t, (at + 1 : U32), SCon{Chr{x}, out}, P.and_true_r(Laws.form.ch(x), Laws.form.s(t), h))

law q_decode:
  for +s: String
  for +h: {Laws.form.s(s) == True{} : Bool}
  {Q.decode(s) == s : String}

def q_decode(s, h):
  Equal.trans(String, Q.decode(s), Q.text.of(U.decode(codes(s))), s, Equal.cong(List<&2, U32>, String, x => Q.text.of(U.decode(x)), Q.bytes.go(s, Q.BO{Q.N{}, []}), codes(s), Equal.trans(List<&2, U32>, Q.bytes.go(s, Q.BO{Q.N{}, []}), List.reverse(&2, U32, List.reverse.go(&2, U32, codes(s), [])), codes(s), q_bytes(s, [], h), lrevrev_u(codes(s)))), Equal.trans(String, Q.text.of(U.decode(codes(s))), String.reverse(String.reverse.go(s, "")), s, Equal.cong(U.Text, String, x => Q.text.of(x), U.decode.go(codes(s), U.U8{0, 0, 128, 191, 0, ""}), U.TOk{String.reverse(String.reverse.go(s, ""))}, q_utf8(s, 0, "", h)), CP.revrev(s)))

law q_dk:
  for +s: String
  for +h: {Laws.form.s(s) == True{} : Bool}
  {s == Q.decode(String.reverse(String.reverse.go(s, ""))) : String}

def q_dk(s, h):
  Equal.sym(String, Q.decode(String.reverse(String.reverse.go(s, ""))), s, Equal.trans(String, Q.decode(String.reverse(String.reverse.go(s, ""))), Q.decode(s), s, Equal.cong(String, String, x => Q.decode(x), String.reverse(String.reverse.go(s, "")), s, CP.revrev(s)), q_decode(s, h)))

# a pair read back is the pair
law q_emit:
  for +k: String
  for +v: String
  for +t: List<&2, Q.Param>
  for +acc: List<&2, Q.Param>
  for +hk: {Laws.form.s(k) == True{} : Bool}
  for +hv: {Laws.form.s(v) == True{} : Bool}
  {List.reverse(&2, Q.Param, List.reverse.go(&2, Q.Param, t, Q.emit(True{}, String.reverse.go(k, ""), String.reverse.go(v, ""), acc))) == List.reverse(&2, Q.Param, List.reverse.go(&2, Q.Param, t, Con{Q.Param{k, v}, acc})) : List<&2, Q.Param>}

def q_emit(k, v, t, acc, hk, hv):
  %q_dk(k, hk) : {List.reverse(&2, Q.Param, List.reverse.go(&2, Q.Param, t, Con{Q.Param{_, Q.decode(String.reverse(String.reverse.go(v, "")))}, acc})) == List.reverse(&2, Q.Param, List.reverse.go(&2, Q.Param, t, Con{Q.Param{k, v}, acc})) : List<&2, Q.Param>}
  %q_dk(v, hv) : {List.reverse(&2, Q.Param, List.reverse.go(&2, Q.Param, t, Con{Q.Param{k, _}, acc})) == List.reverse(&2, Q.Param, List.reverse.go(&2, Q.Param, t, Con{Q.Param{k, v}, acc})) : List<&2, Q.Param>}
  {==}

# the pairs after the first, each after its &
law q_pg:
  for +t: List<&2, Q.Param>
  for +K: String
  for +V: String
  for +acc: List<&2, Q.Param>
  for +h: {Laws.form.plain(t) == True{} : Bool}
  {Q.parse.go(fw.go(t), Q.QS{K, V, True{}, True{}, acc}) == List.reverse(&2, Q.Param, List.reverse.go(&2, Q.Param, t, Q.emit(True{}, K, V, acc))) : List<&2, Q.Param>}

def q_pg(u, K, V, acc, h):
  match u:
    case Nil{}:
      {==}
    case Con{Q.Param{+k, +v}, t}:
      Equal.trans(List<&2, Q.Param>, Q.parse.go(String.append(k, SCon{Chr{61}, String.append(v, fw.go(t))}), Q.QS{"", "", False{}, False{}, Q.emit(True{}, K, V, acc)}), Q.parse.go(String.append(v, fw.go(t)), Q.QS{String.reverse.go(k, ""), "", True{}, True{}, Q.emit(True{}, K, V, acc)}), List.reverse(&2, Q.Param, List.reverse.go(&2, Q.Param, t, Con{Q.Param{k, v}, Q.emit(True{}, K, V, acc)})), q_key(k, String.append(v, fw.go(t)), "", "", False{}, Q.emit(True{}, K, V, acc), P.and_true_l(Laws.form.s(k), Bool.and(Laws.form.s(v), Laws.form.plain(t)), h)), Equal.trans(List<&2, Q.Param>, Q.parse.go(String.append(v, fw.go(t)), Q.QS{String.reverse.go(k, ""), "", True{}, True{}, Q.emit(True{}, K, V, acc)}), Q.parse.go(fw.go(t), Q.QS{String.reverse.go(k, ""), String.reverse.go(v, ""), True{}, True{}, Q.emit(True{}, K, V, acc)}), List.reverse(&2, Q.Param, List.reverse.go(&2, Q.Param, t, Con{Q.Param{k, v}, Q.emit(True{}, K, V, acc)})), q_val(v, fw.go(t), String.reverse.go(k, ""), "", Q.emit(True{}, K, V, acc), P.and_true_l(Laws.form.s(v), Laws.form.plain(t), P.and_true_r(Laws.form.s(k), Bool.and(Laws.form.s(v), Laws.form.plain(t)), h))), Equal.trans(List<&2, Q.Param>, Q.parse.go(fw.go(t), Q.QS{String.reverse.go(k, ""), String.reverse.go(v, ""), True{}, True{}, Q.emit(True{}, K, V, acc)}), List.reverse(&2, Q.Param, List.reverse.go(&2, Q.Param, t, Q.emit(True{}, String.reverse.go(k, ""), String.reverse.go(v, ""), Q.emit(True{}, K, V, acc)))), List.reverse(&2, Q.Param, List.reverse.go(&2, Q.Param, t, Con{Q.Param{k, v}, Q.emit(True{}, K, V, acc)})), q_pg(t, String.reverse.go(k, ""), String.reverse.go(v, ""), Q.emit(True{}, K, V, acc), P.and_true_r(Laws.form.s(v), Laws.form.plain(t), P.and_true_r(Laws.form.s(k), Bool.and(Laws.form.s(v), Laws.form.plain(t)), h))), q_emit(k, v, t, Q.emit(True{}, K, V, acc), P.and_true_l(Laws.form.s(k), Bool.and(Laws.form.s(v), Laws.form.plain(t)), h), P.and_true_l(Laws.form.s(v), Laws.form.plain(t), P.and_true_r(Laws.form.s(k), Bool.and(Laws.form.s(v), Laws.form.plain(t)), h))))))

law q_top:
  for +kv: List<&2, Q.Param>
  for +h: {Laws.form.plain(kv) == True{} : Bool}
  {Q.parse(fw(kv)) == kv : List<&2, Q.Param>}

def q_top(kv, h):
  match kv:
    case Nil{}:
      {==}
    case Con{Q.Param{+k, +v}, t}:
      Equal.trans(List<&2, Q.Param>, Q.parse.go(String.append(k, SCon{Chr{61}, String.append(v, fw.go(t))}), Q.QS{"", "", False{}, False{}, []}), List.reverse(&2, Q.Param, List.reverse.go(&2, Q.Param, Con{Q.Param{k, v}, t}, [])), Con{Q.Param{k, v}, t}, Equal.trans(List<&2, Q.Param>, Q.parse.go(String.append(k, SCon{Chr{61}, String.append(v, fw.go(t))}), Q.QS{"", "", False{}, False{}, []}), Q.parse.go(String.append(v, fw.go(t)), Q.QS{String.reverse.go(k, ""), "", True{}, True{}, []}), List.reverse(&2, Q.Param, List.reverse.go(&2, Q.Param, t, Con{Q.Param{k, v}, []})), q_key(k, String.append(v, fw.go(t)), "", "", False{}, [], P.and_true_l(Laws.form.s(k), Bool.and(Laws.form.s(v), Laws.form.plain(t)), h)), Equal.trans(List<&2, Q.Param>, Q.parse.go(String.append(v, fw.go(t)), Q.QS{String.reverse.go(k, ""), "", True{}, True{}, []}), Q.parse.go(fw.go(t), Q.QS{String.reverse.go(k, ""), String.reverse.go(v, ""), True{}, True{}, []}), List.reverse(&2, Q.Param, List.reverse.go(&2, Q.Param, t, Con{Q.Param{k, v}, []})), q_val(v, fw.go(t), String.reverse.go(k, ""), "", [], P.and_true_l(Laws.form.s(v), Laws.form.plain(t), P.and_true_r(Laws.form.s(k), Bool.and(Laws.form.s(v), Laws.form.plain(t)), h))), Equal.trans(List<&2, Q.Param>, Q.parse.go(fw.go(t), Q.QS{String.reverse.go(k, ""), String.reverse.go(v, ""), True{}, True{}, []}), List.reverse(&2, Q.Param, List.reverse.go(&2, Q.Param, t, Q.emit(True{}, String.reverse.go(k, ""), String.reverse.go(v, ""), []))), List.reverse(&2, Q.Param, List.reverse.go(&2, Q.Param, t, Con{Q.Param{k, v}, []})), q_pg(t, String.reverse.go(k, ""), String.reverse.go(v, ""), [], P.and_true_r(Laws.form.s(v), Laws.form.plain(t), P.and_true_r(Laws.form.s(k), Bool.and(Laws.form.s(v), Laws.form.plain(t)), h))), q_emit(k, v, t, [], P.and_true_l(Laws.form.s(k), Bool.and(Laws.form.s(v), Laws.form.plain(t)), h), P.and_true_l(Laws.form.s(v), Laws.form.plain(t), P.and_true_r(Laws.form.s(k), Bool.and(Laws.form.s(v), Laws.form.plain(t)), h)))))), lrevrev_p(Con{Q.Param{k, v}, t}))

def Laws.form_reads_back(kv, e):
  Equal.trans(List<&2, Q.Param>, Q.parse(C.form.enc(Laws.kv.of(kv))), Q.parse(fw(kv)), kv, Equal.cong(String, List<&2, Q.Param>, x => Q.parse(x), C.form.go(Laws.kv.of(kv), True{}, ""), fw(kv), form_enc(kv, True{}, "", e)), q_top(kv, e))
