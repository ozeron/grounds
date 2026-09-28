import Base
import ./LAWS.bend as Laws
import ./headers.bend as H
import ./query.bend as Q
import ./text.bend as T
import ./event.bend as Ev
import ./cookie.bend as Ck
import ../../utf8/utf8.bend as U
import ./proof/text.bend as P

law keep_found:
  for +hit: Bool
  for +w: String
  for +v: String
  {H.keep(hit, w, Some{v}) == Some{v} : Maybe<&2, String>}

def keep_found(hit, w, v):
  match hit:
    case True{}:
      {==}
    case False{}:
      {==}

# once found, the first value stays
law get_found:
  for +hs: List<&2, H.Header>
  for +n: String
  for +v: String
  {H.get.go(hs, n, Some{v}) == Some{v} : Maybe<&2, String>}

def get_found(hs, n, v):
  match hs:
    case Nil{}:
      {==}
    case Con{H.Header{k, w}, t}:
      %Equal.sym(Maybe<&2, String>, H.keep(H.name_eq(k, n, True{}), w, Some{v}), Some{v}, keep_found(H.name_eq(k, n, True{}), w, v)) : {H.get.go(t, n, _) == Some{v} : Maybe<&2, String>}
      get_found(t, n, v)

def Laws.same_ci(a, b):
  P.same_ci_lows(a, b, True{})

def Laws.header_first(n, m, v, hs, e):
  %Equal.sym(Bool, H.name_eq(n, m, True{}), T.same(P.lows(n), P.lows(m), True{}), P.name_eq_lows(n, m, True{})) : {H.get.go(hs, m, H.keep(_, v, None{})) == Some{v} : Maybe<&2, String>}
  %Equal.sym(Bool, T.same(P.lows(n), P.lows(m), True{}), True{}, e) : {H.get.go(hs, m, H.keep(_, v, None{})) == Some{v} : Maybe<&2, String>}
  get_found(hs, m, v)

law q_same_refl:
  for +s: String
  for +ok: Bool
  {Q.same(s, s, ok) == ok : Bool}

def q_same_refl(s, ok):
  match s:
    case SNil{}:
      {==}
    case SCon{c, t}:
      %Equal.sym(Bool, Char.is_eq(c, c), True{}, P.char_refl(c)) : {Q.same(t, t, Bool.and(ok, _)) == ok : Bool}
      %Equal.sym(Bool, Bool.and(ok, True{}), ok, P.and_true(ok)) : {Q.same(t, t, _) == ok : Bool}
      q_same_refl(t, ok)

law q_keep_found:
  for +hit: Bool
  for +w: String
  for +v: String
  {Q.get.keep(hit, w, Some{v}) == Some{v} : Maybe<&2, String>}

def q_keep_found(hit, w, v):
  match hit:
    case True{}:
      {==}
    case False{}:
      {==}

law q_get_found:
  for +ps: List<&2, Q.Param>
  for +k: String
  for +v: String
  {Q.get.go(ps, k, Some{v}) == Some{v} : Maybe<&2, String>}

def q_get_found(ps, k, v):
  match ps:
    case Nil{}:
      {==}
    case Con{Q.Param{a, w}, t}:
      %Equal.sym(Maybe<&2, String>, Q.get.keep(Q.same(a, k, True{}), w, Some{v}), Some{v}, q_keep_found(Q.same(a, k, True{}), w, v)) : {Q.get.go(t, k, _) == Some{v} : Maybe<&2, String>}
      q_get_found(t, k, v)

def Laws.query_first(k, v, ps):
  %Equal.sym(Bool, Q.same(k, k, True{}), True{}, q_same_refl(k, True{})) : {Q.get.go(ps, k, Q.get.keep(_, v, None{})) == Some{v} : Maybe<&2, String>}
  q_get_found(ps, k, v)

law line_safe_clean:
  for +bad: Bool
  for +b: U32
  for +tail: String
  for same: {Ck.line_byte(b) == bad : Bool}
  for clean: {Ck.no_crlf(tail) == True{} : Bool}
  {Ck.no_crlf(Ck.line_safe(bad, b, tail)) == True{} : Bool}

def line_safe_clean(bad, b, tail, same, clean):
  match bad:
    case True{}:
      clean
    case False{}:
      %Equal.sym(Bool, Ck.line_byte(b), False{}, same) : {Bool.and(Bool.not(_), Ck.no_crlf(tail)) == True{} : Bool}
      %Equal.sym(Bool, Ck.no_crlf(tail), True{}, clean) : {Bool.and(Bool.not(False{}), _) == True{} : Bool}
      {==}

law without_lines_clean:
  for +s: String
  {Ck.no_crlf(Ck.without_lines(s)) == True{} : Bool}

def without_lines_clean(s):
  match s:
    case SNil{}:
      {==}
    case SCon{Chr{+b}, t}:
      line_safe_clean(Ck.line_byte(b), b, Ck.without_lines(t), {==}, without_lines_clean(t))

def Laws.set_cookie_clean(name, value):
  without_lines_clean(Ck.escape.to(U.encode(name), True{}, SCon{'=', Ck.escape.to(U.encode(value), False{}, "; Path=/; HttpOnly; Secure; SameSite=Lax")}))

# Server-sent events
# ------------------

law sapp_assoc:
  for +a: String
  for +b: String
  for +c: String
  {String.append(String.append(a, b), c) == String.append(a, String.append(b, c)) : String}

def sapp_assoc(a, b, c):
  match a:
    case SNil{}:
      {==}
    case SCon{+x, t}:
      Equal.cong(String, String, y => SCon{x, y}, String.append(String.append(t, b), c), String.append(t, String.append(b, c)), sapp_assoc(t, b, c))

law sapp_nil:
  for +a: String
  {String.append(a, "") == a : String}

def sapp_nil(a):
  match a:
    case SNil{}:
      {==}
    case SCon{+x, t}:
      Equal.cong(String, String, y => SCon{x, y}, String.append(t, ""), t, sapp_nil(t))

law srev_rev:
  for +a: String
  for +b: String
  for +c: String
  {String.reverse.go(String.reverse.go(a, b), c) == String.reverse.go(b, String.append(a, c)) : String}

def srev_rev(a, b, c):
  match a:
    case SNil{}:
      {==}
    case SCon{+x, t}:
      srev_rev(t, SCon{x, b}, c)

# a String reversed twice is itself
law revrev:
  for +s: String
  {String.reverse(String.reverse.go(s, "")) == s : String}

def revrev(s):
  Equal.trans(String, String.reverse.go(String.reverse.go(s, ""), ""), String.append(s, ""), s, srev_rev(s, "", ""), sapp_nil(s))

law sdup:
  for +s: String
  for +a: String
  for +b: String
  {Ev.s.dup(s, a, b) == Ev.M2{Some{String.reverse(String.reverse.go(s, a))}, Some{String.reverse(String.reverse.go(s, b))}} : Ev.M2}

def sdup(s, a, b):
  match s:
    case SNil{}:
      {==}
    case SCon{Chr{+x}, t}:
      sdup(t, SCon{Chr{x}, a}, SCon{Chr{x}, b})

law mdup:
  for +m: Maybe<&2, String>
  {Ev.m.dup(m) == Ev.M2{m, m} : Ev.M2}

def mdup(m):
  match m:
    case Some{+s}:
      %revrev(s) : {Ev.s.dup(s, "", "") == Ev.M2{Some{_}, Some{_}} : Ev.M2}
      sdup(s, "", "")
    case None{}:
      {==}

# a name's or an id's chars go to the field's value
law val2:
  for +s: String
  for +R: String
  for +v: String
  for +e: Ev.Evs
  for +evs: List<&2, Ev.Message>
  for +h: {Laws.line.clean(s) == True{} : Bool}
  {Ev.feed.go(String.append(s, R), Ev.Fed{Ev.P{Ev.Ln{2, "", 2, v}, e, False{}, True{}}, evs}) == Ev.feed.go(R, Ev.Fed{Ev.P{Ev.Ln{2, "", 2, String.reverse.go(s, v)}, e, False{}, True{}}, evs}) : Ev.Fed}

def val2(s, R, v, e, evs, h):
  match s:
    case SNil{}:
      {==}
    case SCon{Chr{+x}, t}:
      %Equal.sym(Bool, U32.is_eq(x, 10), False{}, P.not_true(U32.is_eq(x, 10), P.and_true_l(Bool.not(U32.is_eq(x, 10)), Bool.not(U32.is_eq(x, 13)), P.and_true_l(Bool.and(Bool.not(U32.is_eq(x, 10)), Bool.not(U32.is_eq(x, 13))), Laws.line.clean(t), h)))) : {Ev.feed.go(String.append(t, R), Ev.char(_, U32.is_eq(x, 13), x, Ev.P{Ev.Ln{2, "", 2, v}, e, False{}, True{}}, evs)) == Ev.feed.go(R, Ev.Fed{Ev.P{Ev.Ln{2, "", 2, String.reverse.go(t, SCon{Chr{x}, v})}, e, False{}, True{}}, evs}) : Ev.Fed}
      %Equal.sym(Bool, U32.is_eq(x, 13), False{}, P.not_true(U32.is_eq(x, 13), P.and_true_r(Bool.not(U32.is_eq(x, 10)), Bool.not(U32.is_eq(x, 13)), P.and_true_l(Bool.and(Bool.not(U32.is_eq(x, 10)), Bool.not(U32.is_eq(x, 13))), Laws.line.clean(t), h)))) : {Ev.feed.go(String.append(t, R), Ev.char(False{}, _, x, Ev.P{Ev.Ln{2, "", 2, v}, e, False{}, True{}}, evs)) == Ev.feed.go(R, Ev.Fed{Ev.P{Ev.Ln{2, "", 2, String.reverse.go(t, SCon{Chr{x}, v})}, e, False{}, True{}}, evs}) : Ev.Fed}
      val2(t, R, SCon{Chr{x}, v}, e, evs, P.and_true_r(Bool.and(Bool.not(U32.is_eq(x, 10)), Bool.not(U32.is_eq(x, 13))), Laws.line.clean(t), h))

# a name's or an id's chars go to the field's value
law val3:
  for +s: String
  for +R: String
  for +v: String
  for +e: Ev.Evs
  for +evs: List<&2, Ev.Message>
  for +h: {Laws.line.clean(s) == True{} : Bool}
  {Ev.feed.go(String.append(s, R), Ev.Fed{Ev.P{Ev.Ln{2, "", 3, v}, e, False{}, True{}}, evs}) == Ev.feed.go(R, Ev.Fed{Ev.P{Ev.Ln{2, "", 3, String.reverse.go(s, v)}, e, False{}, True{}}, evs}) : Ev.Fed}

def val3(s, R, v, e, evs, h):
  match s:
    case SNil{}:
      {==}
    case SCon{Chr{+x}, t}:
      %Equal.sym(Bool, U32.is_eq(x, 10), False{}, P.not_true(U32.is_eq(x, 10), P.and_true_l(Bool.not(U32.is_eq(x, 10)), Bool.not(U32.is_eq(x, 13)), P.and_true_l(Bool.and(Bool.not(U32.is_eq(x, 10)), Bool.not(U32.is_eq(x, 13))), Laws.line.clean(t), h)))) : {Ev.feed.go(String.append(t, R), Ev.char(_, U32.is_eq(x, 13), x, Ev.P{Ev.Ln{2, "", 3, v}, e, False{}, True{}}, evs)) == Ev.feed.go(R, Ev.Fed{Ev.P{Ev.Ln{2, "", 3, String.reverse.go(t, SCon{Chr{x}, v})}, e, False{}, True{}}, evs}) : Ev.Fed}
      %Equal.sym(Bool, U32.is_eq(x, 13), False{}, P.not_true(U32.is_eq(x, 13), P.and_true_r(Bool.not(U32.is_eq(x, 10)), Bool.not(U32.is_eq(x, 13)), P.and_true_l(Bool.and(Bool.not(U32.is_eq(x, 10)), Bool.not(U32.is_eq(x, 13))), Laws.line.clean(t), h)))) : {Ev.feed.go(String.append(t, R), Ev.char(False{}, _, x, Ev.P{Ev.Ln{2, "", 3, v}, e, False{}, True{}}, evs)) == Ev.feed.go(R, Ev.Fed{Ev.P{Ev.Ln{2, "", 3, String.reverse.go(t, SCon{Chr{x}, v})}, e, False{}, True{}}, evs}) : Ev.Fed}
      val3(t, R, SCon{Chr{x}, v}, e, evs, P.and_true_r(Bool.and(Bool.not(U32.is_eq(x, 10)), Bool.not(U32.is_eq(x, 13))), Laws.line.clean(t), h))

# the prefix event: , from any start
law seg.event:
  for +R: String
  for +e: Ev.Evs
  for +st: Bool
  for +evs: List<&2, Ev.Message>
  {Ev.feed.go(String.append("event: ", R), Ev.Fed{Ev.P{Ev.Ln{0, "", 0, ""}, e, False{}, st}, evs}) == Ev.feed.go(R, Ev.Fed{Ev.P{Ev.Ln{2, "", 2, ""}, e, False{}, True{}}, evs}) : Ev.Fed}

def seg.event(R, e, st, evs):
  match st:
    case True{}:
      {==}
    case False{}:
      {==}

law data.c:
  for +b: Bool
  for +x: U32
  for +t: String
  for +R: String
  for +D: String
  for +a: Bool
  for +nm: String
  for +l: Maybe<&2, String>
  for +r: Maybe<&2, Nat>
  for +sn: Maybe<&2, String>
  for +evs: List<&2, Ev.Message>
  for eb: {U32.is_eq(x, 10) == b : Bool}
  for h13: {U32.is_eq(x, 13) == False{} : Bool}
  for ih: {Ev.feed.go(String.append(Ev.data.fwd(t), R), Ev.Fed{Ev.P{Ev.Ln{2, "", 1, ""}, Ev.Evs{SCon{Chr{x}, D}, True{}, nm, l, r, sn}, False{}, True{}}, evs}) == Ev.feed.go(R, Ev.Fed{Ev.P{Ev.Ln{0, "", 0, ""}, Ev.Evs{SCon{Chr{10}, String.reverse.go(t, SCon{Chr{x}, D})}, True{}, nm, l, r, sn}, False{}, True{}}, evs}) : Ev.Fed}
  {Ev.feed.go(String.append(Ev.data.fwd.c(b, x, Ev.data.fwd(t)), R), Ev.Fed{Ev.P{Ev.Ln{2, "", 1, ""}, Ev.Evs{D, a, nm, l, r, sn}, False{}, True{}}, evs}) == Ev.feed.go(R, Ev.Fed{Ev.P{Ev.Ln{0, "", 0, ""}, Ev.Evs{SCon{Chr{10}, String.reverse.go(t, SCon{Chr{x}, D})}, True{}, nm, l, r, sn}, False{}, True{}}, evs}) : Ev.Fed}

def data.c(b, x, t, R, D, a, nm, l, r, sn, evs, eb, h13, ih):
  match b:
    case True{}:
      %Equal.sym(Bool, U32.is_eq(x, 10), True{}, eb) : {Ev.feed.go(String.append(String.append("data: ", Ev.data.fwd(t)), R), Ev.char(_, U32.is_eq(x, 13), x, Ev.P{Ev.Ln{2, "", 1, ""}, Ev.Evs{D, a, nm, l, r, sn}, False{}, True{}}, evs)) == Ev.feed.go(R, Ev.Fed{Ev.P{Ev.Ln{0, "", 0, ""}, Ev.Evs{SCon{Chr{10}, String.reverse.go(t, SCon{Chr{x}, D})}, True{}, nm, l, r, sn}, False{}, True{}}, evs}) : Ev.Fed}
      ih
    case False{}:
      %Equal.sym(Bool, U32.is_eq(x, 10), False{}, eb) : {Ev.feed.go(String.append(Ev.data.fwd(t), R), Ev.char(_, U32.is_eq(x, 13), x, Ev.P{Ev.Ln{2, "", 1, ""}, Ev.Evs{D, a, nm, l, r, sn}, False{}, True{}}, evs)) == Ev.feed.go(R, Ev.Fed{Ev.P{Ev.Ln{0, "", 0, ""}, Ev.Evs{SCon{Chr{10}, String.reverse.go(t, SCon{Chr{x}, D})}, True{}, nm, l, r, sn}, False{}, True{}}, evs}) : Ev.Fed}
      %Equal.sym(Bool, U32.is_eq(x, 13), False{}, h13) : {Ev.feed.go(String.append(Ev.data.fwd(t), R), Ev.char(False{}, _, x, Ev.P{Ev.Ln{2, "", 1, ""}, Ev.Evs{D, a, nm, l, r, sn}, False{}, True{}}, evs)) == Ev.feed.go(R, Ev.Fed{Ev.P{Ev.Ln{0, "", 0, ""}, Ev.Evs{SCon{Chr{10}, String.reverse.go(t, SCon{Chr{x}, D})}, True{}, nm, l, r, sn}, False{}, True{}}, evs}) : Ev.Fed}
      ih

# data's lines, from just after its first data: to the LF after its last
law data.lines:
  for +t: String
  for +R: String
  for +D: String
  for +a: Bool
  for +nm: String
  for +l: Maybe<&2, String>
  for +r: Maybe<&2, Nat>
  for +sn: Maybe<&2, String>
  for +evs: List<&2, Ev.Message>
  for +h: {Laws.data.clean(t) == True{} : Bool}
  {Ev.feed.go(String.append(Ev.data.fwd(t), R), Ev.Fed{Ev.P{Ev.Ln{2, "", 1, ""}, Ev.Evs{D, a, nm, l, r, sn}, False{}, True{}}, evs}) == Ev.feed.go(R, Ev.Fed{Ev.P{Ev.Ln{0, "", 0, ""}, Ev.Evs{SCon{Chr{10}, String.reverse.go(t, D)}, True{}, nm, l, r, sn}, False{}, True{}}, evs}) : Ev.Fed}

def data.lines(t, R, D, a, nm, l, r, sn, evs, h):
  match t:
    case SNil{}:
      {==}
    case SCon{Chr{+x}, u}:
      data.c(U32.is_eq(x, 10), x, u, R, D, a, nm, l, r, sn, evs, {==}, P.not_true(U32.is_eq(x, 13), P.and_true_l(Bool.not(U32.is_eq(x, 13)), Laws.data.clean(u), h)), data.lines(u, R, SCon{Chr{x}, D}, True{}, nm, l, r, sn, evs, P.and_true_r(Bool.not(U32.is_eq(x, 13)), Laws.data.clean(u), h)))

# the rewrites above, the other way
law mdup_f:
  for +m: Maybe<&2, String>
  {Ev.M2{m, m} == Ev.m.dup(m) : Ev.M2}

def mdup_f(m):
  Equal.sym(Ev.M2, Ev.m.dup(m), Ev.M2{m, m}, mdup(m))

law revrev_f:
  for +s: String
  {s == String.reverse(String.reverse.go(s, "")) : String}

def revrev_f(s):
  Equal.sym(String, String.reverse(String.reverse.go(s, "")), s, revrev(s))

# an event's id line, if any, and the blank line that sends it
law id.tail:
  for +i: Maybe<&2, String>
  for +R: String
  for +D: String
  for +NN: String
  for +last: Maybe<&2, String>
  for +r: Maybe<&2, Nat>
  for +sn: Maybe<&2, String>
  for +evs: List<&2, Ev.Message>
  for +h: {Laws.id.clean(i) == True{} : Bool}
  {Ev.feed.go(Ev.id.fwd(i, SCon{Chr{10}, R}), Ev.Fed{Ev.P{Ev.Ln{0, "", 0, ""}, Ev.Evs{SCon{Chr{10}, D}, True{}, NN, last, r, sn}, False{}, True{}}, evs}) == Ev.feed.go(R, Ev.Fed{Ev.P{Ev.Ln{0, "", 0, ""}, Ev.Evs{"", False{}, "", Laws.next.id(i, last), r, Laws.next.id(i, last)}, False{}, True{}}, Con{Ev.Message{Ev.name.or(NN), String.reverse(D), Laws.next.id(i, last)}, evs}}) : Ev.Fed}

def id.tail(i, R, D, NN, last, r, sn, evs, h):
  match i:
    case None{}:
      %mdup_f(last) : {Ev.feed.go(R, Ev.fed.out(Ev.dispatch.go(SCon{Chr{10}, D}, NN, _, r), False{}, evs)) == Ev.feed.go(R, Ev.Fed{Ev.P{Ev.Ln{0, "", 0, ""}, Ev.Evs{"", False{}, "", Laws.next.id(None{}, last), r, Laws.next.id(None{}, last)}, False{}, True{}}, Con{Ev.Message{Ev.name.or(NN), String.reverse(D), Laws.next.id(None{}, last)}, evs}}) : Ev.Fed}
      %mdup_f(last) : {Ev.feed.go(R, Ev.fed.out(Ev.dispatch.to(SCon{Chr{10}, D}, NN, last, _, r), False{}, evs)) == Ev.feed.go(R, Ev.Fed{Ev.P{Ev.Ln{0, "", 0, ""}, Ev.Evs{"", False{}, "", Laws.next.id(None{}, last), r, Laws.next.id(None{}, last)}, False{}, True{}}, Con{Ev.Message{Ev.name.or(NN), String.reverse(D), Laws.next.id(None{}, last)}, evs}}) : Ev.Fed}
      {==}
    case Some{+s}:
      %Equal.sym(Ev.Fed, Ev.feed.go(String.append(s, SCon{Chr{10}, SCon{Chr{10}, R}}), Ev.Fed{Ev.P{Ev.Ln{2, "", 3, ""}, Ev.Evs{SCon{Chr{10}, D}, True{}, NN, last, r, sn}, False{}, True{}}, evs}), Ev.feed.go(SCon{Chr{10}, SCon{Chr{10}, R}}, Ev.Fed{Ev.P{Ev.Ln{2, "", 3, String.reverse.go(s, "")}, Ev.Evs{SCon{Chr{10}, D}, True{}, NN, last, r, sn}, False{}, True{}}, evs}), val3(s, SCon{Chr{10}, SCon{Chr{10}, R}}, "", Ev.Evs{SCon{Chr{10}, D}, True{}, NN, last, r, sn}, evs, h)) : {_ == Ev.feed.go(R, Ev.Fed{Ev.P{Ev.Ln{0, "", 0, ""}, Ev.Evs{"", False{}, "", Laws.next.id(Some{s}, last), r, Laws.next.id(Some{s}, last)}, False{}, True{}}, Con{Ev.Message{Ev.name.or(NN), String.reverse(D), Laws.next.id(Some{s}, last)}, evs}}) : Ev.Fed}
      %mdup_f(Ev.keep.id.of(String.reverse(String.reverse.go(s, "")), last)) : {Ev.feed.go(R, Ev.fed.out(Ev.dispatch.go(SCon{Chr{10}, D}, NN, _, r), False{}, evs)) == Ev.feed.go(R, Ev.Fed{Ev.P{Ev.Ln{0, "", 0, ""}, Ev.Evs{"", False{}, "", Laws.next.id(Some{s}, last), r, Laws.next.id(Some{s}, last)}, False{}, True{}}, Con{Ev.Message{Ev.name.or(NN), String.reverse(D), Laws.next.id(Some{s}, last)}, evs}}) : Ev.Fed}
      %mdup_f(Ev.keep.id.of(String.reverse(String.reverse.go(s, "")), last)) : {Ev.feed.go(R, Ev.fed.out(Ev.dispatch.to(SCon{Chr{10}, D}, NN, Ev.keep.id.of(String.reverse(String.reverse.go(s, "")), last), _, r), False{}, evs)) == Ev.feed.go(R, Ev.Fed{Ev.P{Ev.Ln{0, "", 0, ""}, Ev.Evs{"", False{}, "", Laws.next.id(Some{s}, last), r, Laws.next.id(Some{s}, last)}, False{}, True{}}, Con{Ev.Message{Ev.name.or(NN), String.reverse(D), Laws.next.id(Some{s}, last)}, evs}}) : Ev.Fed}
      %revrev_f(s) : {Ev.feed.go(R, Ev.fed.out(Ev.Out{Ev.Evs{"", False{}, "", Ev.keep.id.of(_, last), r, Ev.keep.id.of(_, last)}, Some{Ev.Message{Ev.name.or(NN), String.reverse(D), Ev.keep.id.of(_, last)}}}, False{}, evs)) == Ev.feed.go(R, Ev.Fed{Ev.P{Ev.Ln{0, "", 0, ""}, Ev.Evs{"", False{}, "", Laws.next.id(Some{s}, last), r, Laws.next.id(Some{s}, last)}, False{}, True{}}, Con{Ev.Message{Ev.name.or(NN), String.reverse(D), Laws.next.id(Some{s}, last)}, evs}}) : Ev.Fed}
      {==}

law msg.end:
  for +n: String
  for +d: String
  for +i: Maybe<&2, String>
  for +R: String
  for +last: Maybe<&2, String>
  for +r: Maybe<&2, Nat>
  for +evs: List<&2, Ev.Message>
  {Ev.feed.go(R, Ev.Fed{Ev.P{Ev.Ln{0, "", 0, ""}, Ev.Evs{"", False{}, "", Laws.next.id(i, last), r, Laws.next.id(i, last)}, False{}, True{}}, Con{Ev.Message{Ev.name.or(String.reverse(String.reverse.go(n, ""))), String.reverse(String.reverse.go(d, "")), Laws.next.id(i, last)}, evs}}) == Ev.feed.go(R, Ev.Fed{Ev.P{Ev.Ln{0, "", 0, ""}, Ev.Evs{"", False{}, "", Laws.next.id(i, last), r, Laws.next.id(i, last)}, False{}, True{}}, Con{Ev.Message{Ev.name.or(n), d, Laws.next.id(i, last)}, evs}}) : Ev.Fed}

def msg.end(n, d, i, R, last, r, evs):
  %revrev_f(n) : {Ev.feed.go(R, Ev.Fed{Ev.P{Ev.Ln{0, "", 0, ""}, Ev.Evs{"", False{}, "", Laws.next.id(i, last), r, Laws.next.id(i, last)}, False{}, True{}}, Con{Ev.Message{Ev.name.or(_), String.reverse(String.reverse.go(d, "")), Laws.next.id(i, last)}, evs}}) == Ev.feed.go(R, Ev.Fed{Ev.P{Ev.Ln{0, "", 0, ""}, Ev.Evs{"", False{}, "", Laws.next.id(i, last), r, Laws.next.id(i, last)}, False{}, True{}}, Con{Ev.Message{Ev.name.or(n), d, Laws.next.id(i, last)}, evs}}) : Ev.Fed}
  %revrev_f(d) : {Ev.feed.go(R, Ev.Fed{Ev.P{Ev.Ln{0, "", 0, ""}, Ev.Evs{"", False{}, "", Laws.next.id(i, last), r, Laws.next.id(i, last)}, False{}, True{}}, Con{Ev.Message{Ev.name.or(n), _, Laws.next.id(i, last)}, evs}}) == Ev.feed.go(R, Ev.Fed{Ev.P{Ev.Ln{0, "", 0, ""}, Ev.Evs{"", False{}, "", Laws.next.id(i, last), r, Laws.next.id(i, last)}, False{}, True{}}, Con{Ev.Message{Ev.name.or(n), d, Laws.next.id(i, last)}, evs}}) : Ev.Fed}
  {==}

law msg.go:
  for +n: String
  for +d: String
  for +i: Maybe<&2, String>
  for +R: String
  for +last: Maybe<&2, String>
  for +r: Maybe<&2, Nat>
  for +st: Bool
  for +evs: List<&2, Ev.Message>
  for +hn: {Laws.line.clean(n) == True{} : Bool}
  for +hd: {Laws.data.clean(d) == True{} : Bool}
  for +hi: {Laws.id.clean(i) == True{} : Bool}
  {Ev.feed.go(Ev.write.to(Ev.Message{n, d, i}, R), Ev.Fed{Ev.P{Ev.Ln{0, "", 0, ""}, Ev.Evs{"", False{}, "", last, r, last}, False{}, st}, evs}) == Ev.feed.go(R, Ev.Fed{Ev.P{Ev.Ln{0, "", 0, ""}, Ev.Evs{"", False{}, "", Laws.next.id(i, last), r, Laws.next.id(i, last)}, False{}, True{}}, Con{Ev.Message{Ev.name.or(n), d, Laws.next.id(i, last)}, evs}}) : Ev.Fed}

def msg.go(n, d, i, R, last, r, st, evs, hn, hd, hi):
  Equal.trans(Ev.Fed, Ev.feed.go(Ev.write.to(Ev.Message{n, d, i}, R), Ev.Fed{Ev.P{Ev.Ln{0, "", 0, ""}, Ev.Evs{"", False{}, "", last, r, last}, False{}, st}, evs}), Ev.feed.go(String.append(n, SCon{Chr{10}, String.append("data: ", String.append(Ev.data.fwd(d), Ev.id.fwd(i, SCon{Chr{10}, R})))}), Ev.Fed{Ev.P{Ev.Ln{2, "", 2, ""}, Ev.Evs{"", False{}, "", last, r, last}, False{}, True{}}, evs}), Ev.feed.go(R, Ev.Fed{Ev.P{Ev.Ln{0, "", 0, ""}, Ev.Evs{"", False{}, "", Laws.next.id(i, last), r, Laws.next.id(i, last)}, False{}, True{}}, Con{Ev.Message{Ev.name.or(n), d, Laws.next.id(i, last)}, evs}}), seg.event(String.append(n, SCon{Chr{10}, String.append("data: ", String.append(Ev.data.fwd(d), Ev.id.fwd(i, SCon{Chr{10}, R})))}), Ev.Evs{"", False{}, "", last, r, last}, st, evs), Equal.trans(Ev.Fed, Ev.feed.go(String.append(n, SCon{Chr{10}, String.append("data: ", String.append(Ev.data.fwd(d), Ev.id.fwd(i, SCon{Chr{10}, R})))}), Ev.Fed{Ev.P{Ev.Ln{2, "", 2, ""}, Ev.Evs{"", False{}, "", last, r, last}, False{}, True{}}, evs}), Ev.feed.go(SCon{Chr{10}, String.append("data: ", String.append(Ev.data.fwd(d), Ev.id.fwd(i, SCon{Chr{10}, R})))}, Ev.Fed{Ev.P{Ev.Ln{2, "", 2, String.reverse.go(n, "")}, Ev.Evs{"", False{}, "", last, r, last}, False{}, True{}}, evs}), Ev.feed.go(R, Ev.Fed{Ev.P{Ev.Ln{0, "", 0, ""}, Ev.Evs{"", False{}, "", Laws.next.id(i, last), r, Laws.next.id(i, last)}, False{}, True{}}, Con{Ev.Message{Ev.name.or(n), d, Laws.next.id(i, last)}, evs}}), val2(n, SCon{Chr{10}, String.append("data: ", String.append(Ev.data.fwd(d), Ev.id.fwd(i, SCon{Chr{10}, R})))}, "", Ev.Evs{"", False{}, "", last, r, last}, evs, hn), Equal.trans(Ev.Fed, Ev.feed.go(SCon{Chr{10}, String.append("data: ", String.append(Ev.data.fwd(d), Ev.id.fwd(i, SCon{Chr{10}, R})))}, Ev.Fed{Ev.P{Ev.Ln{2, "", 2, String.reverse.go(n, "")}, Ev.Evs{"", False{}, "", last, r, last}, False{}, True{}}, evs}), Ev.feed.go(String.append(Ev.data.fwd(d), Ev.id.fwd(i, SCon{Chr{10}, R})), Ev.Fed{Ev.P{Ev.Ln{2, "", 1, ""}, Ev.Evs{"", False{}, String.reverse(String.reverse.go(n, "")), last, r, last}, False{}, True{}}, evs}), Ev.feed.go(R, Ev.Fed{Ev.P{Ev.Ln{0, "", 0, ""}, Ev.Evs{"", False{}, "", Laws.next.id(i, last), r, Laws.next.id(i, last)}, False{}, True{}}, Con{Ev.Message{Ev.name.or(n), d, Laws.next.id(i, last)}, evs}}), {==}, Equal.trans(Ev.Fed, Ev.feed.go(String.append(Ev.data.fwd(d), Ev.id.fwd(i, SCon{Chr{10}, R})), Ev.Fed{Ev.P{Ev.Ln{2, "", 1, ""}, Ev.Evs{"", False{}, String.reverse(String.reverse.go(n, "")), last, r, last}, False{}, True{}}, evs}), Ev.feed.go(Ev.id.fwd(i, SCon{Chr{10}, R}), Ev.Fed{Ev.P{Ev.Ln{0, "", 0, ""}, Ev.Evs{SCon{Chr{10}, String.reverse.go(d, "")}, True{}, String.reverse(String.reverse.go(n, "")), last, r, last}, False{}, True{}}, evs}), Ev.feed.go(R, Ev.Fed{Ev.P{Ev.Ln{0, "", 0, ""}, Ev.Evs{"", False{}, "", Laws.next.id(i, last), r, Laws.next.id(i, last)}, False{}, True{}}, Con{Ev.Message{Ev.name.or(n), d, Laws.next.id(i, last)}, evs}}), data.lines(d, Ev.id.fwd(i, SCon{Chr{10}, R}), "", False{}, String.reverse(String.reverse.go(n, "")), last, r, last, evs, hd), Equal.trans(Ev.Fed, Ev.feed.go(Ev.id.fwd(i, SCon{Chr{10}, R}), Ev.Fed{Ev.P{Ev.Ln{0, "", 0, ""}, Ev.Evs{SCon{Chr{10}, String.reverse.go(d, "")}, True{}, String.reverse(String.reverse.go(n, "")), last, r, last}, False{}, True{}}, evs}), Ev.feed.go(R, Ev.Fed{Ev.P{Ev.Ln{0, "", 0, ""}, Ev.Evs{"", False{}, "", Laws.next.id(i, last), r, Laws.next.id(i, last)}, False{}, True{}}, Con{Ev.Message{Ev.name.or(String.reverse(String.reverse.go(n, ""))), String.reverse(String.reverse.go(d, "")), Laws.next.id(i, last)}, evs}}), Ev.feed.go(R, Ev.Fed{Ev.P{Ev.Ln{0, "", 0, ""}, Ev.Evs{"", False{}, "", Laws.next.id(i, last), r, Laws.next.id(i, last)}, False{}, True{}}, Con{Ev.Message{Ev.name.or(n), d, Laws.next.id(i, last)}, evs}}), id.tail(i, R, String.reverse.go(d, ""), String.reverse(String.reverse.go(n, "")), last, r, last, evs, hi), msg.end(n, d, i, R, last, r, evs))))))

# one event, written and read back, from a line's start
law msg:
  for +n: String
  for +d: String
  for +i: Maybe<&2, String>
  for +R: String
  for +last: Maybe<&2, String>
  for +r: Maybe<&2, Nat>
  for +st: Bool
  for +evs: List<&2, Ev.Message>
  for +h: {Bool.and(Laws.line.clean(n), Bool.and(Laws.data.clean(d), Laws.id.clean(i))) == True{} : Bool}
  {Ev.feed.go(Ev.write.to(Ev.Message{n, d, i}, R), Ev.Fed{Ev.P{Ev.Ln{0, "", 0, ""}, Ev.Evs{"", False{}, "", last, r, last}, False{}, st}, evs}) == Ev.feed.go(R, Ev.Fed{Ev.P{Ev.Ln{0, "", 0, ""}, Ev.Evs{"", False{}, "", Laws.next.id(i, last), r, Laws.next.id(i, last)}, False{}, True{}}, Con{Ev.Message{Ev.name.or(n), d, Laws.next.id(i, last)}, evs}}) : Ev.Fed}

def msg(n, d, i, R, last, r, st, evs, h):
  msg.go(n, d, i, R, last, r, st, evs, P.and_true_l(Laws.line.clean(n), Bool.and(Laws.data.clean(d), Laws.id.clean(i)), h), P.and_true_l(Laws.data.clean(d), Laws.id.clean(i), P.and_true_r(Laws.line.clean(n), Bool.and(Laws.data.clean(d), Laws.id.clean(i)), h)), P.and_true_r(Laws.data.clean(d), Laws.id.clean(i), P.and_true_r(Laws.line.clean(n), Bool.and(Laws.data.clean(d), Laws.id.clean(i)), h)))

# events, one after another: each read back onto the ones before
law seq:
  for +ms: List<&2, Ev.Message>
  for +last: Maybe<&2, String>
  for +r: Maybe<&2, Nat>
  for +st: Bool
  for +acc: List<&2, Ev.Message>
  for +h: {Laws.writable(ms) == True{} : Bool}
  {Laws.events(Ev.feed.go(Laws.stream(ms), Ev.Fed{Ev.P{Ev.Ln{0, "", 0, ""}, Ev.Evs{"", False{}, "", last, r, last}, False{}, st}, acc})) == List.reverse.go(&2, Ev.Message, Laws.read(ms, last), acc) : List<&2, Ev.Message>}

def seq(ms, last, r, st, acc, h):
  match ms:
    case Nil{}:
      {==}
    case Con{Ev.Message{+n, +d, +i}, t}:
      Equal.trans(List<&2, Ev.Message>, Laws.events(Ev.feed.go(Ev.write.to(Ev.Message{n, d, i}, Laws.stream(t)), Ev.Fed{Ev.P{Ev.Ln{0, "", 0, ""}, Ev.Evs{"", False{}, "", last, r, last}, False{}, st}, acc})), Laws.events(Ev.feed.go(Laws.stream(t), Ev.Fed{Ev.P{Ev.Ln{0, "", 0, ""}, Ev.Evs{"", False{}, "", Laws.next.id(i, last), r, Laws.next.id(i, last)}, False{}, True{}}, Con{Ev.Message{Ev.name.or(n), d, Laws.next.id(i, last)}, acc}})), List.reverse.go(&2, Ev.Message, Laws.read(t, Laws.next.id(i, last)), Con{Ev.Message{Ev.name.or(n), d, Laws.next.id(i, last)}, acc}), Equal.cong(Ev.Fed, List<&2, Ev.Message>, f => Laws.events(f), Ev.feed.go(Ev.write.to(Ev.Message{n, d, i}, Laws.stream(t)), Ev.Fed{Ev.P{Ev.Ln{0, "", 0, ""}, Ev.Evs{"", False{}, "", last, r, last}, False{}, st}, acc}), Ev.feed.go(Laws.stream(t), Ev.Fed{Ev.P{Ev.Ln{0, "", 0, ""}, Ev.Evs{"", False{}, "", Laws.next.id(i, last), r, Laws.next.id(i, last)}, False{}, True{}}, Con{Ev.Message{Ev.name.or(n), d, Laws.next.id(i, last)}, acc}}), msg(n, d, i, Laws.stream(t), last, r, st, acc, P.and_true_l(Bool.and(Laws.line.clean(n), Bool.and(Laws.data.clean(d), Laws.id.clean(i))), Laws.writable(t), h))), seq(t, Laws.next.id(i, last), r, True{}, Con{Ev.Message{Ev.name.or(n), d, Laws.next.id(i, last)}, acc}, P.and_true_r(Bool.and(Laws.line.clean(n), Bool.and(Laws.data.clean(d), Laws.id.clean(i))), Laws.writable(t), h)))

law ord:
  for +f: Ev.Fed
  {Laws.events(Ev.fed.order(f)) == List.reverse(&2, Ev.Message, Laws.events(f)) : List<&2, Ev.Message>}

def ord(f):
  match f:
    case Ev.Fed{p, es}:
      {==}

law lapp_nil:
  for +a: List<&2, Ev.Message>
  {List.append(&2, Ev.Message, a, []) == a : List<&2, Ev.Message>}

def lapp_nil(a):
  match a:
    case Nil{}:
      {==}
    case Con{+x, t}:
      Equal.cong(List<&2, Ev.Message>, List<&2, Ev.Message>, y => Con{x, y}, List.append(&2, Ev.Message, t, []), t, lapp_nil(t))

law lrev_rev:
  for +a: List<&2, Ev.Message>
  for +b: List<&2, Ev.Message>
  for +c: List<&2, Ev.Message>
  {List.reverse.go(&2, Ev.Message, List.reverse.go(&2, Ev.Message, a, b), c) == List.reverse.go(&2, Ev.Message, b, List.append(&2, Ev.Message, a, c)) : List<&2, Ev.Message>}

def lrev_rev(a, b, c):
  match a:
    case Nil{}:
      {==}
    case Con{+x, t}:
      lrev_rev(t, Con{x, b}, c)

law lrevrev:
  for +a: List<&2, Ev.Message>
  {List.reverse(&2, Ev.Message, List.reverse.go(&2, Ev.Message, a, [])) == a : List<&2, Ev.Message>}

def lrevrev(a):
  Equal.trans(List<&2, Ev.Message>, List.reverse.go(&2, Ev.Message, List.reverse.go(&2, Ev.Message, a, []), []), List.append(&2, Ev.Message, a, []), a, lrev_rev(a, [], []), lapp_nil(a))

def Laws.sse_reads_back(ms, e):
  Equal.trans(List<&2, Ev.Message>, Laws.events(Ev.fed.order(Ev.feed.go(Laws.stream(ms), Ev.Fed{Ev.start(), []}))), List.reverse(&2, Ev.Message, Laws.events(Ev.feed.go(Laws.stream(ms), Ev.Fed{Ev.start(), []}))), Laws.read(ms, None{}), ord(Ev.feed.go(Laws.stream(ms), Ev.Fed{Ev.start(), []})), Equal.trans(List<&2, Ev.Message>, List.reverse(&2, Ev.Message, Laws.events(Ev.feed.go(Laws.stream(ms), Ev.Fed{Ev.start(), []}))), List.reverse(&2, Ev.Message, List.reverse.go(&2, Ev.Message, Laws.read(ms, None{}), [])), Laws.read(ms, None{}), Equal.cong(List<&2, Ev.Message>, List<&2, Ev.Message>, x => List.reverse(&2, Ev.Message, x), Laws.events(Ev.feed.go(Laws.stream(ms), Ev.Fed{Ev.start(), []})), List.reverse.go(&2, Ev.Message, Laws.read(ms, None{}), []), seq(ms, None{}, None{}, False{}, [], e)), lrevrev(Laws.read(ms, None{}))))

law sapp_assoc_f:
  for +a: String
  for +b: String
  for +c: String
  {String.append(a, String.append(b, c)) == String.append(String.append(a, b), c) : String}

def sapp_assoc_f(a, b, c):
  Equal.sym(String, String.append(String.append(a, b), c), String.append(a, String.append(b, c)), sapp_assoc(a, b, c))

law idj:
  for +i: Maybe<&2, String>
  for +r: String
  {Ev.id.fwd(i, SCon{Chr{10}, r}) == String.append(Ev.id.fwd(i, SCon{Chr{10}, ""}), r) : String}

def idj(i, r):
  match i:
    case None{}:
      {==}
    case Some{+s}:
      Equal.cong(String, String, y => String.append("id: ", y), String.append(s, SCon{Chr{10}, SCon{Chr{10}, r}}), String.append(String.append(s, SCon{Chr{10}, SCon{Chr{10}, ""}}), r), Equal.sym(String, String.append(String.append(s, SCon{Chr{10}, SCon{Chr{10}, ""}}), r), String.append(s, SCon{Chr{10}, SCon{Chr{10}, r}}), sapp_assoc(s, SCon{Chr{10}, SCon{Chr{10}, ""}}, r)))

def Laws.write_joins(m, r):
  match m:
    case Ev.Message{+n, +d, +i}:
      %sapp_assoc_f(n, SCon{Chr{10}, String.append("data: ", String.append(Ev.data.fwd(d), Ev.id.fwd(i, SCon{Chr{10}, ""})))}, r) : {String.append("event: ", _) == Ev.write.to(Ev.Message{n, d, i}, r) : String}
      %sapp_assoc_f(Ev.data.fwd(d), Ev.id.fwd(i, SCon{Chr{10}, ""}), r) : {String.append("event: ", String.append(n, SCon{Chr{10}, String.append("data: ", _)})) == Ev.write.to(Ev.Message{n, d, i}, r) : String}
      %idj(i, r) : {String.append("event: ", String.append(n, SCon{Chr{10}, String.append("data: ", String.append(Ev.data.fwd(d), _))})) == Ev.write.to(Ev.Message{n, d, i}, r) : String}
      {==}
