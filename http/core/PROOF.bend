import Base
import ./LAWS.bend as Laws
import ./headers.bend as H
import ./query.bend as Q
import ./text.bend as T
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
