import Base
import ./LAWS.bend as Laws
import ./http1.bend as H1
import ./bytes.bend as B
import ../core/headers.bend as H
import ../core/text.bend as T
import ../core/proof/text.bend as P

# Names, in any case
# -----

law kind_te:
  for +n: String
  for e: {P.lows(n) == "transfer-encoding" : String}
  {H1.kind(n) == H1.KTe{} : H1.HKind}

def kind_te(n, e):
  %Equal.sym(Bool, T.same_ci(n, "content-length", True{}), T.same(P.lows(n), P.lows("content-length"), True{}), P.same_ci_lows(n, "content-length", True{})) : {H1.kind.pick(_, H1.KLen{}, H1.kind.pick(T.same_ci(n, "transfer-encoding", True{}), H1.KTe{}, H1.kind.pick(T.same_ci(n, "host", True{}), H1.KHost{}, H1.kind.pick(T.same_ci(n, "connection", True{}), H1.KConn{}, H1.KOther{})))) == H1.KTe{} : H1.HKind}
  %Equal.sym(Bool, T.same_ci(n, "transfer-encoding", True{}), T.same(P.lows(n), P.lows("transfer-encoding"), True{}), P.same_ci_lows(n, "transfer-encoding", True{})) : {H1.kind.pick(T.same(P.lows(n), P.lows("content-length"), True{}), H1.KLen{}, H1.kind.pick(_, H1.KTe{}, H1.kind.pick(T.same_ci(n, "host", True{}), H1.KHost{}, H1.kind.pick(T.same_ci(n, "connection", True{}), H1.KConn{}, H1.KOther{})))) == H1.KTe{} : H1.HKind}
  %Equal.sym(String, P.lows(n), "transfer-encoding", e) : {H1.kind.pick(T.same(_, P.lows("content-length"), True{}), H1.KLen{}, H1.kind.pick(T.same(_, P.lows("transfer-encoding"), True{}), H1.KTe{}, H1.kind.pick(T.same_ci(n, "host", True{}), H1.KHost{}, H1.kind.pick(T.same_ci(n, "connection", True{}), H1.KConn{}, H1.KOther{})))) == H1.KTe{} : H1.HKind}
  {==}

law kind_len:
  for +n: String
  for e: {P.lows(n) == "content-length" : String}
  {H1.kind(n) == H1.KLen{} : H1.HKind}

def kind_len(n, e):
  %Equal.sym(Bool, T.same_ci(n, "content-length", True{}), T.same(P.lows(n), P.lows("content-length"), True{}), P.same_ci_lows(n, "content-length", True{})) : {H1.kind.pick(_, H1.KLen{}, H1.kind.pick(T.same_ci(n, "transfer-encoding", True{}), H1.KTe{}, H1.kind.pick(T.same_ci(n, "host", True{}), H1.KHost{}, H1.kind.pick(T.same_ci(n, "connection", True{}), H1.KConn{}, H1.KOther{})))) == H1.KLen{} : H1.HKind}
  %Equal.sym(String, P.lows(n), "content-length", e) : {H1.kind.pick(T.same(_, P.lows("content-length"), True{}), H1.KLen{}, H1.kind.pick(T.same_ci(n, "transfer-encoding", True{}), H1.KTe{}, H1.kind.pick(T.same_ci(n, "host", True{}), H1.KHost{}, H1.kind.pick(T.same_ci(n, "connection", True{}), H1.KConn{}, H1.KOther{})))) == H1.KLen{} : H1.HKind}
  {==}

def Laws.framing_cl(n, e):
  %Equal.sym(Bool, T.same_ci(n, "content-length", True{}), T.same(P.lows(n), P.lows("content-length"), True{}), P.same_ci_lows(n, "content-length", True{})) : {Bool.or(_, Bool.or(T.same_ci(n, "transfer-encoding", True{}), T.same_ci(n, "connection", True{}))) == True{} : Bool}
  %Equal.sym(String, P.lows(n), "content-length", e) : {Bool.or(T.same(_, P.lows("content-length"), True{}), Bool.or(T.same_ci(n, "transfer-encoding", True{}), T.same_ci(n, "connection", True{}))) == True{} : Bool}
  {==}

def Laws.framing_te(n, e):
  %Equal.sym(Bool, T.same_ci(n, "content-length", True{}), T.same(P.lows(n), P.lows("content-length"), True{}), P.same_ci_lows(n, "content-length", True{})) : {Bool.or(_, Bool.or(T.same_ci(n, "transfer-encoding", True{}), T.same_ci(n, "connection", True{}))) == True{} : Bool}
  %Equal.sym(Bool, T.same_ci(n, "transfer-encoding", True{}), T.same(P.lows(n), P.lows("transfer-encoding"), True{}), P.same_ci_lows(n, "transfer-encoding", True{})) : {Bool.or(T.same(P.lows(n), P.lows("content-length"), True{}), Bool.or(_, T.same_ci(n, "connection", True{}))) == True{} : Bool}
  %Equal.sym(String, P.lows(n), "transfer-encoding", e) : {Bool.or(T.same(_, P.lows("content-length"), True{}), Bool.or(T.same(_, P.lows("transfer-encoding"), True{}), T.same_ci(n, "connection", True{}))) == True{} : Bool}
  {==}

def Laws.framing_connection(n, e):
  %Equal.sym(Bool, T.same_ci(n, "content-length", True{}), T.same(P.lows(n), P.lows("content-length"), True{}), P.same_ci_lows(n, "content-length", True{})) : {Bool.or(_, Bool.or(T.same_ci(n, "transfer-encoding", True{}), T.same_ci(n, "connection", True{}))) == True{} : Bool}
  %Equal.sym(Bool, T.same_ci(n, "transfer-encoding", True{}), T.same(P.lows(n), P.lows("transfer-encoding"), True{}), P.same_ci_lows(n, "transfer-encoding", True{})) : {Bool.or(T.same(P.lows(n), P.lows("content-length"), True{}), Bool.or(_, T.same_ci(n, "connection", True{}))) == True{} : Bool}
  %Equal.sym(Bool, T.same_ci(n, "connection", True{}), T.same(P.lows(n), P.lows("connection"), True{}), P.same_ci_lows(n, "connection", True{})) : {Bool.or(T.same(P.lows(n), P.lows("content-length"), True{}), Bool.or(T.same(P.lows(n), P.lows("transfer-encoding"), True{}), _)) == True{} : Bool}
  %Equal.sym(String, P.lows(n), "connection", e) : {Bool.or(T.same(_, P.lows("content-length"), True{}), Bool.or(T.same(_, P.lows("transfer-encoding"), True{}), T.same(_, P.lows("connection"), True{}))) == True{} : Bool}
  {==}

# Transfer-Encoding
# -----------------

law step_te:
  for +k: H1.HKind
  for +fr: H1.Frame
  for +v: String
  for e: {Laws.fte(fr) == True{} : Bool}
  {Laws.fte(H1.frame.step(k, fr, v)) == True{} : Bool}

def step_te(k, fr, v, e):
  match k fr:
    case H1.KLen{} H1.Frame{cl, te, h, c, kp}:
      e
    case H1.KTe{} H1.Frame{cl, te, h, c, kp}:
      {==}
    case H1.KHost{} H1.Frame{cl, te, h, c, kp}:
      e
    case H1.KConn{} H1.Frame{cl, te, h, c, kp}:
      e
    case H1.KOther{} f:
      e

law te_sticky:
  for +hs: List<&2, H.Header>
  for +fr: H1.Frame
  for +acc: List<&2, H.Header>
  for e: {Laws.fte(fr) == True{} : Bool}
  {Laws.te_of(H1.scan(hs, fr, acc)) == True{} : Bool}

def te_sticky(hs, fr, acc, e):
  match hs:
    case Nil{}:
      e
    case Con{H.Header{+n, +v}, t}:
      te_sticky(t, H1.frame.step(H1.kind(n), fr, v), Con{H.Header{n, v}, acc}, step_te(H1.kind(n), fr, v, e))

law te_head:
  for +post: List<&2, H.Header>
  for +fr: H1.Frame
  for +v: String
  for +acc: List<&2, H.Header>
  {Laws.te_of(H1.scan(post, H1.frame.step(H1.KTe{}, fr, v), acc)) == True{} : Bool}

def te_head(post, fr, v, acc):
  match fr:
    case H1.Frame{cl, te, h, c, kp}:
      te_sticky(post, H1.Frame{cl, True{}, h, c, kp}, acc, {==})

def Laws.te_seen(pre, n, v, post, fr, acc, e):
  match pre:
    case Nil{}:
      %Equal.sym(H1.HKind, H1.kind(n), H1.KTe{}, kind_te(n, e)) : {Laws.te_of(H1.scan(post, H1.frame.step(_, fr, v), Con{H.Header{n, v}, acc})) == True{} : Bool}
      te_head(post, fr, v, Con{H.Header{n, v}, acc})
    case Con{H.Header{+k, +w}, t}:
      Laws.te_seen(t, n, v, post, H1.frame.step(H1.kind(k), fr, w), Con{H.Header{k, w}, acc}, e)

# Obs-fold
# --------

law fields_err:
  for +ls: List<&2, B.Bytes>
  for +e: H1.Err
  {H1.fields(ls, H1.FErr{e}) == H1.FErr{e} : H1.Fields}

def fields_err(ls, e):
  match ls:
    case Nil{}:
      {==}
    case Con{l, t}:
      fields_err(t, e)

law folded:
  for +acc: H1.Fields
  for +post: List<&2, B.Bytes>
  {Laws.is_err(H1.fields(post, H1.fields.add(acc, H1.FBad{H1.ObsFold{}}))) == True{} : Bool}

def folded(acc, post):
  match acc:
    case H1.FOk{_}:
      %Equal.sym(H1.Fields, H1.fields(post, H1.FErr{H1.ObsFold{}}), H1.FErr{H1.ObsFold{}}, fields_err(post, H1.ObsFold{})) : {Laws.is_err(_) == True{} : Bool}
      {==}
    case H1.FErr{x}:
      %Equal.sym(H1.Fields, H1.fields(post, H1.FErr{x}), H1.FErr{x}, fields_err(post, x)) : {Laws.is_err(_) == True{} : Bool}
      {==}

def Laws.obs_fold(pre, w, l, post, acc, e):
  match pre:
    case Nil{}:
      %Equal.sym(Bool, B.is_ws(w), True{}, e) : {Laws.is_err(H1.fields(post, H1.fields.add(acc, H1.field.fold(_, B.BCon{w, l})))) == True{} : Bool}
      folded(acc, post)
    case Con{x, t}:
      Laws.obs_fold(t, w, l, post, H1.fields.add(acc, H1.field(x)), e)

# Dropped headers
# ---------------

def Laws.unsafe_value_dropped(n, v, hs, out, e):
  %Equal.sym(Bool, H1.unsafe(v, False{}), True{}, e) : {H1.heads(hs, H1.heads.keep(Bool.or(H1.framing(n), Bool.or(H1.unsafe(n, False{}), _)), n, v, out)) == H1.heads(hs, out) : String}
  %Equal.sym(Bool, Bool.or(H1.unsafe(n, False{}), True{}), True{}, P.or_true(H1.unsafe(n, False{}))) : {H1.heads(hs, H1.heads.keep(Bool.or(H1.framing(n), _), n, v, out)) == H1.heads(hs, out) : String}
  %Equal.sym(Bool, Bool.or(H1.framing(n), True{}), True{}, P.or_true(H1.framing(n))) : {H1.heads(hs, H1.heads.keep(_, n, v, out)) == H1.heads(hs, out) : String}
  {==}

def Laws.unsafe_name_dropped(n, v, hs, out, e):
  %Equal.sym(Bool, H1.unsafe(n, False{}), True{}, e) : {H1.heads(hs, H1.heads.keep(Bool.or(H1.framing(n), Bool.or(_, H1.unsafe(v, False{}))), n, v, out)) == H1.heads(hs, out) : String}
  %Equal.sym(Bool, Bool.or(H1.framing(n), True{}), True{}, P.or_true(H1.framing(n))) : {H1.heads(hs, H1.heads.keep(_, n, v, out)) == H1.heads(hs, out) : String}
  {==}

def Laws.framing_dropped(n, v, hs, out, e):
  %Equal.sym(Bool, H1.framing(n), True{}, e) : {H1.heads(hs, H1.heads.keep(Bool.or(_, Bool.or(H1.unsafe(n, False{}), H1.unsafe(v, False{}))), n, v, out)) == H1.heads(hs, out) : String}
  {==}

# Content-Length
# --------------

law merge_bad:
  for +m: Maybe<&2, Nat>
  {H1.cl_merge(H1.LenBad{}, m) == H1.LenBad{} : H1.CL}

def merge_bad(m):
  match m:
    case Some{_}:
      {==}
    case None{}:
      {==}

law step_bad:
  for +k: H1.HKind
  for +fr: H1.Frame
  for +v: String
  for e: {Laws.fcl(fr) == H1.LenBad{} : H1.CL}
  {Laws.fcl(H1.frame.step(k, fr, v)) == H1.LenBad{} : H1.CL}

def step_bad(k, fr, v, e):
  match k fr:
    case H1.KLen{} H1.Frame{cl, te, h, c, kp}:
      %Equal.sym(H1.CL, cl, H1.LenBad{}, e) : {H1.cl_merge(_, H1.cl_digits.go(v, 0n, True{}, False{})) == H1.LenBad{} : H1.CL}
      merge_bad(H1.cl_digits.go(v, 0n, True{}, False{}))
    case H1.KTe{} H1.Frame{cl, te, h, c, kp}:
      e
    case H1.KHost{} H1.Frame{cl, te, h, c, kp}:
      e
    case H1.KConn{} H1.Frame{cl, te, h, c, kp}:
      e
    case H1.KOther{} f:
      e

def Laws.cl_bad_stays(hs, fr, acc, e):
  match hs:
    case Nil{}:
      e
    case Con{H.Header{+n, +v}, t}:
      Laws.cl_bad_stays(t, H1.frame.step(H1.kind(n), fr, v), Con{H.Header{n, v}, acc}, step_bad(H1.kind(n), fr, v, e))

# after a Content-Length of a: the length is a, or already bad
def lenish(+a: Nat, cl: H1.CL) -> Bool:
  match cl:
    case H1.NoLen{}:
      False{}
    case H1.Len{b}:
      Nat.is_eq(b, a)
    case H1.LenBad{}:
      True{}

law eq_lenish:
  for +s: Bool
  for +b: Nat
  for +a: Nat
  for h: {Nat.is_eq(b, a) == s : Bool}
  {lenish(a, H1.cl_merge.eq(s, b)) == True{} : Bool}

def eq_lenish(s, b, a, h):
  match s:
    case True{}:
      h
    case False{}:
      {==}

# a Len{b} that is a, merged with any length, is a or bad
law keep_lenish:
  for +s: Bool
  for +b: Nat
  for +a: Nat
  for e: {Nat.is_eq(b, a) == True{} : Bool}
  {lenish(a, H1.cl_merge.eq(s, b)) == True{} : Bool}

def keep_lenish(s, b, a, e):
  match s:
    case True{}:
      e
    case False{}:
      {==}

law merge_lenish:
  for +cl: H1.CL
  for +m: Maybe<&2, Nat>
  for +a: Nat
  for e: {lenish(a, cl) == True{} : Bool}
  {lenish(a, H1.cl_merge(cl, m)) == True{} : Bool}

def merge_lenish(cl, m, a, e):
  match cl m:
    case H1.NoLen{} _:
      P.absurd({lenish(a, H1.cl_merge(H1.NoLen{}, m)) == True{} : Bool}, e)
    case H1.Len{+b} Some{+c}:
      keep_lenish(Nat.is_eq(b, c), b, a, e)
    case H1.Len{b} None{}:
      {==}
    case H1.LenBad{} x:
      %Equal.sym(H1.CL, H1.cl_merge(H1.LenBad{}, x), H1.LenBad{}, merge_bad(x)) : {lenish(a, _) == True{} : Bool}
      {==}

law step_lenish:
  for +k: H1.HKind
  for +fr: H1.Frame
  for +v: String
  for +a: Nat
  for e: {lenish(a, Laws.fcl(fr)) == True{} : Bool}
  {lenish(a, Laws.fcl(H1.frame.step(k, fr, v))) == True{} : Bool}

def step_lenish(k, fr, v, a, e):
  match k fr:
    case H1.KLen{} H1.Frame{cl, te, h, c, kp}:
      merge_lenish(cl, H1.cl_digits.go(v, 0n, True{}, False{}), a, e)
    case H1.KTe{} H1.Frame{cl, te, h, c, kp}:
      e
    case H1.KHost{} H1.Frame{cl, te, h, c, kp}:
      e
    case H1.KConn{} H1.Frame{cl, te, h, c, kp}:
      e
    case H1.KOther{} f:
      e

# the first Content-Length, a: the length is now a, or bad
law first_len:
  for +cl: H1.CL
  for +a: Nat
  {lenish(a, H1.cl_merge(cl, Some{a})) == True{} : Bool}

def first_len(cl, a):
  match cl:
    case H1.NoLen{}:
      P.nat_refl(a)
    case H1.Len{+b}:
      eq_lenish(Nat.is_eq(b, a), b, a, {==})
    case H1.LenBad{}:
      {==}

law step_first:
  for +fr: H1.Frame
  for +v: String
  for +a: Nat
  for d: {Laws.digits(v) == Some{a} : Maybe<&2, Nat>}
  {lenish(a, Laws.fcl(H1.frame.step(H1.KLen{}, fr, v))) == True{} : Bool}

def step_first(fr, v, a, d):
  match fr:
    case H1.Frame{cl, te, h, c, kp}:
      %Equal.sym(Maybe<&2, Nat>, Laws.digits(v), Some{a}, d) : {lenish(a, H1.cl_merge(cl, _)) == True{} : Bool}
      first_len(cl, a)

# a second Content-Length, b, that is not a: the length is bad
law conflict:
  for +s: Bool
  for +c: Nat
  for +a: Nat
  for +b: Nat
  for h: {Nat.is_eq(c, b) == s : Bool}
  for e: {Nat.is_eq(c, a) == True{} : Bool}
  for ne: {Nat.is_eq(a, b) == False{} : Bool}
  {H1.cl_merge.eq(s, c) == H1.LenBad{} : H1.CL}

def conflict(s, c, a, b, h, e, ne):
  match s:
    case True{}:
      P.absurd_t({H1.cl_merge.eq(True{}, c) == H1.LenBad{} : H1.CL}, Equal.trans(Bool, True{}, Nat.is_eq(a, b), False{}, Equal.sym(Bool, Nat.is_eq(a, b), True{}, P.nat_trans(c, a, b, e, h)), ne))
    case False{}:
      {==}

law second_len:
  for +cl: H1.CL
  for +a: Nat
  for +b: Nat
  for e: {lenish(a, cl) == True{} : Bool}
  for ne: {Nat.is_eq(a, b) == False{} : Bool}
  {H1.cl_merge(cl, Some{b}) == H1.LenBad{} : H1.CL}

def second_len(cl, a, b, e, ne):
  match cl:
    case H1.NoLen{}:
      P.absurd({H1.cl_merge(H1.NoLen{}, Some{b}) == H1.LenBad{} : H1.CL}, e)
    case H1.Len{+c}:
      conflict(Nat.is_eq(c, b), c, a, b, {==}, e, ne)
    case H1.LenBad{}:
      {==}

law step_second:
  for +fr: H1.Frame
  for +v: String
  for +a: Nat
  for +b: Nat
  for d: {Laws.digits(v) == Some{b} : Maybe<&2, Nat>}
  for e: {lenish(a, Laws.fcl(fr)) == True{} : Bool}
  for ne: {Nat.is_eq(a, b) == False{} : Bool}
  {Laws.fcl(H1.frame.step(H1.KLen{}, fr, v)) == H1.LenBad{} : H1.CL}

def step_second(fr, v, a, b, d, e, ne):
  match fr:
    case H1.Frame{cl, te, h, c, kp}:
      %Equal.sym(Maybe<&2, Nat>, Laws.digits(v), Some{b}, d) : {H1.cl_merge(cl, _) == H1.LenBad{} : H1.CL}
      second_len(cl, a, b, e, ne)

law mid_then:
  for +mid: List<&2, H.Header>
  for +n2: String
  for +v2: String
  for +post: List<&2, H.Header>
  for +fr: H1.Frame
  for +acc: List<&2, H.Header>
  for +a: Nat
  for +b: Nat
  for e2: {P.lows(n2) == "content-length" : String}
  for d2: {Laws.digits(v2) == Some{b} : Maybe<&2, Nat>}
  for ne: {Nat.is_eq(a, b) == False{} : Bool}
  for e: {lenish(a, Laws.fcl(fr)) == True{} : Bool}
  {Laws.cl_of(H1.scan(List.append(&2, H.Header, mid, Con{H.Header{n2, v2}, post}), fr, acc)) == H1.LenBad{} : H1.CL}

def mid_then(mid, n2, v2, post, fr, acc, a, b, e2, d2, ne, e):
  match mid:
    case Nil{}:
      %Equal.sym(H1.HKind, H1.kind(n2), H1.KLen{}, kind_len(n2, e2)) : {Laws.cl_of(H1.scan(post, H1.frame.step(_, fr, v2), Con{H.Header{n2, v2}, acc})) == H1.LenBad{} : H1.CL}
      Laws.cl_bad_stays(post, H1.frame.step(H1.KLen{}, fr, v2), Con{H.Header{n2, v2}, acc}, step_second(fr, v2, a, b, d2, e, ne))
    case Con{H.Header{+k, +w}, t}:
      mid_then(t, n2, v2, post, H1.frame.step(H1.kind(k), fr, w), Con{H.Header{k, w}, acc}, a, b, e2, d2, ne, step_lenish(H1.kind(k), fr, w, a, e))

def Laws.cl_twice(pre, n1, v1, mid, n2, v2, post, fr, acc, a, b, e1, e2, d1, d2, ne):
  match pre:
    case Nil{}:
      %Equal.sym(H1.HKind, H1.kind(n1), H1.KLen{}, kind_len(n1, e1)) : {Laws.cl_of(H1.scan(List.append(&2, H.Header, mid, Con{H.Header{n2, v2}, post}), H1.frame.step(_, fr, v1), Con{H.Header{n1, v1}, acc})) == H1.LenBad{} : H1.CL}
      mid_then(mid, n2, v2, post, H1.frame.step(H1.KLen{}, fr, v1), Con{H.Header{n1, v1}, acc}, a, b, e2, d2, ne, step_first(fr, v1, a, d1))
    case Con{H.Header{+k, +w}, t}:
      Laws.cl_twice(t, n1, v1, mid, n2, v2, post, H1.frame.step(H1.kind(k), fr, w), Con{H.Header{k, w}, acc}, a, b, e1, e2, d1, d2, ne)
