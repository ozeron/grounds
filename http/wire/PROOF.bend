import Base
import ./LAWS.bend as Laws
import ./http1.bend as H1
import ./bytes.bend as B
import ../core/headers.bend as H
import ../core/method.bend as M
import ../core/text.bend as T
import ../core/proof/text.bend as P

# Names, in any case
# -----

law kind_te:
  for +n: String
  for +e: {P.lows(n) == "transfer-encoding" : String}
  {H1.kind(n) == H1.KTe{} : H1.HKind}

def kind_te(n, e):
  %Equal.sym(Bool, T.same_ci(n, "content-length", True{}), T.same(P.lows(n), P.lows("content-length"), True{}), P.same_ci_lows(n, "content-length", True{})) : {H1.kind.pick(_, H1.KLen{}, H1.kind.pick(T.same_ci(n, "transfer-encoding", True{}), H1.KTe{}, H1.kind.pick(T.same_ci(n, "host", True{}), H1.KHost{}, H1.kind.pick(T.same_ci(n, "connection", True{}), H1.KConn{}, H1.KOther{})))) == H1.KTe{} : H1.HKind}
  %Equal.sym(Bool, T.same_ci(n, "transfer-encoding", True{}), T.same(P.lows(n), P.lows("transfer-encoding"), True{}), P.same_ci_lows(n, "transfer-encoding", True{})) : {H1.kind.pick(T.same(P.lows(n), P.lows("content-length"), True{}), H1.KLen{}, H1.kind.pick(_, H1.KTe{}, H1.kind.pick(T.same_ci(n, "host", True{}), H1.KHost{}, H1.kind.pick(T.same_ci(n, "connection", True{}), H1.KConn{}, H1.KOther{})))) == H1.KTe{} : H1.HKind}
  %Equal.sym(String, P.lows(n), "transfer-encoding", e) : {H1.kind.pick(T.same(_, P.lows("content-length"), True{}), H1.KLen{}, H1.kind.pick(T.same(_, P.lows("transfer-encoding"), True{}), H1.KTe{}, H1.kind.pick(T.same_ci(n, "host", True{}), H1.KHost{}, H1.kind.pick(T.same_ci(n, "connection", True{}), H1.KConn{}, H1.KOther{})))) == H1.KTe{} : H1.HKind}
  {==}

law kind_len:
  for +n: String
  for +e: {P.lows(n) == "content-length" : String}
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
  for +e: {Laws.fte(fr) == True{} : Bool}
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
  for +e: {Laws.fte(fr) == True{} : Bool}
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
  for +e: {Laws.fcl(fr) == H1.LenBad{} : H1.CL}
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

law merge_eq_has:
  for +same: Bool
  for +a: Nat
  {Laws.has_len(H1.cl_merge.eq(same, a)) == True{} : Bool}

def merge_eq_has(same, a):
  match same:
    case True{}:
      {==}
    case False{}:
      {==}

# a Content-Length leaves a length, or a bad one, whatever came before
law merge_has:
  for +cl: H1.CL
  for +d: Maybe<&2, Nat>
  {Laws.has_len(H1.cl_merge(cl, d)) == True{} : Bool}

def merge_has(cl, d):
  match cl d:
    case H1.NoLen{} Some{_}:
      {==}
    case H1.NoLen{} None{}:
      {==}
    case H1.Len{+a} Some{+b}:
      merge_eq_has(Nat.is_eq(a, b), a)
    case H1.Len{_} None{}:
      {==}
    case H1.LenBad{} Some{_}:
      {==}
    case H1.LenBad{} None{}:
      {==}

law step_has:
  for +k: H1.HKind
  for +fr: H1.Frame
  for +v: String
  for +e: {Laws.has_len(Laws.fcl(fr)) == True{} : Bool}
  {Laws.has_len(Laws.fcl(H1.frame.step(k, fr, v))) == True{} : Bool}

def step_has(k, fr, v, e):
  match k fr:
    case H1.KLen{} H1.Frame{cl, te, h, c, kp}:
      merge_has(cl, H1.cl_digits.go(v, 0n, True{}, False{}))
    case H1.KTe{} H1.Frame{cl, te, h, c, kp}:
      e
    case H1.KHost{} H1.Frame{cl, te, h, c, kp}:
      e
    case H1.KConn{} H1.Frame{cl, te, h, c, kp}:
      e
    case H1.KOther{} f:
      e

law has_sticky:
  for +hs: List<&2, H.Header>
  for +fr: H1.Frame
  for +acc: List<&2, H.Header>
  for +e: {Laws.has_len(Laws.fcl(fr)) == True{} : Bool}
  {Laws.has_len(Laws.cl_of(H1.scan(hs, fr, acc))) == True{} : Bool}

def has_sticky(hs, fr, acc, e):
  match hs:
    case Nil{}:
      e
    case Con{H.Header{+n, +v}, t}:
      has_sticky(t, H1.frame.step(H1.kind(n), fr, v), Con{H.Header{n, v}, acc}, step_has(H1.kind(n), fr, v, e))

law has_head:
  for +post: List<&2, H.Header>
  for +fr: H1.Frame
  for +v: String
  for +acc: List<&2, H.Header>
  {Laws.has_len(Laws.cl_of(H1.scan(post, H1.frame.step(H1.KLen{}, fr, v), acc))) == True{} : Bool}

def has_head(post, fr, v, acc):
  match fr:
    case H1.Frame{cl, te, h, c, kp}:
      has_sticky(post, H1.Frame{H1.cl_merge(cl, H1.cl_digits.go(v, 0n, True{}, False{})), te, h, c, kp}, acc, merge_has(cl, H1.cl_digits.go(v, 0n, True{}, False{})))

def Laws.cl_seen(pre, n, v, post, fr, acc, e):
  match pre:
    case Nil{}:
      %Equal.sym(H1.HKind, H1.kind(n), H1.KLen{}, kind_len(n, e)) : {Laws.has_len(Laws.cl_of(H1.scan(post, H1.frame.step(_, fr, v), Con{H.Header{n, v}, acc}))) == True{} : Bool}
      has_head(post, fr, v, Con{H.Header{n, v}, acc})
    case Con{H.Header{+k, +w}, t}:
      Laws.cl_seen(t, n, v, post, H1.frame.step(H1.kind(k), fr, w), Con{H.Header{k, w}, acc}, e)

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
  for +h: {Nat.is_eq(b, a) == s : Bool}
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
  for +e: {Nat.is_eq(b, a) == True{} : Bool}
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
  for +e: {lenish(a, cl) == True{} : Bool}
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
  for +e: {lenish(a, Laws.fcl(fr)) == True{} : Bool}
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
  for +d: {Laws.digits(v) == Some{a} : Maybe<&2, Nat>}
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
  for +h: {Nat.is_eq(c, b) == s : Bool}
  for +e: {Nat.is_eq(c, a) == True{} : Bool}
  for +ne: {Nat.is_eq(a, b) == False{} : Bool}
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
  for +e: {lenish(a, cl) == True{} : Bool}
  for +ne: {Nat.is_eq(a, b) == False{} : Bool}
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
  for +d: {Laws.digits(v) == Some{b} : Maybe<&2, Nat>}
  for +e: {lenish(a, Laws.fcl(fr)) == True{} : Bool}
  for +ne: {Nat.is_eq(a, b) == False{} : Bool}
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
  for +e2: {P.lows(n2) == "content-length" : String}
  for +d2: {Laws.digits(v2) == Some{b} : Maybe<&2, Nat>}
  for +ne: {Nat.is_eq(a, b) == False{} : Bool}
  for +e: {lenish(a, Laws.fcl(fr)) == True{} : Bool}
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

# End to end
# ----------

law frame_te:
  for +s: H1.Scanned
  for +m: M.Method
  for +t: String
  for +ver: H1.Version
  for +rest: B.Bytes
  for +max: Nat
  for +e: {Laws.te_of(s) == True{} : Bool}
  {H1.req.frame(s, m, t, ver, rest, max) == Laws.by_te(s, m, t, ver, rest, max) : H1.Parsed}

def frame_te(s, m, t, ver, rest, max, e):
  match s:
    case H1.Scanned{hs, H1.Frame{cl, te, +h, +c, +k}}:
      %Equal.sym(Bool, te, True{}, e) : {H1.req.check(_, H1.hosts_ok(ver, h), cl, H1.close_of(ver, c, k), max, rest, m, t, hs) == H1.req.te(cl, H1.hosts_ok(ver, h), H1.close_of(ver, c, k), max, rest, m, t, hs) : H1.Parsed}
      {==}

law te_len:
  for +cl: H1.CL
  for +hosts: Bool
  for +close: Bool
  for +max: Nat
  for +rest: B.Bytes
  for +m: M.Method
  for +t: String
  for +hs: List<&2, H.Header>
  for e: {Laws.has_len(cl) == True{} : Bool}
  {Laws.is_bad(H1.req.te(cl, hosts, close, max, rest, m, t, hs)) == True{} : Bool}

def te_len(cl, hosts, close, max, rest, m, t, hs, e):
  match cl:
    case H1.NoLen{}:
      P.absurd({Laws.is_bad(H1.req.te(H1.NoLen{}, hosts, close, max, rest, m, t, hs)) == True{} : Bool}, e)
    case H1.Len{_}:
      {==}
    case H1.LenBad{}:
      {==}

law by_te_len:
  for +s: H1.Scanned
  for +m: M.Method
  for +t: String
  for +ver: H1.Version
  for +rest: B.Bytes
  for +max: Nat
  for +e: {Laws.has_len(Laws.cl_of(s)) == True{} : Bool}
  {Laws.is_bad(Laws.by_te(s, m, t, ver, rest, max)) == True{} : Bool}

def by_te_len(s, m, t, ver, rest, max, e):
  match s:
    case H1.Scanned{hs, H1.Frame{cl, te, +h, +c, +k}}:
      te_len(cl, H1.hosts_ok(ver, h), H1.close_of(ver, c, k), max, rest, m, t, hs, e)

law check_lenbad:
  for +te: Bool
  for +hosts: Bool
  for +close: Bool
  for +max: Nat
  for +rest: B.Bytes
  for +m: M.Method
  for +t: String
  for +hs: List<&2, H.Header>
  {Laws.is_bad(H1.req.check(te, hosts, H1.LenBad{}, close, max, rest, m, t, hs)) == True{} : Bool}

def check_lenbad(te, hosts, close, max, rest, m, t, hs):
  match te hosts:
    case True{} _:
      {==}
    case False{} False{}:
      {==}
    case False{} True{}:
      {==}

law frame_lenbad:
  for +s: H1.Scanned
  for +m: M.Method
  for +t: String
  for +ver: H1.Version
  for +rest: B.Bytes
  for +max: Nat
  for +e: {Laws.cl_of(s) == H1.LenBad{} : H1.CL}
  {Laws.is_bad(H1.req.frame(s, m, t, ver, rest, max)) == True{} : Bool}

def frame_lenbad(s, m, t, ver, rest, max, e):
  match s:
    case H1.Scanned{hs, H1.Frame{cl, te, +h, +c, +k}}:
      %Equal.sym(H1.CL, cl, H1.LenBad{}, e) : {Laws.is_bad(H1.req.check(te, H1.hosts_ok(ver, h), _, H1.close_of(ver, c, k), max, rest, m, t, hs)) == True{} : Bool}
      check_lenbad(te, H1.hosts_ok(ver, h), H1.close_of(ver, c, k), max, rest, m, t, hs)

law fields_bad:
  for +f: H1.Fields
  for +m: M.Method
  for +t: String
  for +ver: H1.Version
  for +rest: B.Bytes
  for +max: Nat
  for +e: {Laws.is_err(f) == True{} : Bool}
  {Laws.is_bad(H1.req.fields(f, m, t, ver, rest, max)) == True{} : Bool}

def fields_bad(f, m, t, ver, rest, max, e):
  match f:
    case H1.FErr{_}:
      {==}
    case H1.FOk{hs}:
      P.absurd({Laws.is_bad(H1.req.fields(H1.FOk{hs}, m, t, ver, rest, max)) == True{} : Bool}, e)

def Frame0() -> H1.Frame:
  Laws.Frame0()

def Laws.parse_te(buf, mh, mb, first, hl, rest, m, t, ver, hs, pre, n, v, post, es, el, ef, eo, en):
  %Equal.sym(H1.Split, H1.split.go(buf, B.BNil{}, [], 0, mh, False{}), H1.Lines{Con{first, hl}, rest}, es) : {H1.req.lines(_, U32.to_nat(mb)) == Laws.by_te(H1.scan(List.append(&2, H.Header, pre, Con{H.Header{n, v}, post}), Frame0(), []), m, t, ver, rest, U32.to_nat(mb)) : H1.Parsed}
  %Equal.sym(H1.Line, H1.request_line(H1.split_sp.go(first, B.BNil{}, [])), H1.Line{m, t, ver}, el) : {H1.req.line(_, hl, rest, U32.to_nat(mb)) == Laws.by_te(H1.scan(List.append(&2, H.Header, pre, Con{H.Header{n, v}, post}), Frame0(), []), m, t, ver, rest, U32.to_nat(mb)) : H1.Parsed}
  %Equal.sym(H1.Fields, H1.fields(hl, H1.FOk{[]}), H1.FOk{hs}, ef) : {H1.req.fields(_, m, t, ver, rest, U32.to_nat(mb)) == Laws.by_te(H1.scan(List.append(&2, H.Header, pre, Con{H.Header{n, v}, post}), Frame0(), []), m, t, ver, rest, U32.to_nat(mb)) : H1.Parsed}
  %Equal.sym(List<&2, H.Header>, List.reverse(&2, H.Header, hs), List.append(&2, H.Header, pre, Con{H.Header{n, v}, post}), eo) : {H1.req.frame(H1.scan(_, Frame0(), []), m, t, ver, rest, U32.to_nat(mb)) == Laws.by_te(H1.scan(List.append(&2, H.Header, pre, Con{H.Header{n, v}, post}), Frame0(), []), m, t, ver, rest, U32.to_nat(mb)) : H1.Parsed}
  frame_te(H1.scan(List.append(&2, H.Header, pre, Con{H.Header{n, v}, post}), Frame0(), []), m, t, ver, rest, U32.to_nat(mb), Laws.te_seen(pre, n, v, post, Frame0(), [], en))

def Laws.parse_te_cl(buf, mh, mb, first, hl, rest, m, t, ver, hs, pre, n, v, post, pre2, n2, v2, post2, es, el, ef, eo, eo2, en, en2):
  %Equal.sym(H1.Parsed, H1.parse(buf, mh, mb), Laws.by_te(H1.scan(List.append(&2, H.Header, pre, Con{H.Header{n, v}, post}), Frame0(), []), m, t, ver, rest, U32.to_nat(mb)), Laws.parse_te(buf, mh, mb, first, hl, rest, m, t, ver, hs, pre, n, v, post, es, el, ef, eo, en)) : {Laws.is_bad(_) == True{} : Bool}
  %Equal.trans(List<&2, H.Header>, List.append(&2, H.Header, pre2, Con{H.Header{n2, v2}, post2}), List.reverse(&2, H.Header, hs), List.append(&2, H.Header, pre, Con{H.Header{n, v}, post}), Equal.sym(List<&2, H.Header>, List.reverse(&2, H.Header, hs), List.append(&2, H.Header, pre2, Con{H.Header{n2, v2}, post2}), eo2), eo) : {Laws.is_bad(Laws.by_te(H1.scan(_, Frame0(), []), m, t, ver, rest, U32.to_nat(mb))) == True{} : Bool}
  by_te_len(H1.scan(List.append(&2, H.Header, pre2, Con{H.Header{n2, v2}, post2}), Frame0(), []), m, t, ver, rest, U32.to_nat(mb), Laws.cl_seen(pre2, n2, v2, post2, Frame0(), [], en2))

def Laws.parse_cl_twice(buf, mh, mb, first, hl, rest, m, t, ver, hs, pre, n1, v1, mid, n2, v2, post, a, b, es, el, ef, eo, e1, e2, d1, d2, ne):
  %Equal.sym(H1.Split, H1.split.go(buf, B.BNil{}, [], 0, mh, False{}), H1.Lines{Con{first, hl}, rest}, es) : {Laws.is_bad(H1.req.lines(_, U32.to_nat(mb))) == True{} : Bool}
  %Equal.sym(H1.Line, H1.request_line(H1.split_sp.go(first, B.BNil{}, [])), H1.Line{m, t, ver}, el) : {Laws.is_bad(H1.req.line(_, hl, rest, U32.to_nat(mb))) == True{} : Bool}
  %Equal.sym(H1.Fields, H1.fields(hl, H1.FOk{[]}), H1.FOk{hs}, ef) : {Laws.is_bad(H1.req.fields(_, m, t, ver, rest, U32.to_nat(mb))) == True{} : Bool}
  %Equal.sym(List<&2, H.Header>, List.reverse(&2, H.Header, hs), List.append(&2, H.Header, pre, Con{H.Header{n1, v1}, List.append(&2, H.Header, mid, Con{H.Header{n2, v2}, post})}), eo) : {Laws.is_bad(H1.req.frame(H1.scan(_, Frame0(), []), m, t, ver, rest, U32.to_nat(mb))) == True{} : Bool}
  frame_lenbad(H1.scan(List.append(&2, H.Header, pre, Con{H.Header{n1, v1}, List.append(&2, H.Header, mid, Con{H.Header{n2, v2}, post})}), Frame0(), []), m, t, ver, rest, U32.to_nat(mb), Laws.cl_twice(pre, n1, v1, mid, n2, v2, post, Frame0(), [], a, b, e1, e2, d1, d2, ne))

def Laws.parse_obs_fold(buf, mh, mb, first, pre, w, l, post, rest, m, t, ver, es, el, e):
  %Equal.sym(H1.Split, H1.split.go(buf, B.BNil{}, [], 0, mh, False{}), H1.Lines{Con{first, List.append(&2, B.Bytes, pre, Con{B.BCon{w, l}, post})}, rest}, es) : {Laws.is_bad(H1.req.lines(_, U32.to_nat(mb))) == True{} : Bool}
  %Equal.sym(H1.Line, H1.request_line(H1.split_sp.go(first, B.BNil{}, [])), H1.Line{m, t, ver}, el) : {Laws.is_bad(H1.req.line(_, List.append(&2, B.Bytes, pre, Con{B.BCon{w, l}, post}), rest, U32.to_nat(mb))) == True{} : Bool}
  fields_bad(H1.fields(List.append(&2, B.Bytes, pre, Con{B.BCon{w, l}, post}), H1.FOk{[]}), m, t, ver, rest, U32.to_nat(mb), Laws.obs_fold(pre, w, l, post, H1.FOk{[]}, e))

# CR and LF only as line ends
# ---------------------------

law unsafe_sticky:
  for +t: String
  {H1.unsafe(t, True{}) == True{} : Bool}

def unsafe_sticky(t):
  match t:
    case SNil{}:
      {==}
    case SCon{Chr{x}, r}:
      unsafe_sticky(r)

law split_char:
  for +s: Bool
  for +x: U32
  for +t: String
  for +h: {H1.unsafe.char(x) == s : Bool}
  for +e: {H1.unsafe(t, s) == False{} : Bool}
  {H1.unsafe.char(x) == False{} : Bool}

def split_char(s, x, t, h, e):
  match s:
    case True{}:
      P.absurd_t({H1.unsafe.char(x) == False{} : Bool}, Equal.trans(Bool, True{}, H1.unsafe(t, True{}), False{}, Equal.sym(Bool, H1.unsafe(t, True{}), True{}, unsafe_sticky(t)), e))
    case False{}:
      h

law split_tail:
  for +s: Bool
  for +t: String
  for +e: {H1.unsafe(t, s) == False{} : Bool}
  {H1.unsafe(t, False{}) == False{} : Bool}

def split_tail(s, t, e):
  match s:
    case True{}:
      P.absurd_t({H1.unsafe(t, False{}) == False{} : Bool}, Equal.trans(Bool, True{}, H1.unsafe(t, True{}), False{}, Equal.sym(Bool, H1.unsafe(t, True{}), True{}, unsafe_sticky(t)), e))
    case False{}:
      e

law clean_step:
  for +x: U32
  for +acc: String
  for +lf: {U32.is_eq(x, 10) == False{} : Bool}
  for +cx: {H1.unsafe.char(x) == False{} : Bool}
  {Laws.rok(SCon{Chr{x}, acc}, False{}) == Laws.rok(acc, False{}) : Bool}

def clean_step(x, acc, lf, cx):
  %Equal.sym(Bool, U32.is_eq(x, 10), False{}, lf) : {Bool.and(Bool.or(_, Bool.not(H1.unsafe.char(x))), Laws.rok(acc, _)) == Laws.rok(acc, False{}) : Bool}
  %Equal.sym(Bool, H1.unsafe.char(x), False{}, cx) : {Bool.and(Bool.or(False{}, Bool.not(_)), Laws.rok(acc, False{})) == Laws.rok(acc, False{}) : Bool}
  {==}

# a String with no CR, LF or NUL, pushed onto acc, reads as acc does
law clean_rgo:
  for +s: String
  for +acc: String
  for +e: {H1.unsafe(s, False{}) == False{} : Bool}
  {Laws.rok(String.reverse.go(s, acc), False{}) == Laws.rok(acc, False{}) : Bool}

def clean_rgo(s, acc, e):
  match s:
    case SNil{}:
      {==}
    case SCon{Chr{+x}, t}:
      Equal.trans(Bool, Laws.rok(String.reverse.go(t, SCon{Chr{x}, acc}), False{}), Laws.rok(SCon{Chr{x}, acc}, False{}), Laws.rok(acc, False{}),
        clean_rgo(t, SCon{Chr{x}, acc}, split_tail(H1.unsafe.char(x), t, e)),
        clean_step(x, acc,
          P.or_false_l(U32.is_eq(x, 10), U32.is_eq(x, 13), P.or_false_r(U32.is_eq(x, 0), Bool.or(U32.is_eq(x, 10), U32.is_eq(x, 13)), split_char(H1.unsafe.char(x), x, t, {==}, e))),
          split_char(H1.unsafe.char(x), x, t, {==}, e)))

law keep_ok:
  for +drop: Bool
  for +n: String
  for +v: String
  for +out: String
  for +h: {Bool.or(H1.framing(n), Bool.or(H1.unsafe(n, False{}), H1.unsafe(v, False{}))) == drop : Bool}
  {Laws.rok(H1.heads.keep(drop, n, v, out), False{}) == Laws.rok(out, False{}) : Bool}

def keep_ok(drop, n, v, out, h):
  match drop:
    case True{}:
      {==}
    case False{}:
      Equal.trans(Bool, Laws.rok(String.reverse.go(v, String.reverse.go(": ", String.reverse.go(n, out))), False{}), Laws.rok(String.reverse.go(n, out), False{}), Laws.rok(out, False{}),
        clean_rgo(v, String.reverse.go(": ", String.reverse.go(n, out)), P.or_false_r(H1.unsafe(n, False{}), H1.unsafe(v, False{}), P.or_false_r(H1.framing(n), Bool.or(H1.unsafe(n, False{}), H1.unsafe(v, False{})), h))),
        clean_rgo(n, out, P.or_false_l(H1.unsafe(n, False{}), H1.unsafe(v, False{}), P.or_false_r(H1.framing(n), Bool.or(H1.unsafe(n, False{}), H1.unsafe(v, False{})), h))))

def Laws.crlf_only(hs, out):
  match hs:
    case Nil{}:
      {==}
    case Con{H.Header{+n, +v}, t}:
      Equal.trans(Bool, Laws.rok(H1.heads(t, H1.heads.keep(Bool.or(H1.framing(n), Bool.or(H1.unsafe(n, False{}), H1.unsafe(v, False{}))), n, v, out)), False{}), Laws.rok(H1.heads.keep(Bool.or(H1.framing(n), Bool.or(H1.unsafe(n, False{}), H1.unsafe(v, False{}))), n, v, out), False{}), Laws.rok(out, False{}),
        Laws.crlf_only(t, H1.heads.keep(Bool.or(H1.framing(n), Bool.or(H1.unsafe(n, False{}), H1.unsafe(v, False{}))), n, v, out)),
        keep_ok(Bool.or(H1.framing(n), Bool.or(H1.unsafe(n, False{}), H1.unsafe(v, False{}))), n, v, out, {==}))

def Laws.crlf_block(hs):
  Laws.crlf_only(hs, "")

# Request injection
# -----------------

law lf_of:
  for +x: U32
  for +cx: {H1.unsafe.char(x) == False{} : Bool}
  {U32.is_eq(x, 10) == False{} : Bool}

def lf_of(x, cx):
  P.or_false_l(U32.is_eq(x, 10), U32.is_eq(x, 13), P.or_false_r(U32.is_eq(x, 0), Bool.or(U32.is_eq(x, 10), U32.is_eq(x, 13)), cx))

# a char of a line, in the middle of it
law in3:
  for +x: U32
  for +t: String
  for +lf: {U32.is_eq(x, 10) == False{} : Bool}
  for +cx: {H1.unsafe.char(x) == False{} : Bool}
  {Laws.hok(SCon{Chr{x}, t}, 3) == Laws.hok(t, 3) : Bool}

def in3(x, t, lf, cx):
  %Equal.sym(Bool, U32.is_eq(x, 10), False{}, lf) : {Laws.hok(t, Bool.pick(U32, _, 1, Bool.pick(U32, H1.unsafe.char(x), 4, 3))) == Laws.hok(t, 3) : Bool}
  %Equal.sym(Bool, H1.unsafe.char(x), False{}, cx) : {Laws.hok(t, Bool.pick(U32, False{}, 1, Bool.pick(U32, _, 4, 3))) == Laws.hok(t, 3) : Bool}
  {==}

# a String with no CR, LF or NUL, pushed onto acc, in the middle of a line
law clean3:
  for +s: String
  for +acc: String
  for +e: {H1.unsafe(s, False{}) == False{} : Bool}
  {Laws.hok(String.reverse.go(s, acc), 3) == Laws.hok(acc, 3) : Bool}

def clean3(s, acc, e):
  match s:
    case SNil{}:
      {==}
    case SCon{Chr{+x}, t}:
      Equal.trans(Bool, Laws.hok(String.reverse.go(t, SCon{Chr{x}, acc}), 3), Laws.hok(SCon{Chr{x}, acc}, 3), Laws.hok(acc, 3),
        clean3(t, SCon{Chr{x}, acc}, split_tail(H1.unsafe.char(x), t, e)),
        in3(x, acc, lf_of(x, split_char(H1.unsafe.char(x), x, t, {==}, e)), split_char(H1.unsafe.char(x), x, t, {==}, e)))

# the same at a line's start, a char x of the line after it: the line
# has a char whatever s is
law clean2:
  for +s: String
  for +x: U32
  for +acc: String
  for +cx: {H1.unsafe.char(x) == False{} : Bool}
  for +e: {H1.unsafe(s, False{}) == False{} : Bool}
  {Laws.hok(String.reverse.go(s, SCon{Chr{x}, acc}), 2) == Laws.hok(acc, 3) : Bool}

def clean2(s, x, acc, cx, e):
  match s:
    case SNil{}:
      %Equal.sym(Bool, H1.unsafe.char(x), False{}, cx) : {Laws.hok(acc, Bool.pick(U32, _, 4, 3)) == Laws.hok(acc, 3) : Bool}
      {==}
    case SCon{Chr{+y}, t}:
      Equal.trans(Bool, Laws.hok(String.reverse.go(t, SCon{Chr{y}, SCon{Chr{x}, acc}}), 2), Laws.hok(SCon{Chr{x}, acc}, 3), Laws.hok(acc, 3),
        clean2(t, y, SCon{Chr{x}, acc}, split_char(H1.unsafe.char(y), y, t, {==}, e), split_tail(H1.unsafe.char(y), t, e)),
        in3(x, acc, lf_of(x, cx), cx))

law keep3:
  for +drop: Bool
  for +n: String
  for +v: String
  for +out: String
  for +h: {Bool.or(H1.framing(n), Bool.or(H1.unsafe(n, False{}), H1.unsafe(v, False{}))) == drop : Bool}
  {Laws.hok(H1.heads.keep(drop, n, v, out), 3) == Laws.hok(out, 3) : Bool}

def keep3(drop, n, v, out, h):
  match drop:
    case True{}:
      {==}
    case False{}:
      Equal.trans(Bool, Laws.hok(String.reverse.go(v, SCon{Chr{32}, SCon{Chr{58}, String.reverse.go(n, out)}}), 2), Laws.hok(String.reverse.go(n, out), 3), Laws.hok(out, 3),
        clean2(v, 32, SCon{Chr{58}, String.reverse.go(n, out)}, {==}, P.or_false_r(H1.unsafe(n, False{}), H1.unsafe(v, False{}), P.or_false_r(H1.framing(n), Bool.or(H1.unsafe(n, False{}), H1.unsafe(v, False{})), h))),
        clean3(n, out, P.or_false_l(H1.unsafe(n, False{}), H1.unsafe(v, False{}), P.or_false_r(H1.framing(n), Bool.or(H1.unsafe(n, False{}), H1.unsafe(v, False{})), h))))

# the header lines, each of a char at least, as crlf_only has it
law heads3:
  for +hs: List<&2, H.Header>
  for +out: String
  {Laws.hok(H1.heads(hs, out), 3) == Laws.hok(out, 3) : Bool}

def heads3(hs, out):
  match hs:
    case Nil{}:
      {==}
    case Con{H.Header{+n, +v}, t}:
      Equal.trans(Bool, Laws.hok(H1.heads(t, H1.heads.keep(Bool.or(H1.framing(n), Bool.or(H1.unsafe(n, False{}), H1.unsafe(v, False{}))), n, v, out)), 3), Laws.hok(H1.heads.keep(Bool.or(H1.framing(n), Bool.or(H1.unsafe(n, False{}), H1.unsafe(v, False{}))), n, v, out), 3), Laws.hok(out, 3),
        heads3(t, H1.heads.keep(Bool.or(H1.framing(n), Bool.or(H1.unsafe(n, False{}), H1.unsafe(v, False{}))), n, v, out)),
        keep3(Bool.or(H1.framing(n), Bool.or(H1.unsafe(n, False{}), H1.unsafe(v, False{}))), n, v, out, {==}))

# a String whose first char is a LF
def lf1(s: String) -> Bool:
  match s:
    case SNil{}:
      False{}
    case SCon{Chr{+x}, _}:
      U32.is_eq(x, 10)

law keep_lf:
  for +drop: Bool
  for +n: String
  for +v: String
  for +out: String
  for +e: {lf1(out) == True{} : Bool}
  {lf1(H1.heads.keep(drop, n, v, out)) == True{} : Bool}

def keep_lf(drop, n, v, out, e):
  match drop:
    case True{}:
      e
    case False{}:
      {==}

law heads_lf:
  for +hs: List<&2, H.Header>
  for +out: String
  for +e: {lf1(out) == True{} : Bool}
  {lf1(H1.heads(hs, out)) == True{} : Bool}

def heads_lf(hs, out, e):
  match hs:
    case Nil{}:
      e
    case Con{H.Header{+n, +v}, t}:
      heads_lf(t, H1.heads.keep(Bool.or(H1.framing(n), Bool.or(H1.unsafe(n, False{}), H1.unsafe(v, False{}))), n, v, out), keep_lf(Bool.or(H1.framing(n), Bool.or(H1.unsafe(n, False{}), H1.unsafe(v, False{}))), n, v, out, e))

# at a line's end, states 0 and 3 read alike
law zero3:
  for +s: String
  for +e: {lf1(s) == True{} : Bool}
  {Laws.hok(s, 0) == Laws.hok(s, 3) : Bool}

def zero3(s, e):
  match s:
    case SNil{}:
      P.absurd({Laws.hok(SNil{}, 0) == Laws.hok(SNil{}, 3) : Bool}, e)
    case SCon{Chr{+x}, t}:
      %Equal.sym(Bool, U32.is_eq(x, 10), True{}, e) : {Laws.hok(t, Bool.pick(U32, _, 1, 4)) == Laws.hok(t, Bool.pick(U32, _, 1, Bool.pick(U32, H1.unsafe.char(x), 4, 3))) : Bool}
      {==}

# a length's digits have no CR, LF or NUL
law dig_clean:
  for +x: H1.Dig
  for +out: String
  {H1.unsafe(SCon{H1.dig.char(x), out}, False{}) == H1.unsafe(out, False{}) : Bool}

def dig_clean(x, out):
  match x:
    case H1.D0{}:
      {==}
    case H1.D1{}:
      {==}
    case H1.D2{}:
      {==}
    case H1.D3{}:
      {==}
    case H1.D4{}:
      {==}
    case H1.D5{}:
      {==}
    case H1.D6{}:
      {==}
    case H1.D7{}:
      {==}
    case H1.D8{}:
      {==}
    case H1.D9{}:
      {==}

law show_clean.go:
  for +d: H1.Dec
  for +out: String
  {H1.unsafe(H1.dec.show.go(d, out), False{}) == H1.unsafe(out, False{}) : Bool}

def show_clean.go(d, out):
  match d:
    case H1.DNil{}:
      {==}
    case H1.DCon{+x, t}:
      Equal.trans(Bool, H1.unsafe(H1.dec.show.go(t, SCon{H1.dig.char(x), out}), False{}), H1.unsafe(SCon{H1.dig.char(x), out}, False{}), H1.unsafe(out, False{}),
        show_clean.go(t, SCon{H1.dig.char(x), out}), dig_clean(x, out))

law show_clean:
  for +d: H1.Dec
  {H1.unsafe(H1.dec.show(d), False{}) == False{} : Bool}

def show_clean(d):
  match d:
    case H1.DNil{}:
      {==}
    case H1.DCon{+x, t}:
      show_clean.go(H1.DCon{x, t}, "")

law len3:
  for +sized: Bool
  for +n: H1.Dec
  for +h: String
  {Laws.hok(H1.request.len(sized, n, h), 3) == Laws.hok(h, 3) : Bool}

def len3(sized, n, h):
  match sized:
    case True{}:
      clean2(H1.dec.show(n), 32, SCon{Chr{58}, String.reverse.go("content-length", h)}, {==}, show_clean(n))
    case False{}:
      {==}

law len_lf:
  for +sized: Bool
  for +n: H1.Dec
  for +h: String
  for +e: {lf1(h) == True{} : Bool}
  {lf1(H1.request.len(sized, n, h)) == True{} : Bool}

def len_lf(sized, n, h, e):
  match sized:
    case True{}:
      {==}
    case False{}:
      e

law start3:
  for +m: String
  for +target: String
  for +host: String
  for +em: {H1.unsafe(m, False{}) == False{} : Bool}
  for +et: {H1.unsafe(target, False{}) == False{} : Bool}
  for +eh: {H1.unsafe(host, False{}) == False{} : Bool}
  {Laws.hok(H1.request.start(m, target, host), 3) == True{} : Bool}

def start3(m, target, host, em, et, eh):
  Equal.trans(Bool, Laws.hok(H1.request.start(m, target, host), 3), Laws.hok(String.reverse.go(" HTTP/1.1\r\n", String.reverse.go(target, String.reverse.go(" ", String.reverse.go(m, "")))), 3), True{},
    clean2(host, 32, SCon{Chr{58}, String.reverse.go("host", String.reverse.go(" HTTP/1.1\r\n", String.reverse.go(target, String.reverse.go(" ", String.reverse.go(m, "")))))}, {==}, eh),
    Equal.trans(Bool, Laws.hok(String.reverse.go(target, String.reverse.go(" ", String.reverse.go(m, ""))), 3), Laws.hok(String.reverse.go(m, ""), 3), True{},
      clean3(target, String.reverse.go(" ", String.reverse.go(m, "")), et),
      clean3(m, "", em)))

law after_close:
  for +close: Bool
  for +l: String
  for +e0: {Laws.hok(l, 0) == True{} : Bool}
  for +e3: {Laws.hok(l, 3) == True{} : Bool}
  {Laws.hdr(String.reverse.go("\r\n", H1.request.close(close, l))) == True{} : Bool}

def after_close(close, l, e0, e3):
  match close:
    case True{}:
      e3
    case False{}:
      e0

def Laws.request_head(m, target, host, hs, n, sized, close, em, et, eh):
  after_close(close, H1.request.len(sized, n, H1.heads(hs, H1.request.start(m, target, host))),
    Equal.trans(Bool, Laws.hok(H1.request.len(sized, n, H1.heads(hs, H1.request.start(m, target, host))), 0), Laws.hok(H1.request.len(sized, n, H1.heads(hs, H1.request.start(m, target, host))), 3), True{},
      zero3(H1.request.len(sized, n, H1.heads(hs, H1.request.start(m, target, host))), len_lf(sized, n, H1.heads(hs, H1.request.start(m, target, host)), heads_lf(hs, H1.request.start(m, target, host), {==}))),
      Equal.trans(Bool, Laws.hok(H1.request.len(sized, n, H1.heads(hs, H1.request.start(m, target, host))), 3), Laws.hok(H1.heads(hs, H1.request.start(m, target, host)), 3), True{},
        len3(sized, n, H1.heads(hs, H1.request.start(m, target, host))),
        Equal.trans(Bool, Laws.hok(H1.heads(hs, H1.request.start(m, target, host)), 3), Laws.hok(H1.request.start(m, target, host), 3), True{},
          heads3(hs, H1.request.start(m, target, host)), start3(m, target, host, em, et, eh)))),
    Equal.trans(Bool, Laws.hok(H1.request.len(sized, n, H1.heads(hs, H1.request.start(m, target, host))), 3), Laws.hok(H1.heads(hs, H1.request.start(m, target, host)), 3), True{},
      len3(sized, n, H1.heads(hs, H1.request.start(m, target, host))),
      Equal.trans(Bool, Laws.hok(H1.heads(hs, H1.request.start(m, target, host)), 3), Laws.hok(H1.request.start(m, target, host), 3), True{},
        heads3(hs, H1.request.start(m, target, host)), start3(m, target, host, em, et, eh))))
