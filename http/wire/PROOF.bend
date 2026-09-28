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

# Chunked bodies read back
# ------------------------

law add_zero:
  for +a: Nat
  {Nat.add(a, 0n) == a : Nat}

def add_zero(a):
  match a:
    case 0n:
      {==}
    case 1n+p:
      Equal.cong(Nat, Nat, x => 1n+x, Nat.add(p, 0n), p, add_zero(p))

law add_succ:
  for +a: Nat
  for +b: Nat
  {Nat.add(a, 1n+b) == 1n+Nat.add(a, b) : Nat}

def add_succ(a, b):
  match a:
    case 0n:
      {==}
    case 1n+p:
      Equal.cong(Nat, Nat, x => 1n+x, Nat.add(p, 1n+b), 1n+Nat.add(p, b), add_succ(p, b))

law add_comm:
  for +a: Nat
  for +b: Nat
  {Nat.add(a, b) == Nat.add(b, a) : Nat}

def add_comm(a, b):
  match a:
    case 0n:
      Equal.sym(Nat, Nat.add(b, 0n), b, add_zero(b))
    case 1n+p:
      Equal.trans(Nat, 1n+Nat.add(p, b), 1n+Nat.add(b, p), Nat.add(b, 1n+p),
        Equal.cong(Nat, Nat, x => 1n+x, Nat.add(p, b), Nat.add(b, p), add_comm(p, b)),
        Equal.sym(Nat, Nat.add(b, 1n+p), 1n+Nat.add(b, p), add_succ(b, p)))

law add_assoc:
  for +a: Nat
  for +b: Nat
  for +c: Nat
  {Nat.add(Nat.add(a, b), c) == Nat.add(a, Nat.add(b, c)) : Nat}

def add_assoc(a, b, c):
  match a:
    case 0n:
      {==}
    case 1n+p:
      Equal.cong(Nat, Nat, x => 1n+x, Nat.add(Nat.add(p, b), c), Nat.add(p, Nat.add(b, c)), add_assoc(p, b, c))

law add_swap:
  for +b: Nat
  for +p: Nat
  for +x: Nat
  {Nat.add(b, Nat.add(p, x)) == Nat.add(p, Nat.add(b, x)) : Nat}

def add_swap(b, p, x):
  Equal.trans(Nat, Nat.add(b, Nat.add(p, x)), Nat.add(Nat.add(b, p), x), Nat.add(p, Nat.add(b, x)),
    Equal.sym(Nat, Nat.add(Nat.add(b, p), x), Nat.add(b, Nat.add(p, x)), add_assoc(b, p, x)),
    Equal.trans(Nat, Nat.add(Nat.add(b, p), x), Nat.add(Nat.add(p, b), x), Nat.add(p, Nat.add(b, x)),
      Equal.cong(Nat, Nat, y => Nat.add(y, x), Nat.add(b, p), Nat.add(p, b), add_comm(b, p)),
      add_assoc(p, b, x)))

law mul_succ:
  for +n: Nat
  for +h: Nat
  {Nat.mul(n, 1n+h) == Nat.add(n, Nat.mul(n, h)) : Nat}

def mul_succ(n, h):
  match n:
    case 0n:
      {==}
    case 1n+p:
      Equal.cong(Nat, Nat, x => 1n+x, Nat.add(h, Nat.mul(p, 1n+h)), Nat.add(p, Nat.add(h, Nat.mul(p, h))),
        Equal.trans(Nat, Nat.add(h, Nat.mul(p, 1n+h)), Nat.add(h, Nat.add(p, Nat.mul(p, h))), Nat.add(p, Nat.add(h, Nat.mul(p, h))),
          Equal.cong(Nat, Nat, y => Nat.add(h, y), Nat.mul(p, 1n+h), Nat.add(p, Nat.mul(p, h)), mul_succ(p, h)),
          add_swap(h, p, Nat.mul(p, h))))

law le_zero:
  for +m: Nat
  {Nat.is_le(0n, m) == True{} : Bool}

def le_zero(m):
  match m:
    case 0n:
      {==}
    case 1n+k:
      {==}

law le_add:
  for +a: Nat
  for +k: Nat
  {Nat.is_le(a, Nat.add(a, k)) == True{} : Bool}

def le_add(a, k):
  match a:
    case 0n:
      le_zero(k)
    case 1n+p:
      le_add(p, k)

law le_trans:
  for +a: Nat
  for +b: Nat
  for +c: Nat
  for +e1: {Nat.is_le(a, b) == True{} : Bool}
  for +e2: {Nat.is_le(b, c) == True{} : Bool}
  {Nat.is_le(a, c) == True{} : Bool}

def le_trans(a, b, c, e1, e2):
  match a b c:
    case 0n _ _:
      le_zero(c)
    case 1n+x 0n _:
      P.absurd({Nat.is_le(1n+x, c) == True{} : Bool}, e1)
    case 1n+x 1n+y 0n:
      P.absurd({Nat.is_le(1n+x, 0n) == True{} : Bool}, e2)
    case 1n+x 1n+y 1n+z:
      le_trans(x, y, z, e1, e2)

# a digit more: the size so far is at most the new size
law le_grow:
  for +x: Nat
  for +v: Nat
  {Nat.is_le(x, Nat.add(Nat.mul(16n, x), v)) == True{} : Bool}

def le_grow(x, v):
  %Equal.sym(Nat, Nat.add(Nat.add(x, Nat.mul(15n, x)), v), Nat.add(x, Nat.add(Nat.mul(15n, x), v)), add_assoc(x, Nat.mul(15n, x), v)) : {Nat.is_le(x, _) == True{} : Bool}
  le_add(x, Nat.add(Nat.mul(15n, x), v))

# what a hex count counts
law inc_hv:
  for +h: H1.Hc
  {Laws.hv(H1.hc.inc(h)) == 1n+Laws.hv(h) : Nat}

def inc_hv(h):
  match h:
    case H1.HNil{}:
      {==}
    case H1.HCon{H1.X0{}, t}:
      add_succ(Nat.mul(16n, Laws.hv(t)), 0n)
    case H1.HCon{H1.X1{}, t}:
      add_succ(Nat.mul(16n, Laws.hv(t)), 1n)
    case H1.HCon{H1.X2{}, t}:
      add_succ(Nat.mul(16n, Laws.hv(t)), 2n)
    case H1.HCon{H1.X3{}, t}:
      add_succ(Nat.mul(16n, Laws.hv(t)), 3n)
    case H1.HCon{H1.X4{}, t}:
      add_succ(Nat.mul(16n, Laws.hv(t)), 4n)
    case H1.HCon{H1.X5{}, t}:
      add_succ(Nat.mul(16n, Laws.hv(t)), 5n)
    case H1.HCon{H1.X6{}, t}:
      add_succ(Nat.mul(16n, Laws.hv(t)), 6n)
    case H1.HCon{H1.X7{}, t}:
      add_succ(Nat.mul(16n, Laws.hv(t)), 7n)
    case H1.HCon{H1.X8{}, t}:
      add_succ(Nat.mul(16n, Laws.hv(t)), 8n)
    case H1.HCon{H1.X9{}, t}:
      add_succ(Nat.mul(16n, Laws.hv(t)), 9n)
    case H1.HCon{H1.XA{}, t}:
      add_succ(Nat.mul(16n, Laws.hv(t)), 10n)
    case H1.HCon{H1.XB{}, t}:
      add_succ(Nat.mul(16n, Laws.hv(t)), 11n)
    case H1.HCon{H1.XC{}, t}:
      add_succ(Nat.mul(16n, Laws.hv(t)), 12n)
    case H1.HCon{H1.XD{}, t}:
      add_succ(Nat.mul(16n, Laws.hv(t)), 13n)
    case H1.HCon{H1.XE{}, t}:
      add_succ(Nat.mul(16n, Laws.hv(t)), 14n)
    case H1.HCon{H1.XF{}, t}:
      Equal.trans(Nat, Nat.add(Nat.mul(16n, Laws.hv(H1.hc.inc(t))), 0n), Nat.mul(16n, Laws.hv(H1.hc.inc(t))), 1n+Nat.add(Nat.mul(16n, Laws.hv(t)), 15n),
        add_zero(Nat.mul(16n, Laws.hv(H1.hc.inc(t)))),
        Equal.trans(Nat, Nat.mul(16n, Laws.hv(H1.hc.inc(t))), Nat.mul(16n, 1n+Laws.hv(t)), 1n+Nat.add(Nat.mul(16n, Laws.hv(t)), 15n),
          Equal.cong(Nat, Nat, y => Nat.mul(16n, y), Laws.hv(H1.hc.inc(t)), 1n+Laws.hv(t), inc_hv(t)),
          Equal.trans(Nat, Nat.mul(16n, 1n+Laws.hv(t)), Nat.add(16n, Nat.mul(16n, Laws.hv(t))), 1n+Nat.add(Nat.mul(16n, Laws.hv(t)), 15n),
            mul_succ(16n, Laws.hv(t)),
            Equal.cong(Nat, Nat, y => 1n+y, Nat.add(15n, Nat.mul(16n, Laws.hv(t))), Nat.add(Nat.mul(16n, Laws.hv(t)), 15n), add_comm(15n, Nat.mul(16n, Laws.hv(t)))))))

law count_hv:
  for +bs: B.Bytes
  for +h: H1.Hc
  {Laws.hv(H1.hc.count(bs, h)) == Nat.add(Laws.blen(bs), Laws.hv(h)) : Nat}

def count_hv(bs, h):
  match bs:
    case B.BNil{}:
      {==}
    case B.BCon{_, t}:
      Equal.trans(Nat, Laws.hv(H1.hc.count(t, H1.hc.inc(h))), Nat.add(Laws.blen(t), Laws.hv(H1.hc.inc(h))), 1n+Nat.add(Laws.blen(t), Laws.hv(h)),
        count_hv(t, H1.hc.inc(h)),
        Equal.trans(Nat, Nat.add(Laws.blen(t), Laws.hv(H1.hc.inc(h))), Nat.add(Laws.blen(t), 1n+Laws.hv(h)), 1n+Nat.add(Laws.blen(t), Laws.hv(h)),
          Equal.cong(Nat, Nat, y => Nat.add(Laws.blen(t), y), Laws.hv(H1.hc.inc(h)), 1n+Laws.hv(h), inc_hv(h)),
          add_succ(Laws.blen(t), Laws.hv(h))))

law count_len:
  for +bs: B.Bytes
  {Laws.hv(H1.hc.count(bs, H1.HNil{})) == Laws.blen(bs) : Nat}

def count_len(bs):
  Equal.trans(Nat, Laws.hv(H1.hc.count(bs, H1.HNil{})), Nat.add(Laws.blen(bs), 0n), Laws.blen(bs), count_hv(bs, H1.HNil{}), add_zero(Laws.blen(bs)))

# every size the decoder sees on the way to hv(h) is within max
def hmax(h: H1.Hc, +max: Nat) -> Bool:
  match h:
    case H1.HNil{}:
      True{}
    case H1.HCon{+x, +t}:
      Bool.and(hmax(t, max), Nat.is_le(Laws.hv(H1.HCon{x, t}), max))

law hmax_of:
  for +h: H1.Hc
  for +max: Nat
  for +e: {Nat.is_le(Laws.hv(h), max) == True{} : Bool}
  {hmax(h, max) == True{} : Bool}

def hmax_of(h, max, e):
  match h:
    case H1.HNil{}:
      {==}
    case H1.HCon{+x, t}:
      %Equal.sym(Bool, Nat.is_le(Laws.hv(H1.HCon{x, t}), max), True{}, e) : {Bool.and(hmax(t, max), _) == True{} : Bool}
      %Equal.sym(Bool, hmax(t, max), True{}, hmax_of(t, max, le_trans(Laws.hv(t), Laws.hv(H1.HCon{x, t}), max, le_grow(Laws.hv(t), Laws.dv(x)), e))) : {Bool.and(_, True{}) == True{} : Bool}
      {==}

# one size digit, within max
law dstep:
  for +x: H1.Hx
  for +n: Nat
  for +T: B.Bytes
  for +acc: B.Bytes
  for +tot: Nat
  for +b: Nat
  for +max: Nat
  for +any: Bool
  for +e: {Nat.is_le(Nat.add(Nat.mul(16n, n), Laws.dv(x)), max) == True{} : Bool}
  {H1.chunks.go(B.BCon{H1.hx.byte(x), T}, H1.CS{H1.CSize{n, any}, acc, tot, 1n+b}, max) == H1.chunks.go(T, H1.CS{H1.CSize{Nat.add(Nat.mul(16n, n), Laws.dv(x)), True{}}, acc, tot, b}, max) : H1.Chunked}

def dstep(x, n, T, acc, tot, b, max, any, e):
  match x:
    case H1.X0{}:
      %Equal.sym(Bool, Nat.is_le(Nat.add(Nat.mul(16n, n), 0n), max), True{}, e) : {H1.chunks.go(T, H1.c.digit(Bool.not(_), Nat.add(Nat.mul(16n, n), 0n), acc, tot, b), max) == H1.chunks.go(T, H1.CS{H1.CSize{Nat.add(Nat.mul(16n, n), 0n), True{}}, acc, tot, b}, max) : H1.Chunked}
      {==}
    case H1.X1{}:
      %Equal.sym(Bool, Nat.is_le(Nat.add(Nat.mul(16n, n), 1n), max), True{}, e) : {H1.chunks.go(T, H1.c.digit(Bool.not(_), Nat.add(Nat.mul(16n, n), 1n), acc, tot, b), max) == H1.chunks.go(T, H1.CS{H1.CSize{Nat.add(Nat.mul(16n, n), 1n), True{}}, acc, tot, b}, max) : H1.Chunked}
      {==}
    case H1.X2{}:
      %Equal.sym(Bool, Nat.is_le(Nat.add(Nat.mul(16n, n), 2n), max), True{}, e) : {H1.chunks.go(T, H1.c.digit(Bool.not(_), Nat.add(Nat.mul(16n, n), 2n), acc, tot, b), max) == H1.chunks.go(T, H1.CS{H1.CSize{Nat.add(Nat.mul(16n, n), 2n), True{}}, acc, tot, b}, max) : H1.Chunked}
      {==}
    case H1.X3{}:
      %Equal.sym(Bool, Nat.is_le(Nat.add(Nat.mul(16n, n), 3n), max), True{}, e) : {H1.chunks.go(T, H1.c.digit(Bool.not(_), Nat.add(Nat.mul(16n, n), 3n), acc, tot, b), max) == H1.chunks.go(T, H1.CS{H1.CSize{Nat.add(Nat.mul(16n, n), 3n), True{}}, acc, tot, b}, max) : H1.Chunked}
      {==}
    case H1.X4{}:
      %Equal.sym(Bool, Nat.is_le(Nat.add(Nat.mul(16n, n), 4n), max), True{}, e) : {H1.chunks.go(T, H1.c.digit(Bool.not(_), Nat.add(Nat.mul(16n, n), 4n), acc, tot, b), max) == H1.chunks.go(T, H1.CS{H1.CSize{Nat.add(Nat.mul(16n, n), 4n), True{}}, acc, tot, b}, max) : H1.Chunked}
      {==}
    case H1.X5{}:
      %Equal.sym(Bool, Nat.is_le(Nat.add(Nat.mul(16n, n), 5n), max), True{}, e) : {H1.chunks.go(T, H1.c.digit(Bool.not(_), Nat.add(Nat.mul(16n, n), 5n), acc, tot, b), max) == H1.chunks.go(T, H1.CS{H1.CSize{Nat.add(Nat.mul(16n, n), 5n), True{}}, acc, tot, b}, max) : H1.Chunked}
      {==}
    case H1.X6{}:
      %Equal.sym(Bool, Nat.is_le(Nat.add(Nat.mul(16n, n), 6n), max), True{}, e) : {H1.chunks.go(T, H1.c.digit(Bool.not(_), Nat.add(Nat.mul(16n, n), 6n), acc, tot, b), max) == H1.chunks.go(T, H1.CS{H1.CSize{Nat.add(Nat.mul(16n, n), 6n), True{}}, acc, tot, b}, max) : H1.Chunked}
      {==}
    case H1.X7{}:
      %Equal.sym(Bool, Nat.is_le(Nat.add(Nat.mul(16n, n), 7n), max), True{}, e) : {H1.chunks.go(T, H1.c.digit(Bool.not(_), Nat.add(Nat.mul(16n, n), 7n), acc, tot, b), max) == H1.chunks.go(T, H1.CS{H1.CSize{Nat.add(Nat.mul(16n, n), 7n), True{}}, acc, tot, b}, max) : H1.Chunked}
      {==}
    case H1.X8{}:
      %Equal.sym(Bool, Nat.is_le(Nat.add(Nat.mul(16n, n), 8n), max), True{}, e) : {H1.chunks.go(T, H1.c.digit(Bool.not(_), Nat.add(Nat.mul(16n, n), 8n), acc, tot, b), max) == H1.chunks.go(T, H1.CS{H1.CSize{Nat.add(Nat.mul(16n, n), 8n), True{}}, acc, tot, b}, max) : H1.Chunked}
      {==}
    case H1.X9{}:
      %Equal.sym(Bool, Nat.is_le(Nat.add(Nat.mul(16n, n), 9n), max), True{}, e) : {H1.chunks.go(T, H1.c.digit(Bool.not(_), Nat.add(Nat.mul(16n, n), 9n), acc, tot, b), max) == H1.chunks.go(T, H1.CS{H1.CSize{Nat.add(Nat.mul(16n, n), 9n), True{}}, acc, tot, b}, max) : H1.Chunked}
      {==}
    case H1.XA{}:
      %Equal.sym(Bool, Nat.is_le(Nat.add(Nat.mul(16n, n), 10n), max), True{}, e) : {H1.chunks.go(T, H1.c.digit(Bool.not(_), Nat.add(Nat.mul(16n, n), 10n), acc, tot, b), max) == H1.chunks.go(T, H1.CS{H1.CSize{Nat.add(Nat.mul(16n, n), 10n), True{}}, acc, tot, b}, max) : H1.Chunked}
      {==}
    case H1.XB{}:
      %Equal.sym(Bool, Nat.is_le(Nat.add(Nat.mul(16n, n), 11n), max), True{}, e) : {H1.chunks.go(T, H1.c.digit(Bool.not(_), Nat.add(Nat.mul(16n, n), 11n), acc, tot, b), max) == H1.chunks.go(T, H1.CS{H1.CSize{Nat.add(Nat.mul(16n, n), 11n), True{}}, acc, tot, b}, max) : H1.Chunked}
      {==}
    case H1.XC{}:
      %Equal.sym(Bool, Nat.is_le(Nat.add(Nat.mul(16n, n), 12n), max), True{}, e) : {H1.chunks.go(T, H1.c.digit(Bool.not(_), Nat.add(Nat.mul(16n, n), 12n), acc, tot, b), max) == H1.chunks.go(T, H1.CS{H1.CSize{Nat.add(Nat.mul(16n, n), 12n), True{}}, acc, tot, b}, max) : H1.Chunked}
      {==}
    case H1.XD{}:
      %Equal.sym(Bool, Nat.is_le(Nat.add(Nat.mul(16n, n), 13n), max), True{}, e) : {H1.chunks.go(T, H1.c.digit(Bool.not(_), Nat.add(Nat.mul(16n, n), 13n), acc, tot, b), max) == H1.chunks.go(T, H1.CS{H1.CSize{Nat.add(Nat.mul(16n, n), 13n), True{}}, acc, tot, b}, max) : H1.Chunked}
      {==}
    case H1.XE{}:
      %Equal.sym(Bool, Nat.is_le(Nat.add(Nat.mul(16n, n), 14n), max), True{}, e) : {H1.chunks.go(T, H1.c.digit(Bool.not(_), Nat.add(Nat.mul(16n, n), 14n), acc, tot, b), max) == H1.chunks.go(T, H1.CS{H1.CSize{Nat.add(Nat.mul(16n, n), 14n), True{}}, acc, tot, b}, max) : H1.Chunked}
      {==}
    case H1.XF{}:
      %Equal.sym(Bool, Nat.is_le(Nat.add(Nat.mul(16n, n), 15n), max), True{}, e) : {H1.chunks.go(T, H1.c.digit(Bool.not(_), Nat.add(Nat.mul(16n, n), 15n), acc, tot, b), max) == H1.chunks.go(T, H1.CS{H1.CSize{Nat.add(Nat.mul(16n, n), 15n), True{}}, acc, tot, b}, max) : H1.Chunked}
      {==}

def anyh(any: Bool, h: H1.Hc) -> Bool:
  match h:
    case H1.HNil{}:
      any
    case H1.HCon{_, _}:
      True{}

# all the size digits: the decoder arrives at the count they write
law hex:
  for +h: H1.Hc
  for +Z: B.Bytes
  for +acc: B.Bytes
  for +tot: Nat
  for +b: Nat
  for +any: Bool
  for +max: Nat
  for +e: {hmax(h, max) == True{} : Bool}
  {H1.chunks.go(H1.hc.bytes(h, Z), H1.CS{H1.CSize{0n, any}, acc, tot, Nat.add(Laws.hlen(h), b)}, max) == H1.chunks.go(Z, H1.CS{H1.CSize{Laws.hv(h), anyh(any, h)}, acc, tot, b}, max) : H1.Chunked}

def hex(h, Z, acc, tot, b, any, max, e):
  match h:
    case H1.HNil{}:
      {==}
    case H1.HCon{+x, t}:
      %add_succ(Laws.hlen(t), b) : {H1.chunks.go(H1.hc.bytes(t, B.BCon{H1.hx.byte(x), Z}), H1.CS{H1.CSize{0n, any}, acc, tot, _}, max) == H1.chunks.go(Z, H1.CS{H1.CSize{Laws.hv(H1.HCon{x, t}), True{}}, acc, tot, b}, max) : H1.Chunked}
      Equal.trans(H1.Chunked, H1.chunks.go(H1.hc.bytes(t, B.BCon{H1.hx.byte(x), Z}), H1.CS{H1.CSize{0n, any}, acc, tot, Nat.add(Laws.hlen(t), 1n+b)}, max), H1.chunks.go(B.BCon{H1.hx.byte(x), Z}, H1.CS{H1.CSize{Laws.hv(t), anyh(any, t)}, acc, tot, 1n+b}, max), H1.chunks.go(Z, H1.CS{H1.CSize{Laws.hv(H1.HCon{x, t}), True{}}, acc, tot, b}, max),
        hex(t, B.BCon{H1.hx.byte(x), Z}, acc, tot, 1n+b, any, max, P.and_true_l(hmax(t, max), Nat.is_le(Laws.hv(H1.HCon{x, t}), max), e)),
        dstep(x, Laws.hv(t), Z, acc, tot, b, max, anyh(any, t), P.and_true_r(hmax(t, max), Nat.is_le(Laws.hv(H1.HCon{x, t}), max), e)))

# a chunk's data bytes go to the body, one at a time
law data:
  for +t: B.Bytes
  for +x: U32
  for +T: B.Bytes
  for +acc: B.Bytes
  for +tot: Nat
  for +bud: Nat
  for +max: Nat
  {H1.chunks.go(B.BCon{x, B.cat(t, T)}, H1.CS{H1.CData{1n+Laws.blen(t)}, acc, tot, bud}, max) == H1.chunks.go(T, H1.CS{H1.CDataCR{}, B.rev.go(B.BCon{x, t}, acc), tot, bud}, max) : H1.Chunked}

def data(t, x, T, acc, tot, bud, max):
  match t:
    case B.BNil{}:
      {==}
    case B.BCon{+y, u}:
      data(u, y, T, B.BCon{x, acc}, tot, bud, max)

law cat_hc:
  for +h: H1.Hc
  for +Y: B.Bytes
  for +T: B.Bytes
  {B.cat(H1.hc.bytes(h, Y), T) == H1.hc.bytes(h, B.cat(Y, T)) : B.Bytes}

def cat_hc(h, Y, T):
  match h:
    case H1.HNil{}:
      {==}
    case H1.HCon{+x, t}:
      cat_hc(t, B.BCon{H1.hx.byte(x), Y}, T)

law cat_assoc:
  for +a: B.Bytes
  for +b: B.Bytes
  for +c: B.Bytes
  {B.cat(B.cat(a, b), c) == B.cat(a, B.cat(b, c)) : B.Bytes}

def cat_assoc(a, b, c):
  match a:
    case B.BNil{}:
      {==}
    case B.BCon{+x, t}:
      Equal.cong(B.Bytes, B.Bytes, y => B.BCon{x, y}, B.cat(B.cat(t, b), c), B.cat(t, B.cat(b, c)), cat_assoc(t, b, c))

law cat_nil:
  for +a: B.Bytes
  {B.cat(a, B.BNil{}) == a : B.Bytes}

def cat_nil(a):
  match a:
    case B.BNil{}:
      {==}
    case B.BCon{+x, t}:
      Equal.cong(B.Bytes, B.Bytes, y => B.BCon{x, y}, B.cat(t, B.BNil{}), t, cat_nil(t))

law rev_cat:
  for +a: B.Bytes
  for +b: B.Bytes
  for +acc: B.Bytes
  {B.rev.go(B.cat(a, b), acc) == B.rev.go(b, B.rev.go(a, acc)) : B.Bytes}

def rev_cat(a, b, acc):
  match a:
    case B.BNil{}:
      {==}
    case B.BCon{+x, t}:
      rev_cat(t, b, B.BCon{x, acc})

law rev_rev:
  for +a: B.Bytes
  for +b: B.Bytes
  for +c: B.Bytes
  {B.rev.go(B.rev.go(a, b), c) == B.rev.go(b, B.cat(a, c)) : B.Bytes}

def rev_rev(a, b, c):
  match a:
    case B.BNil{}:
      {==}
    case B.BCon{+x, t}:
      rev_rev(t, B.BCon{x, b}, c)

# the body so far, reversed, after each piece
def racc(ps: List<&2, B.Bytes>, acc: B.Bytes) -> B.Bytes:
  match ps:
    case Nil{}:
      acc
    case Con{p, t}:
      racc(t, B.rev.go(p, acc))

law racc_joined:
  for +ps: List<&2, B.Bytes>
  for +acc: B.Bytes
  {racc(ps, acc) == B.rev.go(Laws.joined(ps), acc) : B.Bytes}

def racc_joined(ps, acc):
  match ps:
    case Nil{}:
      {==}
    case Con{+p, t}:
      Equal.trans(B.Bytes, racc(t, B.rev.go(p, acc)), B.rev.go(Laws.joined(t), B.rev.go(p, acc)), B.rev.go(B.cat(p, Laws.joined(t)), acc),
        racc_joined(t, B.rev.go(p, acc)),
        Equal.sym(B.Bytes, B.rev.go(B.cat(p, Laws.joined(t)), acc), B.rev.go(Laws.joined(t), B.rev.go(p, acc)), rev_cat(p, Laws.joined(t), acc)))

# the bytes of a chunk, as the decoder reads them
law chunk_bytes:
  for +x: U32
  for +u: B.Bytes
  for +T: B.Bytes
  {B.cat(H1.chunk(B.BCon{x, u}), T) == H1.hc.bytes(H1.hc.count(B.BCon{x, u}, H1.HNil{}), B.BCon{13, B.BCon{10, B.BCon{x, B.cat(u, B.BCon{13, B.BCon{10, T}})}}}) : B.Bytes}

def chunk_bytes(x, u, T):
  Equal.trans(B.Bytes, B.cat(H1.chunk(B.BCon{x, u}), T), H1.hc.bytes(H1.hc.count(B.BCon{x, u}, H1.HNil{}), B.cat(B.BCon{13, B.BCon{10, B.cat(B.BCon{x, u}, B.BCon{13, B.BCon{10, B.BNil{}}})}}, T)), H1.hc.bytes(H1.hc.count(B.BCon{x, u}, H1.HNil{}), B.BCon{13, B.BCon{10, B.BCon{x, B.cat(u, B.BCon{13, B.BCon{10, T}})}}}),
    cat_hc(H1.hc.count(B.BCon{x, u}, H1.HNil{}), B.BCon{13, B.BCon{10, B.cat(B.BCon{x, u}, B.BCon{13, B.BCon{10, B.BNil{}}})}}, T),
    Equal.cong(B.Bytes, B.Bytes, y => H1.hc.bytes(H1.hc.count(B.BCon{x, u}, H1.HNil{}), B.BCon{13, B.BCon{10, B.BCon{x, y}}}), B.cat(B.cat(u, B.BCon{13, B.BCon{10, B.BNil{}}}), T), B.cat(u, B.BCon{13, B.BCon{10, T}}), cat_assoc(u, B.BCon{13, B.BCon{10, B.BNil{}}}, T)))

# after the size line: the size is the piece's length, within max
law sized:
  for +x: U32
  for +u: B.Bytes
  for +T: B.Bytes
  for +acc: B.Bytes
  for +tot: Nat
  for +b: Nat
  for +max: Nat
  for +e: {Nat.is_le(Nat.add(tot, 1n+Laws.blen(u)), max) == True{} : Bool}
  {H1.chunks.go(B.BCon{13, B.BCon{10, B.BCon{x, B.cat(u, T)}}}, H1.CS{H1.CSize{1n+Laws.blen(u), True{}}, acc, tot, 1n+1n+b}, max) == H1.chunks.go(B.BCon{x, B.cat(u, T)}, H1.CS{H1.CData{1n+Laws.blen(u)}, acc, Nat.add(tot, 1n+Laws.blen(u)), b}, max) : H1.Chunked}

def sized(x, u, T, acc, tot, b, max, e):
  %Equal.sym(Bool, Nat.is_le(Nat.add(tot, 1n+Laws.blen(u)), max), True{}, e) : {H1.chunks.go(B.BCon{x, B.cat(u, T)}, H1.c.start(False{}, _, 1n+Laws.blen(u), acc, tot, b), max) == H1.chunks.go(B.BCon{x, B.cat(u, T)}, H1.CS{H1.CData{1n+Laws.blen(u)}, acc, Nat.add(tot, 1n+Laws.blen(u)), b}, max) : H1.Chunked}
  {==}

# b <= a + b
law le_add.r:
  for +a: Nat
  for +b: Nat
  {Nat.is_le(b, Nat.add(a, b)) == True{} : Bool}

def le_add.r(a, b):
  %add_comm(b, a) : {Nat.is_le(b, _) == True{} : Bool}
  le_add(b, a)

# a count of one byte or more has a digit, whatever it started at
law inc_any:
  for +h: H1.Hc
  for +any: Bool
  {anyh(any, H1.hc.inc(h)) == True{} : Bool}

def inc_any(h, any):
  match h:
    case H1.HNil{}:
      {==}
    case H1.HCon{H1.X0{}, t}:
      {==}
    case H1.HCon{H1.X1{}, t}:
      {==}
    case H1.HCon{H1.X2{}, t}:
      {==}
    case H1.HCon{H1.X3{}, t}:
      {==}
    case H1.HCon{H1.X4{}, t}:
      {==}
    case H1.HCon{H1.X5{}, t}:
      {==}
    case H1.HCon{H1.X6{}, t}:
      {==}
    case H1.HCon{H1.X7{}, t}:
      {==}
    case H1.HCon{H1.X8{}, t}:
      {==}
    case H1.HCon{H1.X9{}, t}:
      {==}
    case H1.HCon{H1.XA{}, t}:
      {==}
    case H1.HCon{H1.XB{}, t}:
      {==}
    case H1.HCon{H1.XC{}, t}:
      {==}
    case H1.HCon{H1.XD{}, t}:
      {==}
    case H1.HCon{H1.XE{}, t}:
      {==}
    case H1.HCon{H1.XF{}, t}:
      {==}

law cnt_any:
  for +bs: B.Bytes
  for +h: H1.Hc
  for +any: Bool
  for +e: {anyh(any, h) == True{} : Bool}
  {anyh(any, H1.hc.count(bs, h)) == True{} : Bool}

def cnt_any(bs, h, any, e):
  match bs:
    case B.BNil{}:
      e
    case B.BCon{_, t}:
      cnt_any(t, H1.hc.inc(h), any, inc_any(h, any))

# after the size digits: the size is the piece's length, and its data
# and CR LF follow
law one.rest:
  for +x: U32
  for +u: B.Bytes
  for +T: B.Bytes
  for +acc: B.Bytes
  for +tot: Nat
  for +b: Nat
  for +max: Nat
  for +e: {Nat.is_le(Nat.add(tot, Laws.blen(B.BCon{x, u})), max) == True{} : Bool}
  {H1.chunks.go(B.BCon{13, B.BCon{10, B.BCon{x, B.cat(u, B.BCon{13, B.BCon{10, T}})}}}, H1.CS{H1.CSize{Laws.hv(H1.hc.count(B.BCon{x, u}, H1.HNil{})), anyh(False{}, H1.hc.count(B.BCon{x, u}, H1.HNil{}))}, acc, tot, Nat.add(4n, b)}, max) == H1.chunks.go(T, H1.CS{H1.CSize{0n, False{}}, B.rev.go(B.BCon{x, u}, acc), Nat.add(tot, Laws.blen(B.BCon{x, u})), b}, max) : H1.Chunked}

def one.rest(x, u, T, acc, tot, b, max, e):
  %Equal.sym(Bool, anyh(False{}, H1.hc.count(B.BCon{x, u}, H1.HNil{})), True{}, cnt_any(u, H1.HCon{H1.X1{}, H1.HNil{}}, False{}, {==})) : {H1.chunks.go(B.BCon{13, B.BCon{10, B.BCon{x, B.cat(u, B.BCon{13, B.BCon{10, T}})}}}, H1.CS{H1.CSize{Laws.hv(H1.hc.count(B.BCon{x, u}, H1.HNil{})), _}, acc, tot, Nat.add(4n, b)}, max) == H1.chunks.go(T, H1.CS{H1.CSize{0n, False{}}, B.rev.go(B.BCon{x, u}, acc), Nat.add(tot, Laws.blen(B.BCon{x, u})), b}, max) : H1.Chunked}
  %Equal.sym(Nat, Laws.hv(H1.hc.count(B.BCon{x, u}, H1.HNil{})), Laws.blen(B.BCon{x, u}), count_len(B.BCon{x, u})) : {H1.chunks.go(B.BCon{13, B.BCon{10, B.BCon{x, B.cat(u, B.BCon{13, B.BCon{10, T}})}}}, H1.CS{H1.CSize{_, True{}}, acc, tot, Nat.add(4n, b)}, max) == H1.chunks.go(T, H1.CS{H1.CSize{0n, False{}}, B.rev.go(B.BCon{x, u}, acc), Nat.add(tot, Laws.blen(B.BCon{x, u})), b}, max) : H1.Chunked}
  Equal.trans(H1.Chunked, H1.chunks.go(B.BCon{13, B.BCon{10, B.BCon{x, B.cat(u, B.BCon{13, B.BCon{10, T}})}}}, H1.CS{H1.CSize{1n+Laws.blen(u), True{}}, acc, tot, 1n+1n+1n+1n+b}, max),
    H1.chunks.go(B.BCon{x, B.cat(u, B.BCon{13, B.BCon{10, T}})}, H1.CS{H1.CData{1n+Laws.blen(u)}, acc, Nat.add(tot, 1n+Laws.blen(u)), 1n+1n+b}, max),
    H1.chunks.go(T, H1.CS{H1.CSize{0n, False{}}, B.rev.go(B.BCon{x, u}, acc), Nat.add(tot, Laws.blen(B.BCon{x, u})), b}, max),
    sized(x, u, B.BCon{13, B.BCon{10, T}}, acc, tot, 1n+1n+b, max, e),
    data(u, x, B.BCon{13, B.BCon{10, T}}, acc, Nat.add(tot, 1n+Laws.blen(u)), 1n+1n+b, max))

# one piece, as a chunk: its bytes join the body, and the decoder is back
# at a chunk's start
law one:
  for +x: U32
  for +u: B.Bytes
  for +T: B.Bytes
  for +acc: B.Bytes
  for +tot: Nat
  for +b: Nat
  for +max: Nat
  for +e: {Nat.is_le(Nat.add(tot, Laws.blen(B.BCon{x, u})), max) == True{} : Bool}
  {H1.chunks.go(B.cat(H1.chunk(B.BCon{x, u}), T), H1.CS{H1.CSize{0n, False{}}, acc, tot, Laws.piece(B.BCon{x, u}, b)}, max) == H1.chunks.go(T, H1.CS{H1.CSize{0n, False{}}, B.rev.go(B.BCon{x, u}, acc), Nat.add(tot, Laws.blen(B.BCon{x, u})), b}, max) : H1.Chunked}

def one(x, u, T, acc, tot, b, max, e):
  %Equal.sym(B.Bytes, B.cat(H1.chunk(B.BCon{x, u}), T), H1.hc.bytes(H1.hc.count(B.BCon{x, u}, H1.HNil{}), B.BCon{13, B.BCon{10, B.BCon{x, B.cat(u, B.BCon{13, B.BCon{10, T}})}}}), chunk_bytes(x, u, T)) : {H1.chunks.go(_, H1.CS{H1.CSize{0n, False{}}, acc, tot, Laws.piece(B.BCon{x, u}, b)}, max) == H1.chunks.go(T, H1.CS{H1.CSize{0n, False{}}, B.rev.go(B.BCon{x, u}, acc), Nat.add(tot, Laws.blen(B.BCon{x, u})), b}, max) : H1.Chunked}
  Equal.trans(H1.Chunked, H1.chunks.go(H1.hc.bytes(H1.hc.count(B.BCon{x, u}, H1.HNil{}), B.BCon{13, B.BCon{10, B.BCon{x, B.cat(u, B.BCon{13, B.BCon{10, T}})}}}), H1.CS{H1.CSize{0n, False{}}, acc, tot, Nat.add(Laws.hlen(H1.hc.count(B.BCon{x, u}, H1.HNil{})), Nat.add(4n, b))}, max),
    H1.chunks.go(B.BCon{13, B.BCon{10, B.BCon{x, B.cat(u, B.BCon{13, B.BCon{10, T}})}}}, H1.CS{H1.CSize{Laws.hv(H1.hc.count(B.BCon{x, u}, H1.HNil{})), anyh(False{}, H1.hc.count(B.BCon{x, u}, H1.HNil{}))}, acc, tot, Nat.add(4n, b)}, max),
    H1.chunks.go(T, H1.CS{H1.CSize{0n, False{}}, B.rev.go(B.BCon{x, u}, acc), Nat.add(tot, Laws.blen(B.BCon{x, u})), b}, max),
    hex(H1.hc.count(B.BCon{x, u}, H1.HNil{}), B.BCon{13, B.BCon{10, B.BCon{x, B.cat(u, B.BCon{13, B.BCon{10, T}})}}}, acc, tot, Nat.add(4n, b), False{}, max,
      hmax_of(H1.hc.count(B.BCon{x, u}, H1.HNil{}), max,
        %Equal.sym(Nat, Laws.hv(H1.hc.count(B.BCon{x, u}, H1.HNil{})), Laws.blen(B.BCon{x, u}), count_len(B.BCon{x, u})) : {Nat.is_le(_, max) == True{} : Bool}
        le_trans(Laws.blen(B.BCon{x, u}), Nat.add(tot, Laws.blen(B.BCon{x, u})), max, le_add.r(tot, Laws.blen(B.BCon{x, u})), e))),
    one.rest(x, u, T, acc, tot, b, max, e))

# the last chunk and the empty trailer end the body
law last:
  for +rest: B.Bytes
  for +acc: B.Bytes
  for +tot: Nat
  for +extra: Nat
  for +max: Nat
  {H1.chunks.go(B.cat(H1.last_chunk(), rest), H1.CS{H1.CSize{0n, False{}}, acc, tot, Nat.add(5n, extra)}, max) == H1.CDone{B.rev(acc), rest} : H1.Chunked}

def last(rest, acc, tot, extra, max):
  match rest:
    case B.BNil{}:
      %Equal.sym(Bool, Nat.is_le(0n, max), True{}, le_zero(max)) : {H1.chunks.go(B.BCon{13, B.BCon{10, B.BCon{13, B.BCon{10, B.BNil{}}}}}, H1.c.digit(Bool.not(_), 0n, acc, tot, 1n+1n+1n+1n+extra), max) == H1.CDone{B.rev(acc), B.BNil{}} : H1.Chunked}
      {==}
    case B.BCon{+y, r}:
      %Equal.sym(Bool, Nat.is_le(0n, max), True{}, le_zero(max)) : {H1.chunks.go(B.BCon{13, B.BCon{10, B.BCon{13, B.BCon{10, B.BCon{y, r}}}}}, H1.c.digit(Bool.not(_), 0n, acc, tot, 1n+1n+1n+1n+extra), max) == H1.CDone{B.rev(acc), B.BCon{y, r}} : H1.Chunked}
      {==}

law pieces:
  for +ps: List<&2, B.Bytes>
  for +rest: B.Bytes
  for +acc: B.Bytes
  for +tot: Nat
  for +extra: Nat
  for +max: Nat
  for +e: {Nat.is_le(Nat.add(tot, Laws.total(ps)), max) == True{} : Bool}
  {H1.chunks.go(Laws.stream(ps, rest), H1.CS{H1.CSize{0n, False{}}, acc, tot, Laws.frames(ps, extra)}, max) == H1.CDone{B.rev(racc(ps, acc)), rest} : H1.Chunked}

def pieces(ps, rest, acc, tot, extra, max, e):
  match ps:
    case Nil{}:
      last(rest, acc, tot, extra, max)
    case Con{B.BNil{}, t}:
      pieces(t, rest, acc, tot, extra, max, e)
    case Con{B.BCon{+x, +u}, t}:
      Equal.trans(H1.Chunked, H1.chunks.go(Laws.stream(Con{B.BCon{x, u}, t}, rest), H1.CS{H1.CSize{0n, False{}}, acc, tot, Laws.frames(Con{B.BCon{x, u}, t}, extra)}, max),
        H1.chunks.go(Laws.stream(t, rest), H1.CS{H1.CSize{0n, False{}}, B.rev.go(B.BCon{x, u}, acc), Nat.add(tot, Laws.blen(B.BCon{x, u})), Laws.frames(t, extra)}, max),
        H1.CDone{B.rev(racc(Con{B.BCon{x, u}, t}, acc)), rest},
        one(x, u, Laws.stream(t, rest), acc, tot, Laws.frames(t, extra), max,
          le_trans(Nat.add(tot, Laws.blen(B.BCon{x, u})), Nat.add(Nat.add(tot, Laws.blen(B.BCon{x, u})), Laws.total(t)), max, le_add(Nat.add(tot, Laws.blen(B.BCon{x, u})), Laws.total(t)),
            %Equal.sym(Nat, Nat.add(Nat.add(tot, Laws.blen(B.BCon{x, u})), Laws.total(t)), Nat.add(tot, Nat.add(Laws.blen(B.BCon{x, u}), Laws.total(t))), add_assoc(tot, Laws.blen(B.BCon{x, u}), Laws.total(t))) : {Nat.is_le(_, max) == True{} : Bool}
            e)),
        pieces(t, rest, B.rev.go(B.BCon{x, u}, acc), Nat.add(tot, Laws.blen(B.BCon{x, u})), extra, max,
          %Equal.sym(Nat, Nat.add(Nat.add(tot, Laws.blen(B.BCon{x, u})), Laws.total(t)), Nat.add(tot, Nat.add(Laws.blen(B.BCon{x, u}), Laws.total(t))), add_assoc(tot, Laws.blen(B.BCon{x, u}), Laws.total(t))) : {Nat.is_le(_, max) == True{} : Bool}
          e))

def Laws.chunked_reads_back(ps, rest, max, extra, e):
  Equal.trans(H1.Chunked, H1.chunks.go(Laws.stream(ps, rest), H1.CS{H1.CSize{0n, False{}}, B.BNil{}, 0n, Laws.frames(ps, extra)}, max), H1.CDone{B.rev(racc(ps, B.BNil{})), rest}, H1.CDone{Laws.joined(ps), rest},
    pieces(ps, rest, B.BNil{}, 0n, extra, max, e),
    Equal.cong(B.Bytes, H1.Chunked, y => H1.CDone{y, rest}, B.rev(racc(ps, B.BNil{})), Laws.joined(ps),
      Equal.trans(B.Bytes, B.rev.go(racc(ps, B.BNil{}), B.BNil{}), B.rev.go(B.rev.go(Laws.joined(ps), B.BNil{}), B.BNil{}), Laws.joined(ps),
        Equal.cong(B.Bytes, B.Bytes, y => B.rev.go(y, B.BNil{}), racc(ps, B.BNil{}), B.rev.go(Laws.joined(ps), B.BNil{}), racc_joined(ps, B.BNil{})),
        Equal.trans(B.Bytes, B.rev.go(B.rev.go(Laws.joined(ps), B.BNil{}), B.BNil{}), B.cat(Laws.joined(ps), B.BNil{}), Laws.joined(ps),
          rev_rev(Laws.joined(ps), B.BNil{}, B.BNil{}), cat_nil(Laws.joined(ps))))))

# Lengths read back
# -----------------

law dinc:
  for +d: H1.Dec
  {Laws.dval(H1.dec.inc(d)) == 1n+Laws.dval(d) : Nat}

def dinc(d):
  match d:
    case H1.DNil{}:
      {==}
    case H1.DCon{H1.D0{}, t}:
      add_succ(Nat.mul(10n, Laws.dval(t)), 0n)
    case H1.DCon{H1.D1{}, t}:
      add_succ(Nat.mul(10n, Laws.dval(t)), 1n)
    case H1.DCon{H1.D2{}, t}:
      add_succ(Nat.mul(10n, Laws.dval(t)), 2n)
    case H1.DCon{H1.D3{}, t}:
      add_succ(Nat.mul(10n, Laws.dval(t)), 3n)
    case H1.DCon{H1.D4{}, t}:
      add_succ(Nat.mul(10n, Laws.dval(t)), 4n)
    case H1.DCon{H1.D5{}, t}:
      add_succ(Nat.mul(10n, Laws.dval(t)), 5n)
    case H1.DCon{H1.D6{}, t}:
      add_succ(Nat.mul(10n, Laws.dval(t)), 6n)
    case H1.DCon{H1.D7{}, t}:
      add_succ(Nat.mul(10n, Laws.dval(t)), 7n)
    case H1.DCon{H1.D8{}, t}:
      add_succ(Nat.mul(10n, Laws.dval(t)), 8n)
    case H1.DCon{H1.D9{}, t}:
      Equal.trans(Nat, Nat.add(Nat.mul(10n, Laws.dval(H1.dec.inc(t))), 0n), Nat.mul(10n, Laws.dval(H1.dec.inc(t))), 1n+Nat.add(Nat.mul(10n, Laws.dval(t)), 9n),
        add_zero(Nat.mul(10n, Laws.dval(H1.dec.inc(t)))),
        Equal.trans(Nat, Nat.mul(10n, Laws.dval(H1.dec.inc(t))), Nat.mul(10n, 1n+Laws.dval(t)), 1n+Nat.add(Nat.mul(10n, Laws.dval(t)), 9n),
          Equal.cong(Nat, Nat, y => Nat.mul(10n, y), Laws.dval(H1.dec.inc(t)), 1n+Laws.dval(t), dinc(t)),
          Equal.trans(Nat, Nat.mul(10n, 1n+Laws.dval(t)), Nat.add(10n, Nat.mul(10n, Laws.dval(t))), 1n+Nat.add(Nat.mul(10n, Laws.dval(t)), 9n),
            mul_succ(10n, Laws.dval(t)),
            Equal.cong(Nat, Nat, y => 1n+y, Nat.add(9n, Nat.mul(10n, Laws.dval(t))), Nat.add(Nat.mul(10n, Laws.dval(t)), 9n), add_comm(9n, Nat.mul(10n, Laws.dval(t)))))))

law dcount:
  for +bs: B.Bytes
  for +d: H1.Dec
  {Laws.dval(H1.dec.count(bs, d)) == Nat.add(Laws.blen(bs), Laws.dval(d)) : Nat}

def dcount(bs, d):
  match bs:
    case B.BNil{}:
      {==}
    case B.BCon{_, t}:
      Equal.trans(Nat, Laws.dval(H1.dec.count(t, H1.dec.inc(d))), Nat.add(Laws.blen(t), Laws.dval(H1.dec.inc(d))), 1n+Nat.add(Laws.blen(t), Laws.dval(d)),
        dcount(t, H1.dec.inc(d)),
        Equal.trans(Nat, Nat.add(Laws.blen(t), Laws.dval(H1.dec.inc(d))), Nat.add(Laws.blen(t), 1n+Laws.dval(d)), 1n+Nat.add(Laws.blen(t), Laws.dval(d)),
          Equal.cong(Nat, Nat, y => Nat.add(Laws.blen(t), y), Laws.dval(H1.dec.inc(d)), 1n+Laws.dval(d), dinc(d)),
          add_succ(Laws.blen(t), Laws.dval(d))))

law dlen:
  for +bs: B.Bytes
  {Laws.dval(H1.dec.count(bs, H1.DNil{})) == Laws.blen(bs) : Nat}

def dlen(bs):
  Equal.trans(Nat, Laws.dval(H1.dec.count(bs, H1.DNil{})), Nat.add(Laws.blen(bs), 0n), Laws.blen(bs), dcount(bs, H1.DNil{}), add_zero(Laws.blen(bs)))

# every value the digit parser sees on the way to dval(d) is within cap
def dmax(d: H1.Dec, +cap: Nat) -> Bool:
  match d:
    case H1.DNil{}:
      True{}
    case H1.DCon{+x, +t}:
      Bool.and(dmax(t, cap), Nat.is_le(Laws.dval(H1.DCon{x, t}), cap))

law dgrow:
  for +x: Nat
  for +v: Nat
  {Nat.is_le(x, Nat.add(Nat.mul(10n, x), v)) == True{} : Bool}

def dgrow(x, v):
  %Equal.sym(Nat, Nat.add(Nat.add(x, Nat.mul(9n, x)), v), Nat.add(x, Nat.add(Nat.mul(9n, x), v)), add_assoc(x, Nat.mul(9n, x), v)) : {Nat.is_le(x, _) == True{} : Bool}
  le_add(x, Nat.add(Nat.mul(9n, x), v))

law dmax_of:
  for +d: H1.Dec
  for +cap: Nat
  for +e: {Nat.is_le(Laws.dval(d), cap) == True{} : Bool}
  {dmax(d, cap) == True{} : Bool}

def dmax_of(d, cap, e):
  match d:
    case H1.DNil{}:
      {==}
    case H1.DCon{+x, t}:
      %Equal.sym(Bool, Nat.is_le(Laws.dval(H1.DCon{x, t}), cap), True{}, e) : {Bool.and(dmax(t, cap), _) == True{} : Bool}
      %Equal.sym(Bool, dmax(t, cap), True{}, dmax_of(t, cap, le_trans(Laws.dval(t), Laws.dval(H1.DCon{x, t}), cap, dgrow(Laws.dval(t), Laws.dd(x)), e))) : {Bool.and(_, True{}) == True{} : Bool}
      {==}

# one digit, within the cap
law ddigit:
  for +x: H1.Dig
  for +n: Nat
  for +T: String
  for +any: Bool
  for +e: {Nat.is_le(Nat.add(Nat.mul(10n, n), Laws.dd(x)), 4294967295n) == True{} : Bool}
  {H1.cl_digits.go(SCon{H1.dig.char(x), T}, n, True{}, any) == H1.cl_digits.go(T, Nat.add(Nat.mul(10n, n), Laws.dd(x)), True{}, True{}) : Maybe<&2, Nat>}

def ddigit(x, n, T, any, e):
  match x:
    case H1.D0{}:
      %Equal.sym(Bool, Nat.is_le(Nat.add(Nat.mul(10n, n), 0n), 4294967295n), True{}, e) : {H1.cl_digits.go(T, H1.nat_le.pick(_, Nat.add(Nat.mul(10n, n), 0n), 4294967295n), True{}, True{}) == H1.cl_digits.go(T, Nat.add(Nat.mul(10n, n), 0n), True{}, True{}) : Maybe<&2, Nat>}
      {==}
    case H1.D1{}:
      %Equal.sym(Bool, Nat.is_le(Nat.add(Nat.mul(10n, n), 1n), 4294967295n), True{}, e) : {H1.cl_digits.go(T, H1.nat_le.pick(_, Nat.add(Nat.mul(10n, n), 1n), 4294967295n), True{}, True{}) == H1.cl_digits.go(T, Nat.add(Nat.mul(10n, n), 1n), True{}, True{}) : Maybe<&2, Nat>}
      {==}
    case H1.D2{}:
      %Equal.sym(Bool, Nat.is_le(Nat.add(Nat.mul(10n, n), 2n), 4294967295n), True{}, e) : {H1.cl_digits.go(T, H1.nat_le.pick(_, Nat.add(Nat.mul(10n, n), 2n), 4294967295n), True{}, True{}) == H1.cl_digits.go(T, Nat.add(Nat.mul(10n, n), 2n), True{}, True{}) : Maybe<&2, Nat>}
      {==}
    case H1.D3{}:
      %Equal.sym(Bool, Nat.is_le(Nat.add(Nat.mul(10n, n), 3n), 4294967295n), True{}, e) : {H1.cl_digits.go(T, H1.nat_le.pick(_, Nat.add(Nat.mul(10n, n), 3n), 4294967295n), True{}, True{}) == H1.cl_digits.go(T, Nat.add(Nat.mul(10n, n), 3n), True{}, True{}) : Maybe<&2, Nat>}
      {==}
    case H1.D4{}:
      %Equal.sym(Bool, Nat.is_le(Nat.add(Nat.mul(10n, n), 4n), 4294967295n), True{}, e) : {H1.cl_digits.go(T, H1.nat_le.pick(_, Nat.add(Nat.mul(10n, n), 4n), 4294967295n), True{}, True{}) == H1.cl_digits.go(T, Nat.add(Nat.mul(10n, n), 4n), True{}, True{}) : Maybe<&2, Nat>}
      {==}
    case H1.D5{}:
      %Equal.sym(Bool, Nat.is_le(Nat.add(Nat.mul(10n, n), 5n), 4294967295n), True{}, e) : {H1.cl_digits.go(T, H1.nat_le.pick(_, Nat.add(Nat.mul(10n, n), 5n), 4294967295n), True{}, True{}) == H1.cl_digits.go(T, Nat.add(Nat.mul(10n, n), 5n), True{}, True{}) : Maybe<&2, Nat>}
      {==}
    case H1.D6{}:
      %Equal.sym(Bool, Nat.is_le(Nat.add(Nat.mul(10n, n), 6n), 4294967295n), True{}, e) : {H1.cl_digits.go(T, H1.nat_le.pick(_, Nat.add(Nat.mul(10n, n), 6n), 4294967295n), True{}, True{}) == H1.cl_digits.go(T, Nat.add(Nat.mul(10n, n), 6n), True{}, True{}) : Maybe<&2, Nat>}
      {==}
    case H1.D7{}:
      %Equal.sym(Bool, Nat.is_le(Nat.add(Nat.mul(10n, n), 7n), 4294967295n), True{}, e) : {H1.cl_digits.go(T, H1.nat_le.pick(_, Nat.add(Nat.mul(10n, n), 7n), 4294967295n), True{}, True{}) == H1.cl_digits.go(T, Nat.add(Nat.mul(10n, n), 7n), True{}, True{}) : Maybe<&2, Nat>}
      {==}
    case H1.D8{}:
      %Equal.sym(Bool, Nat.is_le(Nat.add(Nat.mul(10n, n), 8n), 4294967295n), True{}, e) : {H1.cl_digits.go(T, H1.nat_le.pick(_, Nat.add(Nat.mul(10n, n), 8n), 4294967295n), True{}, True{}) == H1.cl_digits.go(T, Nat.add(Nat.mul(10n, n), 8n), True{}, True{}) : Maybe<&2, Nat>}
      {==}
    case H1.D9{}:
      %Equal.sym(Bool, Nat.is_le(Nat.add(Nat.mul(10n, n), 9n), 4294967295n), True{}, e) : {H1.cl_digits.go(T, H1.nat_le.pick(_, Nat.add(Nat.mul(10n, n), 9n), 4294967295n), True{}, True{}) == H1.cl_digits.go(T, Nat.add(Nat.mul(10n, n), 9n), True{}, True{}) : Maybe<&2, Nat>}
      {==}

def danyd(any: Bool, d: H1.Dec) -> Bool:
  match d:
    case H1.DNil{}:
      any
    case H1.DCon{_, _}:
      True{}

# all the digits, most significant first: the parser arrives at dval
law ddigits:
  for +d: H1.Dec
  for +T: String
  for +any: Bool
  for +e: {dmax(d, 4294967295n) == True{} : Bool}
  {H1.cl_digits.go(H1.dec.show.go(d, T), 0n, True{}, any) == H1.cl_digits.go(T, Laws.dval(d), True{}, danyd(any, d)) : Maybe<&2, Nat>}

def ddigits(d, T, any, e):
  match d:
    case H1.DNil{}:
      {==}
    case H1.DCon{+x, t}:
      Equal.trans(Maybe<&2, Nat>, H1.cl_digits.go(H1.dec.show.go(t, SCon{H1.dig.char(x), T}), 0n, True{}, any), H1.cl_digits.go(SCon{H1.dig.char(x), T}, Laws.dval(t), True{}, danyd(any, t)), H1.cl_digits.go(T, Laws.dval(H1.DCon{x, t}), True{}, True{}),
        ddigits(t, SCon{H1.dig.char(x), T}, any, P.and_true_l(dmax(t, 4294967295n), Nat.is_le(Laws.dval(H1.DCon{x, t}), 4294967295n), e)),
        ddigit(x, Laws.dval(t), T, danyd(any, t), P.and_true_r(dmax(t, 4294967295n), Nat.is_le(Laws.dval(H1.DCon{x, t}), 4294967295n), e)))

def isdcon(d: H1.Dec) -> Bool:
  match d:
    case H1.DNil{}:
      False{}
    case H1.DCon{_, _}:
      True{}

law incd:
  for +d: H1.Dec
  {isdcon(H1.dec.inc(d)) == True{} : Bool}

def incd(d):
  match d:
    case H1.DNil{}:
      {==}
    case H1.DCon{H1.D0{}, t}:
      {==}
    case H1.DCon{H1.D1{}, t}:
      {==}
    case H1.DCon{H1.D2{}, t}:
      {==}
    case H1.DCon{H1.D3{}, t}:
      {==}
    case H1.DCon{H1.D4{}, t}:
      {==}
    case H1.DCon{H1.D5{}, t}:
      {==}
    case H1.DCon{H1.D6{}, t}:
      {==}
    case H1.DCon{H1.D7{}, t}:
      {==}
    case H1.DCon{H1.D8{}, t}:
      {==}
    case H1.DCon{H1.D9{}, t}:
      {==}

law cntd:
  for +bs: B.Bytes
  for +d: H1.Dec
  for +e: {isdcon(d) == True{} : Bool}
  {isdcon(H1.dec.count(bs, d)) == True{} : Bool}

def cntd(bs, d, e):
  match bs:
    case B.BNil{}:
      e
    case B.BCon{_, t}:
      cntd(t, H1.dec.inc(d), incd(d))

# a count of one byte or more is shown by its digits alone
law show_con:
  for +d: H1.Dec
  for +e: {isdcon(d) == True{} : Bool}
  {H1.dec.show(d) == H1.dec.show.go(d, "") : String}

def show_con(d, e):
  match d:
    case H1.DNil{}:
      P.absurd({H1.dec.show(H1.DNil{}) == H1.dec.show.go(H1.DNil{}, "") : String}, e)
    case H1.DCon{_, _}:
      {==}

law body_length.end:
  for +d: H1.Dec
  for +n: Nat
  for +c: {isdcon(d) == True{} : Bool}
  for +e: {Laws.dval(d) == n : Nat}
  {H1.cl_digits.go("", Laws.dval(d), True{}, danyd(False{}, d)) == Some{n} : Maybe<&2, Nat>}

def body_length.end(d, n, c, e):
  match d:
    case H1.DNil{}:
      P.absurd({H1.cl_digits.go("", Laws.dval(H1.DNil{}), True{}, danyd(False{}, H1.DNil{})) == Some{n} : Maybe<&2, Nat>}, c)
    case H1.DCon{+x, +t}:
      Equal.cong(Nat, Maybe<&2, Nat>, y => Some{y}, Laws.dval(H1.DCon{x, t}), n, e)

def Laws.body_length(bs, e):
  match bs:
    case B.BNil{}:
      {==}
    case B.BCon{+x, +t}:
      %Equal.sym(String, H1.dec.show(H1.dec.count(B.BCon{x, t}, H1.DNil{})), H1.dec.show.go(H1.dec.count(B.BCon{x, t}, H1.DNil{}), ""), show_con(H1.dec.count(B.BCon{x, t}, H1.DNil{}), cntd(t, H1.DCon{H1.D1{}, H1.DNil{}}, {==}))) : {H1.cl_digits.go(_, 0n, True{}, False{}) == Some{Laws.blen(B.BCon{x, t})} : Maybe<&2, Nat>}
      Equal.trans(Maybe<&2, Nat>, H1.cl_digits.go(H1.dec.show.go(H1.dec.count(B.BCon{x, t}, H1.DNil{}), ""), 0n, True{}, False{}), H1.cl_digits.go("", Laws.dval(H1.dec.count(B.BCon{x, t}, H1.DNil{})), True{}, danyd(False{}, H1.dec.count(B.BCon{x, t}, H1.DNil{}))), Some{Laws.blen(B.BCon{x, t})},
        ddigits(H1.dec.count(B.BCon{x, t}, H1.DNil{}), "", False{}, dmax_of(H1.dec.count(B.BCon{x, t}, H1.DNil{}), 4294967295n,
          %Equal.sym(Nat, Laws.dval(H1.dec.count(B.BCon{x, t}, H1.DNil{})), Laws.blen(B.BCon{x, t}), dlen(B.BCon{x, t})) : {Nat.is_le(_, 4294967295n) == True{} : Bool}
          e)),
        body_length.end(H1.dec.count(B.BCon{x, t}, H1.DNil{}), Laws.blen(B.BCon{x, t}), cntd(t, H1.DCon{H1.D1{}, H1.DNil{}}, {==}), dlen(B.BCon{x, t})))

def Laws.writes_count(m, t, h, hs, bs, sized, close):
  {==}
