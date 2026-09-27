import Base
import ./LAWS.bend as Laws
import ./http1.bend as H1
import ./bytes.bend as B
import ../core/headers.bend as H

law or_true:
  for +b: Bool
  {Bool.or(b, True{}) == True{} : Bool}

def or_true(b):
  match b:
    case True{}:
      {==}
    case False{}:
      {==}

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

def Laws.te_sticky(hs, fr, acc, e):
  match hs:
    case Nil{}:
      e
    case Con{H.Header{+n, +v}, t}:
      Laws.te_sticky(t, H1.frame.step(H1.kind(n), fr, v), Con{H.Header{n, v}, acc}, step_te(H1.kind(n), fr, v, e))

def Laws.te_seen(pre, v, post, fr, acc):
  match pre:
    case Nil{}:
      match fr:
        case H1.Frame{cl, te, h, c, kp}:
          Laws.te_sticky(post, H1.Frame{cl, True{}, h, c, kp}, Con{H.Header{"Transfer-Encoding", v}, acc}, {==})
    case Con{H.Header{+n, +w}, t}:
      Laws.te_seen(t, v, post, H1.frame.step(H1.kind(n), fr, w), Con{H.Header{n, w}, acc})

def Laws.te_refused(hosts, cl, close, max, rest, m, target, hs):
  {==}

def Laws.cl_conflict(a, b, e):
  %Equal.sym(Bool, Nat.is_eq(a, b), False{}, e) : {H1.cl_merge.eq(_, a) == H1.LenBad{} : H1.CL}
  {==}

def Laws.cl_bad_sticky(m):
  match m:
    case Some{_}:
      {==}
    case None{}:
      {==}

def Laws.cl_bad_refused(max, rest, m, target, hs, close):
  {==}

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

# a refused line fails the fields, whatever came before
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

def Laws.unsafe_value_dropped(n, v, hs, out, e):
  %Equal.sym(Bool, H1.unsafe(v, False{}), True{}, e) : {H1.heads(hs, H1.heads.keep(Bool.or(H1.framing(n), Bool.or(H1.unsafe(n, False{}), _)), n, v, out)) == H1.heads(hs, out) : String}
  %Equal.sym(Bool, Bool.or(H1.unsafe(n, False{}), True{}), True{}, or_true(H1.unsafe(n, False{}))) : {H1.heads(hs, H1.heads.keep(Bool.or(H1.framing(n), _), n, v, out)) == H1.heads(hs, out) : String}
  %Equal.sym(Bool, Bool.or(H1.framing(n), True{}), True{}, or_true(H1.framing(n))) : {H1.heads(hs, H1.heads.keep(_, n, v, out)) == H1.heads(hs, out) : String}
  {==}

def Laws.unsafe_name_dropped(n, v, hs, out, e):
  %Equal.sym(Bool, H1.unsafe(n, False{}), True{}, e) : {H1.heads(hs, H1.heads.keep(Bool.or(H1.framing(n), Bool.or(_, H1.unsafe(v, False{}))), n, v, out)) == H1.heads(hs, out) : String}
  %Equal.sym(Bool, Bool.or(H1.framing(n), True{}), True{}, or_true(H1.framing(n))) : {H1.heads(hs, H1.heads.keep(_, n, v, out)) == H1.heads(hs, out) : String}
  {==}

def Laws.framing_dropped(v, hs, out):
  {==}

def Laws.te_dropped(v, hs, out):
  {==}

def Laws.connection_dropped(v, hs, out):
  {==}
