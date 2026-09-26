import Base
import ./LAWS.bend as Laws
import ./json.bend as J
import ./proof/parse.bend as RoundTrip
import ./proof/fast_run.bend as FastRoundTrip
import ./proof/layout.bend as Layout
import ./proof/access.bend as Access

def Laws.round_trip(j):
  RoundTrip.round_trip(j)

def Laws.fast_round_trip(j):
  FastRoundTrip.fast_round_trip(j)

def Laws.pretty_round_trip(j):
  Layout.pretty_round_trip(j)

def Laws.always_parses(j):
  %Equal.sym(Result<&2, &2, J.Error, J.Json>, J.parse(J.encode(j)), Done{j}, RoundTrip.round_trip(j)) : {J.is_ok(_) == True{} : Bool}
  {==}

def Laws.bool_round_trip(b):
  match b:
    case True{}:
      {==}
    case False{}:
      {==}

def Laws.null_round_trip():
  {==}

def Laws.pretty_literal(b, unit):
  match b:
    case True{}:
      {==}
    case False{}:
      {==}

def Laws.get_last(k, v, fs):
  Access.get_last(k, v, fs)

def Laws.get_missing(k):
  {==}

def Laws.index_first(x, xs):
  {==}

def Laws.index_second(x, y, ys):
  {==}

def Laws.index_empty(i):
  {==}

def Laws.string_exact(s):
  {==}

def Laws.bool_exact(b):
  {==}

def Laws.number_exact(n):
  {==}

def Laws.array_exact(xs):
  {==}

def Laws.object_exact(fs):
  {==}

def Laws.string_kind(j):
  match j:
    case J.JNull{}:
      {==}
    case J.JBool{_}:
      {==}
    case J.JNum{_}:
      {==}
    case J.JStr{_}:
      {==}
    case J.JArr{_}:
      {==}
    case J.JObj{_}:
      {==}

def Laws.bool_kind(j):
  match j:
    case J.JNull{}:
      {==}
    case J.JBool{_}:
      {==}
    case J.JNum{_}:
      {==}
    case J.JStr{_}:
      {==}
    case J.JArr{_}:
      {==}
    case J.JObj{_}:
      {==}

def Laws.number_kind(j):
  match j:
    case J.JNull{}:
      {==}
    case J.JBool{_}:
      {==}
    case J.JNum{_}:
      {==}
    case J.JStr{_}:
      {==}
    case J.JArr{_}:
      {==}
    case J.JObj{_}:
      {==}

def Laws.array_kind(j):
  match j:
    case J.JNull{}:
      {==}
    case J.JBool{_}:
      {==}
    case J.JNum{_}:
      {==}
    case J.JStr{_}:
      {==}
    case J.JArr{_}:
      {==}
    case J.JObj{_}:
      {==}

def Laws.object_kind(j):
  match j:
    case J.JNull{}:
      {==}
    case J.JBool{_}:
      {==}
    case J.JNum{_}:
      {==}
    case J.JStr{_}:
      {==}
    case J.JArr{_}:
      {==}
    case J.JObj{_}:
      {==}

def Laws.u32_kind(j):
  match j:
    case J.JNull{}:
      {==}
    case J.JBool{_}:
      {==}
    case J.JNum{n}:
      Access.num_ok(n)
    case J.JStr{_}:
      {==}
    case J.JArr{_}:
      {==}
    case J.JObj{_}:
      {==}

def Laws.f32_kind(j):
  match j:
    case J.JNull{}:
      {==}
    case J.JBool{_}:
      {==}
    case J.JNum{n}:
      Access.f32_range(F32.read(J.num_text(n)))
    case J.JStr{_}:
      {==}
    case J.JArr{_}:
      {==}
    case J.JObj{_}:
      {==}

def Laws.index_kind(j, i):
  match j:
    case J.JNull{}:
      {==}
    case J.JBool{_}:
      {==}
    case J.JNum{_}:
      {==}
    case J.JStr{_}:
      {==}
    case J.JArr{xs}:
      Access.index_found(xs, U32.to_nat(i), i)
    case J.JObj{_}:
      {==}

def Laws.get_kind(j, k):
  match j:
    case J.JNull{}:
      {==}
    case J.JBool{_}:
      {==}
    case J.JNum{_}:
      {==}
    case J.JStr{_}:
      {==}
    case J.JArr{_}:
      {==}
    case J.JObj{fs}:
      Access.get_found(J.get.go(fs, k, None{}), k)

def Laws.u32_frac_zero(neg, i, e):
  Access.frac_zero(neg, i, e)

def Laws.u32_exp_zero(neg, i, f, u, s):
  Access.exp_zero(neg, i, f, u, s)

def Laws.u32_neg_zero():
  {==}

def Laws.u32_shift(l, ds):
  Access.shift(l, ds)

def Laws.f32_finite(j):
  match j:
    case J.JNull{}:
      {==}
    case J.JBool{_}:
      {==}
    case J.JNum{n}:
      Access.go_ok(F32.read(J.num_text(n)))
    case J.JStr{_}:
      {==}
    case J.JArr{_}:
      {==}
    case J.JObj{_}:
      {==}

def Laws.key_reads_back(k):
  RoundTrip.round_trip(J.JStr{k})

def Laws.skip_ws_space(s):
  {==}
