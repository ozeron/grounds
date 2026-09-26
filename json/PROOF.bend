import Base
import ./LAWS.bend as Laws
import ./bjson.bend as J
import ./proof/parse.bend as RoundTrip
import ./proof/fast_run.bend as FastRoundTrip
import ./proof/layout.bend as Layout

def Laws.round_trip(j):
  RoundTrip.round_trip(j)

def Laws.fast_round_trip(j):
  FastRoundTrip.fast_round_trip(j)

def Laws.pretty_round_trip(j):
  Layout.pretty_round_trip(j)

def Laws.always_parses(j):
  %Equal.sym(Result<&2, &2, J.Error, J.Json>, J.parse(J.stringify(j)), Done{j}, RoundTrip.round_trip(j)) : {J.is_ok(_) == True{} : Bool}
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

def Laws.get_empty(k):
  {==}

def Laws.at_empty(n):
  match n:
    case 0n:
      {==}
    case 1n+p:
      {==}

def Laws.get_not_object(xs, k):
  {==}

def Laws.at_not_array(fs, n):
  {==}

def Laws.as_bool_exact(b):
  {==}

def Laws.as_str_exact(s):
  {==}

def Laws.skip_ws_space(s):
  {==}
