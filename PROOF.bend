import Base
import ./LAWS.bend as Laws

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
