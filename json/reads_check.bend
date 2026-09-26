import Base
import ./json.bend as J

# reads on numbers too large to check at compile time: test.bend's
# proofs are evaluated by the checker, which counts Nats one by one

def n(s: String) -> J.Json:
  J.num_u32.go(J.num(s))

def su(r: Result<&2, &2, J.Access, U32>) -> String:
  match r:
    case Done{x}:
      U32.show(x)
    case Fail{a}:
      J.message_access(a)

def sf(r: Result<&2, &2, J.Access, F32>) -> String:
  match r:
    case Done{x}:
      F32.show(x)
    case Fail{a}:
      J.message_access(a)

type Case is Data:
  Case{got: String, want: String}

def cases() -> List<&2, Case>:
  [
    Case{su(J.u32(n("4294967295"))), "4294967295"},
    Case{su(J.u32(n("4294967296"))), "$: number out of range"},
    Case{su(J.u32(n("42949672950e-1"))), "4294967295"},
    Case{su(J.u32(n("1e10"))), "$: number out of range"},
    Case{su(J.u32(n("99999999999999999999"))), "$: number out of range"},
    Case{su(J.u32(n("1e999999999999999999"))), "$: number out of range"},
    Case{su(J.u32(n("0e999999999999999999"))), "0"},
    Case{su(J.u32(n("1e-999999999999999999"))), "$: number out of range"},
    Case{su(J.u32(n("0.000042949672950e11"))), "$: number out of range"},
    Case{sf(J.f32(n("1e39"))), "$: number out of range"},
    Case{sf(J.f32(n("-1e39"))), "$: number out of range"},
    Case{sf(J.f32(n("16777217"))), "16777216"},
    Case{sf(J.f32(n("1e-50"))), "0"},
    Case{J.message_access(J.Missing{[J.Name{"x\"y"}, J.Index{4294967295}]}), "$[\"x\\\"y\"][4294967295]: missing"}
  ]

def eq.go(a: String, b: String, ok: Bool) -> Bool:
  match a b:
    case SNil{} SNil{}:
      ok
    case SCon{x, at} SCon{y, bt}:
      eq.go(at, bt, Bool.and(ok, Char.is_eq(x, y)))
    case _ _:
      False{}

def note(ok: Bool, got: String, want: String, acc: List<&2, String>) -> List<&2, String>:
  match ok:
    case True{}:
      acc
    case False{}:
      ("got " ++ got ++ ", want " ++ want) <> acc

def fails(xs: List<&2, Case>, acc: List<&2, String>) -> List<&2, String>:
  match xs:
    case Nil{}:
      acc
    case Con{Case{+got, +want}, t}:
      fails(t, note(eq.go(got, want, True{}), got, want, acc))

def report(bad: List<&2, String>) -> IO(Unit):
  match bad:
    case Nil{}:
      IO.print("reads: all big-number cases pass")
    case _:
      IO.die(Unit, 1, String.join(bad, "\n"))

def main() -> IO(Unit):
  report(fails(cases(), []))
