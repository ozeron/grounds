import Base
import ../json.bend as J
import ../fast.bend as F
import ./spec.bend as S
import ./fast_text.bend as T
import ./fast.bend as FS
import ./print.bend as P

# The fast loop reads the printed text of any value back to the same
# text; with the string lemmas in proof/fast.bend, this ends in
# fast_round_trip.

def push(a: String, out: String) -> String:
  String.reverse.go(a, out)

# where the loop is after a value: any mode that may take what follows
type Q is Data:
  Q{mode: F.Mode, key: Bool, at: U32, ea: U32}

def after(+r: String, stk: List<&2, F.Box>, out: String, q: Q) -> F.Out:
  match q:
    case Q{m, k, a, e}:
      F.gc(r, m, r, stk, out, 0, 0, k, a, e)

def Aft(m: F.Mode) -> Type:
  match m:
    case F.VAfter{}:
      Unit
    case F.NZero{}:
      Unit
    case F.NInt{}:
      Unit
    case F.NFrac{}:
      Unit
    case F.NExp{}:
      Unit
    case _:
      Empty

def AftQ(q: Q) -> Type:
  match q:
    case Q{m, _, _, _}:
      Aft(m)

# reading t from mode m reaches r in some Aft mode, having pushed o2
def V(t: String, m: F.Mode, stk: List<&2, F.Box>, out: String, key: Bool, at: U32, ea: U32, r: String, stk2: List<&2, F.Box>, o2: String) -> Type:
  &q: Q -> (AftQ(q) & {F.gc(t, m, t, stk, out, 0, 0, key, at, ea) == after(r, stk2, o2, q) : F.Out})

def ValM(m: F.Mode) -> Type:
  match m:
    case F.VStart{}:
      Unit
    case F.VTop{}:
      Unit
    case F.VFirst{}:
      Unit
    case F.VItem{}:
      Unit
    case F.VObjVal{}:
      Unit
    case _:
      Empty

# Numbers
# -------

law dstep_int:
  for +d: J.Digit
  for +x: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  {F.gc(SCon{J.digit_char(d), x}, F.NInt{}, SCon{J.digit_char(d), x}, stk, out, 0, 0, key, at, ea) == F.gc(x, F.NInt{}, x, stk, SCon{J.digit_char(d), out}, 0, 0, key, (at + 1 : U32), ea) : F.Out}

def dstep_int(d, x, stk, out, key, at, ea):
  match d stk:
    case J.D0{} Nil{}:
      {==}
    case J.D0{} Con{F.BArr{}, up}:
      {==}
    case J.D0{} Con{F.BObj{}, up}:
      {==}
    case J.D1{} Nil{}:
      {==}
    case J.D1{} Con{F.BArr{}, up}:
      {==}
    case J.D1{} Con{F.BObj{}, up}:
      {==}
    case J.D2{} Nil{}:
      {==}
    case J.D2{} Con{F.BArr{}, up}:
      {==}
    case J.D2{} Con{F.BObj{}, up}:
      {==}
    case J.D3{} Nil{}:
      {==}
    case J.D3{} Con{F.BArr{}, up}:
      {==}
    case J.D3{} Con{F.BObj{}, up}:
      {==}
    case J.D4{} Nil{}:
      {==}
    case J.D4{} Con{F.BArr{}, up}:
      {==}
    case J.D4{} Con{F.BObj{}, up}:
      {==}
    case J.D5{} Nil{}:
      {==}
    case J.D5{} Con{F.BArr{}, up}:
      {==}
    case J.D5{} Con{F.BObj{}, up}:
      {==}
    case J.D6{} Nil{}:
      {==}
    case J.D6{} Con{F.BArr{}, up}:
      {==}
    case J.D6{} Con{F.BObj{}, up}:
      {==}
    case J.D7{} Nil{}:
      {==}
    case J.D7{} Con{F.BArr{}, up}:
      {==}
    case J.D7{} Con{F.BObj{}, up}:
      {==}
    case J.D8{} Nil{}:
      {==}
    case J.D8{} Con{F.BArr{}, up}:
      {==}
    case J.D8{} Con{F.BObj{}, up}:
      {==}
    case J.D9{} Nil{}:
      {==}
    case J.D9{} Con{F.BArr{}, up}:
      {==}
    case J.D9{} Con{F.BObj{}, up}:
      {==}

law dstep_frac:
  for +d: J.Digit
  for +x: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  {F.gc(SCon{J.digit_char(d), x}, F.NFrac{}, SCon{J.digit_char(d), x}, stk, out, 0, 0, key, at, ea) == F.gc(x, F.NFrac{}, x, stk, SCon{J.digit_char(d), out}, 0, 0, key, (at + 1 : U32), ea) : F.Out}

def dstep_frac(d, x, stk, out, key, at, ea):
  match d stk:
    case J.D0{} Nil{}:
      {==}
    case J.D0{} Con{F.BArr{}, up}:
      {==}
    case J.D0{} Con{F.BObj{}, up}:
      {==}
    case J.D1{} Nil{}:
      {==}
    case J.D1{} Con{F.BArr{}, up}:
      {==}
    case J.D1{} Con{F.BObj{}, up}:
      {==}
    case J.D2{} Nil{}:
      {==}
    case J.D2{} Con{F.BArr{}, up}:
      {==}
    case J.D2{} Con{F.BObj{}, up}:
      {==}
    case J.D3{} Nil{}:
      {==}
    case J.D3{} Con{F.BArr{}, up}:
      {==}
    case J.D3{} Con{F.BObj{}, up}:
      {==}
    case J.D4{} Nil{}:
      {==}
    case J.D4{} Con{F.BArr{}, up}:
      {==}
    case J.D4{} Con{F.BObj{}, up}:
      {==}
    case J.D5{} Nil{}:
      {==}
    case J.D5{} Con{F.BArr{}, up}:
      {==}
    case J.D5{} Con{F.BObj{}, up}:
      {==}
    case J.D6{} Nil{}:
      {==}
    case J.D6{} Con{F.BArr{}, up}:
      {==}
    case J.D6{} Con{F.BObj{}, up}:
      {==}
    case J.D7{} Nil{}:
      {==}
    case J.D7{} Con{F.BArr{}, up}:
      {==}
    case J.D7{} Con{F.BObj{}, up}:
      {==}
    case J.D8{} Nil{}:
      {==}
    case J.D8{} Con{F.BArr{}, up}:
      {==}
    case J.D8{} Con{F.BObj{}, up}:
      {==}
    case J.D9{} Nil{}:
      {==}
    case J.D9{} Con{F.BArr{}, up}:
      {==}
    case J.D9{} Con{F.BObj{}, up}:
      {==}

law dstep_exp:
  for +d: J.Digit
  for +x: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  {F.gc(SCon{J.digit_char(d), x}, F.NExp{}, SCon{J.digit_char(d), x}, stk, out, 0, 0, key, at, ea) == F.gc(x, F.NExp{}, x, stk, SCon{J.digit_char(d), out}, 0, 0, key, (at + 1 : U32), ea) : F.Out}

def dstep_exp(d, x, stk, out, key, at, ea):
  match d stk:
    case J.D0{} Nil{}:
      {==}
    case J.D0{} Con{F.BArr{}, up}:
      {==}
    case J.D0{} Con{F.BObj{}, up}:
      {==}
    case J.D1{} Nil{}:
      {==}
    case J.D1{} Con{F.BArr{}, up}:
      {==}
    case J.D1{} Con{F.BObj{}, up}:
      {==}
    case J.D2{} Nil{}:
      {==}
    case J.D2{} Con{F.BArr{}, up}:
      {==}
    case J.D2{} Con{F.BObj{}, up}:
      {==}
    case J.D3{} Nil{}:
      {==}
    case J.D3{} Con{F.BArr{}, up}:
      {==}
    case J.D3{} Con{F.BObj{}, up}:
      {==}
    case J.D4{} Nil{}:
      {==}
    case J.D4{} Con{F.BArr{}, up}:
      {==}
    case J.D4{} Con{F.BObj{}, up}:
      {==}
    case J.D5{} Nil{}:
      {==}
    case J.D5{} Con{F.BArr{}, up}:
      {==}
    case J.D5{} Con{F.BObj{}, up}:
      {==}
    case J.D6{} Nil{}:
      {==}
    case J.D6{} Con{F.BArr{}, up}:
      {==}
    case J.D6{} Con{F.BObj{}, up}:
      {==}
    case J.D7{} Nil{}:
      {==}
    case J.D7{} Con{F.BArr{}, up}:
      {==}
    case J.D7{} Con{F.BObj{}, up}:
      {==}
    case J.D8{} Nil{}:
      {==}
    case J.D8{} Con{F.BArr{}, up}:
      {==}
    case J.D8{} Con{F.BObj{}, up}:
      {==}
    case J.D9{} Nil{}:
      {==}
    case J.D9{} Con{F.BArr{}, up}:
      {==}
    case J.D9{} Con{F.BObj{}, up}:
      {==}

law dstep_dot:
  for +d: J.Digit
  for +x: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  {F.gc(SCon{J.digit_char(d), x}, F.NDot{}, SCon{J.digit_char(d), x}, stk, out, 0, 0, key, at, ea) == F.gc(x, F.NFrac{}, x, stk, SCon{J.digit_char(d), out}, 0, 0, key, (at + 1 : U32), ea) : F.Out}

def dstep_dot(d, x, stk, out, key, at, ea):
  match d stk:
    case J.D0{} Nil{}:
      {==}
    case J.D0{} Con{F.BArr{}, up}:
      {==}
    case J.D0{} Con{F.BObj{}, up}:
      {==}
    case J.D1{} Nil{}:
      {==}
    case J.D1{} Con{F.BArr{}, up}:
      {==}
    case J.D1{} Con{F.BObj{}, up}:
      {==}
    case J.D2{} Nil{}:
      {==}
    case J.D2{} Con{F.BArr{}, up}:
      {==}
    case J.D2{} Con{F.BObj{}, up}:
      {==}
    case J.D3{} Nil{}:
      {==}
    case J.D3{} Con{F.BArr{}, up}:
      {==}
    case J.D3{} Con{F.BObj{}, up}:
      {==}
    case J.D4{} Nil{}:
      {==}
    case J.D4{} Con{F.BArr{}, up}:
      {==}
    case J.D4{} Con{F.BObj{}, up}:
      {==}
    case J.D5{} Nil{}:
      {==}
    case J.D5{} Con{F.BArr{}, up}:
      {==}
    case J.D5{} Con{F.BObj{}, up}:
      {==}
    case J.D6{} Nil{}:
      {==}
    case J.D6{} Con{F.BArr{}, up}:
      {==}
    case J.D6{} Con{F.BObj{}, up}:
      {==}
    case J.D7{} Nil{}:
      {==}
    case J.D7{} Con{F.BArr{}, up}:
      {==}
    case J.D7{} Con{F.BObj{}, up}:
      {==}
    case J.D8{} Nil{}:
      {==}
    case J.D8{} Con{F.BArr{}, up}:
      {==}
    case J.D8{} Con{F.BObj{}, up}:
      {==}
    case J.D9{} Nil{}:
      {==}
    case J.D9{} Con{F.BArr{}, up}:
      {==}
    case J.D9{} Con{F.BObj{}, up}:
      {==}

law dstep_e:
  for +d: J.Digit
  for +x: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  {F.gc(SCon{J.digit_char(d), x}, F.NE{}, SCon{J.digit_char(d), x}, stk, out, 0, 0, key, at, ea) == F.gc(x, F.NExp{}, x, stk, SCon{J.digit_char(d), out}, 0, 0, key, (at + 1 : U32), ea) : F.Out}

def dstep_e(d, x, stk, out, key, at, ea):
  match d stk:
    case J.D0{} Nil{}:
      {==}
    case J.D0{} Con{F.BArr{}, up}:
      {==}
    case J.D0{} Con{F.BObj{}, up}:
      {==}
    case J.D1{} Nil{}:
      {==}
    case J.D1{} Con{F.BArr{}, up}:
      {==}
    case J.D1{} Con{F.BObj{}, up}:
      {==}
    case J.D2{} Nil{}:
      {==}
    case J.D2{} Con{F.BArr{}, up}:
      {==}
    case J.D2{} Con{F.BObj{}, up}:
      {==}
    case J.D3{} Nil{}:
      {==}
    case J.D3{} Con{F.BArr{}, up}:
      {==}
    case J.D3{} Con{F.BObj{}, up}:
      {==}
    case J.D4{} Nil{}:
      {==}
    case J.D4{} Con{F.BArr{}, up}:
      {==}
    case J.D4{} Con{F.BObj{}, up}:
      {==}
    case J.D5{} Nil{}:
      {==}
    case J.D5{} Con{F.BArr{}, up}:
      {==}
    case J.D5{} Con{F.BObj{}, up}:
      {==}
    case J.D6{} Nil{}:
      {==}
    case J.D6{} Con{F.BArr{}, up}:
      {==}
    case J.D6{} Con{F.BObj{}, up}:
      {==}
    case J.D7{} Nil{}:
      {==}
    case J.D7{} Con{F.BArr{}, up}:
      {==}
    case J.D7{} Con{F.BObj{}, up}:
      {==}
    case J.D8{} Nil{}:
      {==}
    case J.D8{} Con{F.BArr{}, up}:
      {==}
    case J.D8{} Con{F.BObj{}, up}:
      {==}
    case J.D9{} Nil{}:
      {==}
    case J.D9{} Con{F.BArr{}, up}:
      {==}
    case J.D9{} Con{F.BObj{}, up}:
      {==}

law dstep_esign:
  for +d: J.Digit
  for +x: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  {F.gc(SCon{J.digit_char(d), x}, F.NESign{}, SCon{J.digit_char(d), x}, stk, out, 0, 0, key, at, ea) == F.gc(x, F.NExp{}, x, stk, SCon{J.digit_char(d), out}, 0, 0, key, (at + 1 : U32), ea) : F.Out}

def dstep_esign(d, x, stk, out, key, at, ea):
  match d stk:
    case J.D0{} Nil{}:
      {==}
    case J.D0{} Con{F.BArr{}, up}:
      {==}
    case J.D0{} Con{F.BObj{}, up}:
      {==}
    case J.D1{} Nil{}:
      {==}
    case J.D1{} Con{F.BArr{}, up}:
      {==}
    case J.D1{} Con{F.BObj{}, up}:
      {==}
    case J.D2{} Nil{}:
      {==}
    case J.D2{} Con{F.BArr{}, up}:
      {==}
    case J.D2{} Con{F.BObj{}, up}:
      {==}
    case J.D3{} Nil{}:
      {==}
    case J.D3{} Con{F.BArr{}, up}:
      {==}
    case J.D3{} Con{F.BObj{}, up}:
      {==}
    case J.D4{} Nil{}:
      {==}
    case J.D4{} Con{F.BArr{}, up}:
      {==}
    case J.D4{} Con{F.BObj{}, up}:
      {==}
    case J.D5{} Nil{}:
      {==}
    case J.D5{} Con{F.BArr{}, up}:
      {==}
    case J.D5{} Con{F.BObj{}, up}:
      {==}
    case J.D6{} Nil{}:
      {==}
    case J.D6{} Con{F.BArr{}, up}:
      {==}
    case J.D6{} Con{F.BObj{}, up}:
      {==}
    case J.D7{} Nil{}:
      {==}
    case J.D7{} Con{F.BArr{}, up}:
      {==}
    case J.D7{} Con{F.BObj{}, up}:
      {==}
    case J.D8{} Nil{}:
      {==}
    case J.D8{} Con{F.BArr{}, up}:
      {==}
    case J.D8{} Con{F.BObj{}, up}:
      {==}
    case J.D9{} Nil{}:
      {==}
    case J.D9{} Con{F.BArr{}, up}:
      {==}
    case J.D9{} Con{F.BObj{}, up}:
      {==}

def Run_int(ds: List<&2, J.Digit>, x: String, stk: List<&2, F.Box>, out: String, key: Bool, at: U32, ea: U32) -> Type:
  &a: U32 -> {F.gc(J.digits_k(ds, x), F.NInt{}, J.digits_k(ds, x), stk, out, 0, 0, key, at, ea) == F.gc(x, F.NInt{}, x, stk, push(J.digits_k(ds, ""), out), 0, 0, key, a, ea) : F.Out}

law run_int.1:
  for +d: J.Digit
  for +t: List<&2, J.Digit>
  for +x: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  for g: Run_int(t, x, stk, SCon{J.digit_char(d), out}, key, (at + 1 : U32), ea)
  Run_int(Con{d, t}, x, stk, out, key, at, ea)

def run_int.1(d, t, x, stk, out, key, at, ea, g):
  (+a, e) = g
  (a, Equal.trans(F.Out,
    F.gc(SCon{J.digit_char(d), J.digits_k(t, x)}, F.NInt{}, SCon{J.digit_char(d), J.digits_k(t, x)}, stk, out, 0, 0, key, at, ea),
    F.gc(J.digits_k(t, x), F.NInt{}, J.digits_k(t, x), stk, SCon{J.digit_char(d), out}, 0, 0, key, (at + 1 : U32), ea),
    F.gc(x, F.NInt{}, x, stk, push(J.digits_k(Con{d, t}, ""), out), 0, 0, key, a, ea),
    dstep_int(d, J.digits_k(t, x), stk, out, key, at, ea),
    e))

law run_int:
  for +ds: List<&2, J.Digit>
  for +x: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  Run_int(ds, x, stk, out, key, at, ea)

def run_int(ds, x, stk, out, key, at, ea):
  match ds:
    case Nil{}:
      (at, {==})
    case Con{d, t}:
      run_int.1(d, t, x, stk, out, key, at, ea, run_int(t, x, stk, SCon{J.digit_char(d), out}, key, (at + 1 : U32), ea))

def Run_frac(ds: List<&2, J.Digit>, x: String, stk: List<&2, F.Box>, out: String, key: Bool, at: U32, ea: U32) -> Type:
  &a: U32 -> {F.gc(J.digits_k(ds, x), F.NFrac{}, J.digits_k(ds, x), stk, out, 0, 0, key, at, ea) == F.gc(x, F.NFrac{}, x, stk, push(J.digits_k(ds, ""), out), 0, 0, key, a, ea) : F.Out}

law run_frac.1:
  for +d: J.Digit
  for +t: List<&2, J.Digit>
  for +x: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  for g: Run_frac(t, x, stk, SCon{J.digit_char(d), out}, key, (at + 1 : U32), ea)
  Run_frac(Con{d, t}, x, stk, out, key, at, ea)

def run_frac.1(d, t, x, stk, out, key, at, ea, g):
  (+a, e) = g
  (a, Equal.trans(F.Out,
    F.gc(SCon{J.digit_char(d), J.digits_k(t, x)}, F.NFrac{}, SCon{J.digit_char(d), J.digits_k(t, x)}, stk, out, 0, 0, key, at, ea),
    F.gc(J.digits_k(t, x), F.NFrac{}, J.digits_k(t, x), stk, SCon{J.digit_char(d), out}, 0, 0, key, (at + 1 : U32), ea),
    F.gc(x, F.NFrac{}, x, stk, push(J.digits_k(Con{d, t}, ""), out), 0, 0, key, a, ea),
    dstep_frac(d, J.digits_k(t, x), stk, out, key, at, ea),
    e))

law run_frac:
  for +ds: List<&2, J.Digit>
  for +x: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  Run_frac(ds, x, stk, out, key, at, ea)

def run_frac(ds, x, stk, out, key, at, ea):
  match ds:
    case Nil{}:
      (at, {==})
    case Con{d, t}:
      run_frac.1(d, t, x, stk, out, key, at, ea, run_frac(t, x, stk, SCon{J.digit_char(d), out}, key, (at + 1 : U32), ea))

def Run_exp(ds: List<&2, J.Digit>, x: String, stk: List<&2, F.Box>, out: String, key: Bool, at: U32, ea: U32) -> Type:
  &a: U32 -> {F.gc(J.digits_k(ds, x), F.NExp{}, J.digits_k(ds, x), stk, out, 0, 0, key, at, ea) == F.gc(x, F.NExp{}, x, stk, push(J.digits_k(ds, ""), out), 0, 0, key, a, ea) : F.Out}

law run_exp.1:
  for +d: J.Digit
  for +t: List<&2, J.Digit>
  for +x: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  for g: Run_exp(t, x, stk, SCon{J.digit_char(d), out}, key, (at + 1 : U32), ea)
  Run_exp(Con{d, t}, x, stk, out, key, at, ea)

def run_exp.1(d, t, x, stk, out, key, at, ea, g):
  (+a, e) = g
  (a, Equal.trans(F.Out,
    F.gc(SCon{J.digit_char(d), J.digits_k(t, x)}, F.NExp{}, SCon{J.digit_char(d), J.digits_k(t, x)}, stk, out, 0, 0, key, at, ea),
    F.gc(J.digits_k(t, x), F.NExp{}, J.digits_k(t, x), stk, SCon{J.digit_char(d), out}, 0, 0, key, (at + 1 : U32), ea),
    F.gc(x, F.NExp{}, x, stk, push(J.digits_k(Con{d, t}, ""), out), 0, 0, key, a, ea),
    dstep_exp(d, J.digits_k(t, x), stk, out, key, at, ea),
    e))

law run_exp:
  for +ds: List<&2, J.Digit>
  for +x: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  Run_exp(ds, x, stk, out, key, at, ea)

def run_exp(ds, x, stk, out, key, at, ea):
  match ds:
    case Nil{}:
      (at, {==})
    case Con{d, t}:
      run_exp.1(d, t, x, stk, out, key, at, ea, run_exp(t, x, stk, SCon{J.digit_char(d), out}, key, (at + 1 : U32), ea))

law step_dot.NZero:
  for +x: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  {F.gc(SCon{'.', x}, F.NZero{}, SCon{'.', x}, stk, out, 0, 0, key, at, ea) == F.gc(x, F.NDot{}, x, stk, SCon{'.', out}, 0, 0, key, (at + 1 : U32), ea) : F.Out}

def step_dot.NZero(x, stk, out, key, at, ea):
  match stk:
    case Nil{}:
      {==}
    case Con{F.BArr{}, up}:
      {==}
    case Con{F.BObj{}, up}:
      {==}

law step_dot.NInt:
  for +x: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  {F.gc(SCon{'.', x}, F.NInt{}, SCon{'.', x}, stk, out, 0, 0, key, at, ea) == F.gc(x, F.NDot{}, x, stk, SCon{'.', out}, 0, 0, key, (at + 1 : U32), ea) : F.Out}

def step_dot.NInt(x, stk, out, key, at, ea):
  match stk:
    case Nil{}:
      {==}
    case Con{F.BArr{}, up}:
      {==}
    case Con{F.BObj{}, up}:
      {==}

law step_e.NZero:
  for +u: Bool
  for +x: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  {F.gc(SCon{Bool.pick(Char, u, 'E', 'e'), x}, F.NZero{}, SCon{Bool.pick(Char, u, 'E', 'e'), x}, stk, out, 0, 0, key, at, ea) == F.gc(x, F.NE{}, x, stk, SCon{Bool.pick(Char, u, 'E', 'e'), out}, 0, 0, key, (at + 1 : U32), ea) : F.Out}

def step_e.NZero(u, x, stk, out, key, at, ea):
  match u stk:
    case True{} Nil{}:
      {==}
    case True{} Con{F.BArr{}, up}:
      {==}
    case True{} Con{F.BObj{}, up}:
      {==}
    case False{} Nil{}:
      {==}
    case False{} Con{F.BArr{}, up}:
      {==}
    case False{} Con{F.BObj{}, up}:
      {==}

law step_e.NInt:
  for +u: Bool
  for +x: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  {F.gc(SCon{Bool.pick(Char, u, 'E', 'e'), x}, F.NInt{}, SCon{Bool.pick(Char, u, 'E', 'e'), x}, stk, out, 0, 0, key, at, ea) == F.gc(x, F.NE{}, x, stk, SCon{Bool.pick(Char, u, 'E', 'e'), out}, 0, 0, key, (at + 1 : U32), ea) : F.Out}

def step_e.NInt(u, x, stk, out, key, at, ea):
  match u stk:
    case True{} Nil{}:
      {==}
    case True{} Con{F.BArr{}, up}:
      {==}
    case True{} Con{F.BObj{}, up}:
      {==}
    case False{} Nil{}:
      {==}
    case False{} Con{F.BArr{}, up}:
      {==}
    case False{} Con{F.BObj{}, up}:
      {==}

law step_e.NFrac:
  for +u: Bool
  for +x: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  {F.gc(SCon{Bool.pick(Char, u, 'E', 'e'), x}, F.NFrac{}, SCon{Bool.pick(Char, u, 'E', 'e'), x}, stk, out, 0, 0, key, at, ea) == F.gc(x, F.NE{}, x, stk, SCon{Bool.pick(Char, u, 'E', 'e'), out}, 0, 0, key, (at + 1 : U32), ea) : F.Out}

def step_e.NFrac(u, x, stk, out, key, at, ea):
  match u stk:
    case True{} Nil{}:
      {==}
    case True{} Con{F.BArr{}, up}:
      {==}
    case True{} Con{F.BObj{}, up}:
      {==}
    case False{} Nil{}:
      {==}
    case False{} Con{F.BArr{}, up}:
      {==}
    case False{} Con{F.BObj{}, up}:
      {==}

law v_minus:
  for +m: F.Mode
  for vm: ValM(m)
  for +x: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  {F.gc(SCon{'-', x}, m, SCon{'-', x}, stk, out, 0, 0, key, at, ea) == F.gc(x, F.NMin{}, x, stk, SCon{'-', out}, 0, 0, key, (at + 1 : U32), ea) : F.Out}

def v_minus(m, vm, x, stk, out, key, at, ea):
  match m stk:
    case F.VStart{} Nil{}:
      {==}
    case F.VStart{} Con{F.BArr{}, up}:
      {==}
    case F.VStart{} Con{F.BObj{}, up}:
      {==}
    case F.VTop{} Nil{}:
      {==}
    case F.VTop{} Con{F.BArr{}, up}:
      {==}
    case F.VTop{} Con{F.BObj{}, up}:
      {==}
    case F.VFirst{} Nil{}:
      {==}
    case F.VFirst{} Con{F.BArr{}, up}:
      {==}
    case F.VFirst{} Con{F.BObj{}, up}:
      {==}
    case F.VItem{} Nil{}:
      {==}
    case F.VItem{} Con{F.BArr{}, up}:
      {==}
    case F.VItem{} Con{F.BObj{}, up}:
      {==}
    case F.VObjFirst{} _:
      match vm:
    case F.VKey{} _:
      match vm:
    case F.VColon{} _:
      match vm:
    case F.VObjVal{} Nil{}:
      {==}
    case F.VObjVal{} Con{F.BArr{}, up}:
      {==}
    case F.VObjVal{} Con{F.BObj{}, up}:
      {==}
    case F.VAfter{} _:
      match vm:
    case F.SStr{} _:
      match vm:
    case F.SEsc{} _:
      match vm:
    case F.SU4{} _:
      match vm:
    case F.SU3{} _:
      match vm:
    case F.SU2{} _:
      match vm:
    case F.SU1{} _:
      match vm:
    case F.SHi{} _:
      match vm:
    case F.SHiU{} _:
      match vm:
    case F.NMin{} _:
      match vm:
    case F.NZero{} _:
      match vm:
    case F.NInt{} _:
      match vm:
    case F.NDot{} _:
      match vm:
    case F.NFrac{} _:
      match vm:
    case F.NE{} _:
      match vm:
    case F.NESign{} _:
      match vm:
    case F.NExp{} _:
      match vm:
    case F.T1{} _:
      match vm:
    case F.T2{} _:
      match vm:
    case F.T3{} _:
      match vm:
    case F.F1{} _:
      match vm:
    case F.F2{} _:
      match vm:
    case F.F3{} _:
      match vm:
    case F.F4{} _:
      match vm:
    case F.U1{} _:
      match vm:
    case F.U2{} _:
      match vm:
    case F.U3{} _:
      match vm:
    case F.BCtrl{} _:
      match vm:
    case F.BUni{} _:
      match vm:
    case F.BLone{} _:
      match vm:
    case F.BEsc{} _:
      match vm:

law v_zero:
  for +m: F.Mode
  for vm: ValM(m)
  for +x: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  {F.gc(SCon{'0', x}, m, SCon{'0', x}, stk, out, 0, 0, key, at, ea) == F.gc(x, F.NZero{}, x, stk, SCon{'0', out}, 0, 0, key, (at + 1 : U32), ea) : F.Out}

def v_zero(m, vm, x, stk, out, key, at, ea):
  match m stk:
    case F.VStart{} Nil{}:
      {==}
    case F.VStart{} Con{F.BArr{}, up}:
      {==}
    case F.VStart{} Con{F.BObj{}, up}:
      {==}
    case F.VTop{} Nil{}:
      {==}
    case F.VTop{} Con{F.BArr{}, up}:
      {==}
    case F.VTop{} Con{F.BObj{}, up}:
      {==}
    case F.VFirst{} Nil{}:
      {==}
    case F.VFirst{} Con{F.BArr{}, up}:
      {==}
    case F.VFirst{} Con{F.BObj{}, up}:
      {==}
    case F.VItem{} Nil{}:
      {==}
    case F.VItem{} Con{F.BArr{}, up}:
      {==}
    case F.VItem{} Con{F.BObj{}, up}:
      {==}
    case F.VObjFirst{} _:
      match vm:
    case F.VKey{} _:
      match vm:
    case F.VColon{} _:
      match vm:
    case F.VObjVal{} Nil{}:
      {==}
    case F.VObjVal{} Con{F.BArr{}, up}:
      {==}
    case F.VObjVal{} Con{F.BObj{}, up}:
      {==}
    case F.VAfter{} _:
      match vm:
    case F.SStr{} _:
      match vm:
    case F.SEsc{} _:
      match vm:
    case F.SU4{} _:
      match vm:
    case F.SU3{} _:
      match vm:
    case F.SU2{} _:
      match vm:
    case F.SU1{} _:
      match vm:
    case F.SHi{} _:
      match vm:
    case F.SHiU{} _:
      match vm:
    case F.NMin{} _:
      match vm:
    case F.NZero{} _:
      match vm:
    case F.NInt{} _:
      match vm:
    case F.NDot{} _:
      match vm:
    case F.NFrac{} _:
      match vm:
    case F.NE{} _:
      match vm:
    case F.NESign{} _:
      match vm:
    case F.NExp{} _:
      match vm:
    case F.T1{} _:
      match vm:
    case F.T2{} _:
      match vm:
    case F.T3{} _:
      match vm:
    case F.F1{} _:
      match vm:
    case F.F2{} _:
      match vm:
    case F.F3{} _:
      match vm:
    case F.F4{} _:
      match vm:
    case F.U1{} _:
      match vm:
    case F.U2{} _:
      match vm:
    case F.U3{} _:
      match vm:
    case F.BCtrl{} _:
      match vm:
    case F.BUni{} _:
      match vm:
    case F.BLone{} _:
      match vm:
    case F.BEsc{} _:
      match vm:

law v_lead:
  for +m: F.Mode
  for vm: ValM(m)
  for +l: J.Lead
  for +x: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  {F.gc(SCon{J.lead_char(l), x}, m, SCon{J.lead_char(l), x}, stk, out, 0, 0, key, at, ea) == F.gc(x, F.NInt{}, x, stk, SCon{J.lead_char(l), out}, 0, 0, key, (at + 1 : U32), ea) : F.Out}

def v_lead(m, vm, l, x, stk, out, key, at, ea):
  match m l stk:
    case F.VStart{} J.L1{} Nil{}:
      {==}
    case F.VStart{} J.L1{} Con{F.BArr{}, up}:
      {==}
    case F.VStart{} J.L1{} Con{F.BObj{}, up}:
      {==}
    case F.VStart{} J.L2{} Nil{}:
      {==}
    case F.VStart{} J.L2{} Con{F.BArr{}, up}:
      {==}
    case F.VStart{} J.L2{} Con{F.BObj{}, up}:
      {==}
    case F.VStart{} J.L3{} Nil{}:
      {==}
    case F.VStart{} J.L3{} Con{F.BArr{}, up}:
      {==}
    case F.VStart{} J.L3{} Con{F.BObj{}, up}:
      {==}
    case F.VStart{} J.L4{} Nil{}:
      {==}
    case F.VStart{} J.L4{} Con{F.BArr{}, up}:
      {==}
    case F.VStart{} J.L4{} Con{F.BObj{}, up}:
      {==}
    case F.VStart{} J.L5{} Nil{}:
      {==}
    case F.VStart{} J.L5{} Con{F.BArr{}, up}:
      {==}
    case F.VStart{} J.L5{} Con{F.BObj{}, up}:
      {==}
    case F.VStart{} J.L6{} Nil{}:
      {==}
    case F.VStart{} J.L6{} Con{F.BArr{}, up}:
      {==}
    case F.VStart{} J.L6{} Con{F.BObj{}, up}:
      {==}
    case F.VStart{} J.L7{} Nil{}:
      {==}
    case F.VStart{} J.L7{} Con{F.BArr{}, up}:
      {==}
    case F.VStart{} J.L7{} Con{F.BObj{}, up}:
      {==}
    case F.VStart{} J.L8{} Nil{}:
      {==}
    case F.VStart{} J.L8{} Con{F.BArr{}, up}:
      {==}
    case F.VStart{} J.L8{} Con{F.BObj{}, up}:
      {==}
    case F.VStart{} J.L9{} Nil{}:
      {==}
    case F.VStart{} J.L9{} Con{F.BArr{}, up}:
      {==}
    case F.VStart{} J.L9{} Con{F.BObj{}, up}:
      {==}
    case F.VTop{} J.L1{} Nil{}:
      {==}
    case F.VTop{} J.L1{} Con{F.BArr{}, up}:
      {==}
    case F.VTop{} J.L1{} Con{F.BObj{}, up}:
      {==}
    case F.VTop{} J.L2{} Nil{}:
      {==}
    case F.VTop{} J.L2{} Con{F.BArr{}, up}:
      {==}
    case F.VTop{} J.L2{} Con{F.BObj{}, up}:
      {==}
    case F.VTop{} J.L3{} Nil{}:
      {==}
    case F.VTop{} J.L3{} Con{F.BArr{}, up}:
      {==}
    case F.VTop{} J.L3{} Con{F.BObj{}, up}:
      {==}
    case F.VTop{} J.L4{} Nil{}:
      {==}
    case F.VTop{} J.L4{} Con{F.BArr{}, up}:
      {==}
    case F.VTop{} J.L4{} Con{F.BObj{}, up}:
      {==}
    case F.VTop{} J.L5{} Nil{}:
      {==}
    case F.VTop{} J.L5{} Con{F.BArr{}, up}:
      {==}
    case F.VTop{} J.L5{} Con{F.BObj{}, up}:
      {==}
    case F.VTop{} J.L6{} Nil{}:
      {==}
    case F.VTop{} J.L6{} Con{F.BArr{}, up}:
      {==}
    case F.VTop{} J.L6{} Con{F.BObj{}, up}:
      {==}
    case F.VTop{} J.L7{} Nil{}:
      {==}
    case F.VTop{} J.L7{} Con{F.BArr{}, up}:
      {==}
    case F.VTop{} J.L7{} Con{F.BObj{}, up}:
      {==}
    case F.VTop{} J.L8{} Nil{}:
      {==}
    case F.VTop{} J.L8{} Con{F.BArr{}, up}:
      {==}
    case F.VTop{} J.L8{} Con{F.BObj{}, up}:
      {==}
    case F.VTop{} J.L9{} Nil{}:
      {==}
    case F.VTop{} J.L9{} Con{F.BArr{}, up}:
      {==}
    case F.VTop{} J.L9{} Con{F.BObj{}, up}:
      {==}
    case F.VFirst{} J.L1{} Nil{}:
      {==}
    case F.VFirst{} J.L1{} Con{F.BArr{}, up}:
      {==}
    case F.VFirst{} J.L1{} Con{F.BObj{}, up}:
      {==}
    case F.VFirst{} J.L2{} Nil{}:
      {==}
    case F.VFirst{} J.L2{} Con{F.BArr{}, up}:
      {==}
    case F.VFirst{} J.L2{} Con{F.BObj{}, up}:
      {==}
    case F.VFirst{} J.L3{} Nil{}:
      {==}
    case F.VFirst{} J.L3{} Con{F.BArr{}, up}:
      {==}
    case F.VFirst{} J.L3{} Con{F.BObj{}, up}:
      {==}
    case F.VFirst{} J.L4{} Nil{}:
      {==}
    case F.VFirst{} J.L4{} Con{F.BArr{}, up}:
      {==}
    case F.VFirst{} J.L4{} Con{F.BObj{}, up}:
      {==}
    case F.VFirst{} J.L5{} Nil{}:
      {==}
    case F.VFirst{} J.L5{} Con{F.BArr{}, up}:
      {==}
    case F.VFirst{} J.L5{} Con{F.BObj{}, up}:
      {==}
    case F.VFirst{} J.L6{} Nil{}:
      {==}
    case F.VFirst{} J.L6{} Con{F.BArr{}, up}:
      {==}
    case F.VFirst{} J.L6{} Con{F.BObj{}, up}:
      {==}
    case F.VFirst{} J.L7{} Nil{}:
      {==}
    case F.VFirst{} J.L7{} Con{F.BArr{}, up}:
      {==}
    case F.VFirst{} J.L7{} Con{F.BObj{}, up}:
      {==}
    case F.VFirst{} J.L8{} Nil{}:
      {==}
    case F.VFirst{} J.L8{} Con{F.BArr{}, up}:
      {==}
    case F.VFirst{} J.L8{} Con{F.BObj{}, up}:
      {==}
    case F.VFirst{} J.L9{} Nil{}:
      {==}
    case F.VFirst{} J.L9{} Con{F.BArr{}, up}:
      {==}
    case F.VFirst{} J.L9{} Con{F.BObj{}, up}:
      {==}
    case F.VItem{} J.L1{} Nil{}:
      {==}
    case F.VItem{} J.L1{} Con{F.BArr{}, up}:
      {==}
    case F.VItem{} J.L1{} Con{F.BObj{}, up}:
      {==}
    case F.VItem{} J.L2{} Nil{}:
      {==}
    case F.VItem{} J.L2{} Con{F.BArr{}, up}:
      {==}
    case F.VItem{} J.L2{} Con{F.BObj{}, up}:
      {==}
    case F.VItem{} J.L3{} Nil{}:
      {==}
    case F.VItem{} J.L3{} Con{F.BArr{}, up}:
      {==}
    case F.VItem{} J.L3{} Con{F.BObj{}, up}:
      {==}
    case F.VItem{} J.L4{} Nil{}:
      {==}
    case F.VItem{} J.L4{} Con{F.BArr{}, up}:
      {==}
    case F.VItem{} J.L4{} Con{F.BObj{}, up}:
      {==}
    case F.VItem{} J.L5{} Nil{}:
      {==}
    case F.VItem{} J.L5{} Con{F.BArr{}, up}:
      {==}
    case F.VItem{} J.L5{} Con{F.BObj{}, up}:
      {==}
    case F.VItem{} J.L6{} Nil{}:
      {==}
    case F.VItem{} J.L6{} Con{F.BArr{}, up}:
      {==}
    case F.VItem{} J.L6{} Con{F.BObj{}, up}:
      {==}
    case F.VItem{} J.L7{} Nil{}:
      {==}
    case F.VItem{} J.L7{} Con{F.BArr{}, up}:
      {==}
    case F.VItem{} J.L7{} Con{F.BObj{}, up}:
      {==}
    case F.VItem{} J.L8{} Nil{}:
      {==}
    case F.VItem{} J.L8{} Con{F.BArr{}, up}:
      {==}
    case F.VItem{} J.L8{} Con{F.BObj{}, up}:
      {==}
    case F.VItem{} J.L9{} Nil{}:
      {==}
    case F.VItem{} J.L9{} Con{F.BArr{}, up}:
      {==}
    case F.VItem{} J.L9{} Con{F.BObj{}, up}:
      {==}
    case F.VObjFirst{} _ _:
      match vm:
    case F.VKey{} _ _:
      match vm:
    case F.VColon{} _ _:
      match vm:
    case F.VObjVal{} J.L1{} Nil{}:
      {==}
    case F.VObjVal{} J.L1{} Con{F.BArr{}, up}:
      {==}
    case F.VObjVal{} J.L1{} Con{F.BObj{}, up}:
      {==}
    case F.VObjVal{} J.L2{} Nil{}:
      {==}
    case F.VObjVal{} J.L2{} Con{F.BArr{}, up}:
      {==}
    case F.VObjVal{} J.L2{} Con{F.BObj{}, up}:
      {==}
    case F.VObjVal{} J.L3{} Nil{}:
      {==}
    case F.VObjVal{} J.L3{} Con{F.BArr{}, up}:
      {==}
    case F.VObjVal{} J.L3{} Con{F.BObj{}, up}:
      {==}
    case F.VObjVal{} J.L4{} Nil{}:
      {==}
    case F.VObjVal{} J.L4{} Con{F.BArr{}, up}:
      {==}
    case F.VObjVal{} J.L4{} Con{F.BObj{}, up}:
      {==}
    case F.VObjVal{} J.L5{} Nil{}:
      {==}
    case F.VObjVal{} J.L5{} Con{F.BArr{}, up}:
      {==}
    case F.VObjVal{} J.L5{} Con{F.BObj{}, up}:
      {==}
    case F.VObjVal{} J.L6{} Nil{}:
      {==}
    case F.VObjVal{} J.L6{} Con{F.BArr{}, up}:
      {==}
    case F.VObjVal{} J.L6{} Con{F.BObj{}, up}:
      {==}
    case F.VObjVal{} J.L7{} Nil{}:
      {==}
    case F.VObjVal{} J.L7{} Con{F.BArr{}, up}:
      {==}
    case F.VObjVal{} J.L7{} Con{F.BObj{}, up}:
      {==}
    case F.VObjVal{} J.L8{} Nil{}:
      {==}
    case F.VObjVal{} J.L8{} Con{F.BArr{}, up}:
      {==}
    case F.VObjVal{} J.L8{} Con{F.BObj{}, up}:
      {==}
    case F.VObjVal{} J.L9{} Nil{}:
      {==}
    case F.VObjVal{} J.L9{} Con{F.BArr{}, up}:
      {==}
    case F.VObjVal{} J.L9{} Con{F.BObj{}, up}:
      {==}
    case F.VAfter{} _ _:
      match vm:
    case F.SStr{} _ _:
      match vm:
    case F.SEsc{} _ _:
      match vm:
    case F.SU4{} _ _:
      match vm:
    case F.SU3{} _ _:
      match vm:
    case F.SU2{} _ _:
      match vm:
    case F.SU1{} _ _:
      match vm:
    case F.SHi{} _ _:
      match vm:
    case F.SHiU{} _ _:
      match vm:
    case F.NMin{} _ _:
      match vm:
    case F.NZero{} _ _:
      match vm:
    case F.NInt{} _ _:
      match vm:
    case F.NDot{} _ _:
      match vm:
    case F.NFrac{} _ _:
      match vm:
    case F.NE{} _ _:
      match vm:
    case F.NESign{} _ _:
      match vm:
    case F.NExp{} _ _:
      match vm:
    case F.T1{} _ _:
      match vm:
    case F.T2{} _ _:
      match vm:
    case F.T3{} _ _:
      match vm:
    case F.F1{} _ _:
      match vm:
    case F.F2{} _ _:
      match vm:
    case F.F3{} _ _:
      match vm:
    case F.F4{} _ _:
      match vm:
    case F.U1{} _ _:
      match vm:
    case F.U2{} _ _:
      match vm:
    case F.U3{} _ _:
      match vm:
    case F.BCtrl{} _ _:
      match vm:
    case F.BUni{} _ _:
      match vm:
    case F.BLone{} _ _:
      match vm:
    case F.BEsc{} _ _:
      match vm:

law min_zero:
  for +x: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  {F.gc(SCon{'0', x}, F.NMin{}, SCon{'0', x}, stk, out, 0, 0, key, at, ea) == F.gc(x, F.NZero{}, x, stk, SCon{'0', out}, 0, 0, key, (at + 1 : U32), ea) : F.Out}

def min_zero(x, stk, out, key, at, ea):
  {==}

law min_lead:
  for +l: J.Lead
  for +x: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  {F.gc(SCon{J.lead_char(l), x}, F.NMin{}, SCon{J.lead_char(l), x}, stk, out, 0, 0, key, at, ea) == F.gc(x, F.NInt{}, x, stk, SCon{J.lead_char(l), out}, 0, 0, key, (at + 1 : U32), ea) : F.Out}

def min_lead(l, x, stk, out, key, at, ea):
  match l:
    case J.L1{}:
      {==}
    case J.L2{}:
      {==}
    case J.L3{}:
      {==}
    case J.L4{}:
      {==}
    case J.L5{}:
      {==}
    case J.L6{}:
      {==}
    case J.L7{}:
      {==}
    case J.L8{}:
      {==}
    case J.L9{}:
      {==}

law exp.NZero.NoSign.k:
  for +u: Bool
  for +d: J.Digit
  for +ds: List<&2, J.Digit>
  for +r: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  for g: Run_exp(ds, r, stk, SCon{J.digit_char(d), SCon{Bool.pick(Char, u, 'E', 'e'), out}}, key, ((at + 1 : U32) + 1 : U32), ea)
  V(J.exp_k(J.ESome{u, J.NoSign{}, d, ds}, r), F.NZero{}, stk, out, key, at, ea, r, stk, push(J.exp_k(J.ESome{u, J.NoSign{}, d, ds}, ""), out))

def exp.NZero.NoSign.k(u, d, ds, r, stk, out, key, at, ea, g):
  (+a, e3) = g
  (Q{F.NExp{}, key, a, ea}, (Unit{}, Equal.trans(F.Out,
      F.gc(SCon{Bool.pick(Char, u, 'E', 'e'), SCon{J.digit_char(d), J.digits_k(ds, r)}}, F.NZero{}, SCon{Bool.pick(Char, u, 'E', 'e'), SCon{J.digit_char(d), J.digits_k(ds, r)}}, stk, out, 0, 0, key, at, ea),
      F.gc(SCon{J.digit_char(d), J.digits_k(ds, r)}, F.NE{}, SCon{J.digit_char(d), J.digits_k(ds, r)}, stk, SCon{Bool.pick(Char, u, 'E', 'e'), out}, 0, 0, key, (at + 1 : U32), ea),
      F.gc(r, F.NExp{}, r, stk, push(J.digits_k(ds, ""), SCon{J.digit_char(d), SCon{Bool.pick(Char, u, 'E', 'e'), out}}), 0, 0, key, a, ea),
      step_e.NZero(u, SCon{J.digit_char(d), J.digits_k(ds, r)}, stk, out, key, at, ea),
      Equal.trans(F.Out,
        F.gc(SCon{J.digit_char(d), J.digits_k(ds, r)}, F.NE{}, SCon{J.digit_char(d), J.digits_k(ds, r)}, stk, SCon{Bool.pick(Char, u, 'E', 'e'), out}, 0, 0, key, (at + 1 : U32), ea),
        F.gc(J.digits_k(ds, r), F.NExp{}, J.digits_k(ds, r), stk, SCon{J.digit_char(d), SCon{Bool.pick(Char, u, 'E', 'e'), out}}, 0, 0, key, ((at + 1 : U32) + 1 : U32), ea),
        F.gc(r, F.NExp{}, r, stk, push(J.digits_k(ds, ""), SCon{J.digit_char(d), SCon{Bool.pick(Char, u, 'E', 'e'), out}}), 0, 0, key, a, ea),
        dstep_e(d, J.digits_k(ds, r), stk, SCon{Bool.pick(Char, u, 'E', 'e'), out}, key, (at + 1 : U32), ea),
        e3))))

law exp.NZero.Plus.k:
  for +u: Bool
  for +d: J.Digit
  for +ds: List<&2, J.Digit>
  for +r: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  for g: Run_exp(ds, r, stk, SCon{J.digit_char(d), SCon{'+', SCon{Bool.pick(Char, u, 'E', 'e'), out}}}, key, (((at + 1 : U32) + 1 : U32) + 1 : U32), ea)
  V(J.exp_k(J.ESome{u, J.Plus{}, d, ds}, r), F.NZero{}, stk, out, key, at, ea, r, stk, push(J.exp_k(J.ESome{u, J.Plus{}, d, ds}, ""), out))

def exp.NZero.Plus.k(u, d, ds, r, stk, out, key, at, ea, g):
  (+a, e3) = g
  (Q{F.NExp{}, key, a, ea}, (Unit{}, Equal.trans(F.Out,
      F.gc(SCon{Bool.pick(Char, u, 'E', 'e'), SCon{'+', SCon{J.digit_char(d), J.digits_k(ds, r)}}}, F.NZero{}, SCon{Bool.pick(Char, u, 'E', 'e'), SCon{'+', SCon{J.digit_char(d), J.digits_k(ds, r)}}}, stk, out, 0, 0, key, at, ea),
      F.gc(SCon{'+', SCon{J.digit_char(d), J.digits_k(ds, r)}}, F.NE{}, SCon{'+', SCon{J.digit_char(d), J.digits_k(ds, r)}}, stk, SCon{Bool.pick(Char, u, 'E', 'e'), out}, 0, 0, key, (at + 1 : U32), ea),
      F.gc(r, F.NExp{}, r, stk, push(J.digits_k(ds, ""), SCon{J.digit_char(d), SCon{'+', SCon{Bool.pick(Char, u, 'E', 'e'), out}}}), 0, 0, key, a, ea),
      step_e.NZero(u, SCon{'+', SCon{J.digit_char(d), J.digits_k(ds, r)}}, stk, out, key, at, ea),
      Equal.trans(F.Out,
        F.gc(SCon{'+', SCon{J.digit_char(d), J.digits_k(ds, r)}}, F.NE{}, SCon{'+', SCon{J.digit_char(d), J.digits_k(ds, r)}}, stk, SCon{Bool.pick(Char, u, 'E', 'e'), out}, 0, 0, key, (at + 1 : U32), ea),
        F.gc(SCon{J.digit_char(d), J.digits_k(ds, r)}, F.NESign{}, SCon{J.digit_char(d), J.digits_k(ds, r)}, stk, SCon{'+', SCon{Bool.pick(Char, u, 'E', 'e'), out}}, 0, 0, key, ((at + 1 : U32) + 1 : U32), ea),
        F.gc(r, F.NExp{}, r, stk, push(J.digits_k(ds, ""), SCon{J.digit_char(d), SCon{'+', SCon{Bool.pick(Char, u, 'E', 'e'), out}}}), 0, 0, key, a, ea),
        {==},
        Equal.trans(F.Out,
          F.gc(SCon{J.digit_char(d), J.digits_k(ds, r)}, F.NESign{}, SCon{J.digit_char(d), J.digits_k(ds, r)}, stk, SCon{'+', SCon{Bool.pick(Char, u, 'E', 'e'), out}}, 0, 0, key, ((at + 1 : U32) + 1 : U32), ea),
          F.gc(J.digits_k(ds, r), F.NExp{}, J.digits_k(ds, r), stk, SCon{J.digit_char(d), SCon{'+', SCon{Bool.pick(Char, u, 'E', 'e'), out}}}, 0, 0, key, (((at + 1 : U32) + 1 : U32) + 1 : U32), ea),
          F.gc(r, F.NExp{}, r, stk, push(J.digits_k(ds, ""), SCon{J.digit_char(d), SCon{'+', SCon{Bool.pick(Char, u, 'E', 'e'), out}}}), 0, 0, key, a, ea),
          dstep_esign(d, J.digits_k(ds, r), stk, SCon{'+', SCon{Bool.pick(Char, u, 'E', 'e'), out}}, key, ((at + 1 : U32) + 1 : U32), ea),
          e3)))))

law exp.NZero.Minus.k:
  for +u: Bool
  for +d: J.Digit
  for +ds: List<&2, J.Digit>
  for +r: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  for g: Run_exp(ds, r, stk, SCon{J.digit_char(d), SCon{'-', SCon{Bool.pick(Char, u, 'E', 'e'), out}}}, key, (((at + 1 : U32) + 1 : U32) + 1 : U32), ea)
  V(J.exp_k(J.ESome{u, J.Minus{}, d, ds}, r), F.NZero{}, stk, out, key, at, ea, r, stk, push(J.exp_k(J.ESome{u, J.Minus{}, d, ds}, ""), out))

def exp.NZero.Minus.k(u, d, ds, r, stk, out, key, at, ea, g):
  (+a, e3) = g
  (Q{F.NExp{}, key, a, ea}, (Unit{}, Equal.trans(F.Out,
      F.gc(SCon{Bool.pick(Char, u, 'E', 'e'), SCon{'-', SCon{J.digit_char(d), J.digits_k(ds, r)}}}, F.NZero{}, SCon{Bool.pick(Char, u, 'E', 'e'), SCon{'-', SCon{J.digit_char(d), J.digits_k(ds, r)}}}, stk, out, 0, 0, key, at, ea),
      F.gc(SCon{'-', SCon{J.digit_char(d), J.digits_k(ds, r)}}, F.NE{}, SCon{'-', SCon{J.digit_char(d), J.digits_k(ds, r)}}, stk, SCon{Bool.pick(Char, u, 'E', 'e'), out}, 0, 0, key, (at + 1 : U32), ea),
      F.gc(r, F.NExp{}, r, stk, push(J.digits_k(ds, ""), SCon{J.digit_char(d), SCon{'-', SCon{Bool.pick(Char, u, 'E', 'e'), out}}}), 0, 0, key, a, ea),
      step_e.NZero(u, SCon{'-', SCon{J.digit_char(d), J.digits_k(ds, r)}}, stk, out, key, at, ea),
      Equal.trans(F.Out,
        F.gc(SCon{'-', SCon{J.digit_char(d), J.digits_k(ds, r)}}, F.NE{}, SCon{'-', SCon{J.digit_char(d), J.digits_k(ds, r)}}, stk, SCon{Bool.pick(Char, u, 'E', 'e'), out}, 0, 0, key, (at + 1 : U32), ea),
        F.gc(SCon{J.digit_char(d), J.digits_k(ds, r)}, F.NESign{}, SCon{J.digit_char(d), J.digits_k(ds, r)}, stk, SCon{'-', SCon{Bool.pick(Char, u, 'E', 'e'), out}}, 0, 0, key, ((at + 1 : U32) + 1 : U32), ea),
        F.gc(r, F.NExp{}, r, stk, push(J.digits_k(ds, ""), SCon{J.digit_char(d), SCon{'-', SCon{Bool.pick(Char, u, 'E', 'e'), out}}}), 0, 0, key, a, ea),
        {==},
        Equal.trans(F.Out,
          F.gc(SCon{J.digit_char(d), J.digits_k(ds, r)}, F.NESign{}, SCon{J.digit_char(d), J.digits_k(ds, r)}, stk, SCon{'-', SCon{Bool.pick(Char, u, 'E', 'e'), out}}, 0, 0, key, ((at + 1 : U32) + 1 : U32), ea),
          F.gc(J.digits_k(ds, r), F.NExp{}, J.digits_k(ds, r), stk, SCon{J.digit_char(d), SCon{'-', SCon{Bool.pick(Char, u, 'E', 'e'), out}}}, 0, 0, key, (((at + 1 : U32) + 1 : U32) + 1 : U32), ea),
          F.gc(r, F.NExp{}, r, stk, push(J.digits_k(ds, ""), SCon{J.digit_char(d), SCon{'-', SCon{Bool.pick(Char, u, 'E', 'e'), out}}}), 0, 0, key, a, ea),
          dstep_esign(d, J.digits_k(ds, r), stk, SCon{'-', SCon{Bool.pick(Char, u, 'E', 'e'), out}}, key, ((at + 1 : U32) + 1 : U32), ea),
          e3)))))

law exp.NZero:
  for +e: J.Exp
  for +r: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  V(J.exp_k(e, r), F.NZero{}, stk, out, key, at, ea, r, stk, push(J.exp_k(e, ""), out))

def exp.NZero(e, r, stk, out, key, at, ea):
  match e:
    case J.ENone{}:
      (Q{F.NZero{}, key, at, ea}, (Unit{}, {==}))
    case J.ESome{u, sg, d, ds}:
      match sg:
        case J.NoSign{}:
          exp.NZero.NoSign.k(u, d, ds, r, stk, out, key, at, ea, run_exp(ds, r, stk, SCon{J.digit_char(d), SCon{Bool.pick(Char, u, 'E', 'e'), out}}, key, ((at + 1 : U32) + 1 : U32), ea))
        case J.Plus{}:
          exp.NZero.Plus.k(u, d, ds, r, stk, out, key, at, ea, run_exp(ds, r, stk, SCon{J.digit_char(d), SCon{'+', SCon{Bool.pick(Char, u, 'E', 'e'), out}}}, key, (((at + 1 : U32) + 1 : U32) + 1 : U32), ea))
        case J.Minus{}:
          exp.NZero.Minus.k(u, d, ds, r, stk, out, key, at, ea, run_exp(ds, r, stk, SCon{J.digit_char(d), SCon{'-', SCon{Bool.pick(Char, u, 'E', 'e'), out}}}, key, (((at + 1 : U32) + 1 : U32) + 1 : U32), ea))

law exp.NInt.NoSign.k:
  for +u: Bool
  for +d: J.Digit
  for +ds: List<&2, J.Digit>
  for +r: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  for g: Run_exp(ds, r, stk, SCon{J.digit_char(d), SCon{Bool.pick(Char, u, 'E', 'e'), out}}, key, ((at + 1 : U32) + 1 : U32), ea)
  V(J.exp_k(J.ESome{u, J.NoSign{}, d, ds}, r), F.NInt{}, stk, out, key, at, ea, r, stk, push(J.exp_k(J.ESome{u, J.NoSign{}, d, ds}, ""), out))

def exp.NInt.NoSign.k(u, d, ds, r, stk, out, key, at, ea, g):
  (+a, e3) = g
  (Q{F.NExp{}, key, a, ea}, (Unit{}, Equal.trans(F.Out,
      F.gc(SCon{Bool.pick(Char, u, 'E', 'e'), SCon{J.digit_char(d), J.digits_k(ds, r)}}, F.NInt{}, SCon{Bool.pick(Char, u, 'E', 'e'), SCon{J.digit_char(d), J.digits_k(ds, r)}}, stk, out, 0, 0, key, at, ea),
      F.gc(SCon{J.digit_char(d), J.digits_k(ds, r)}, F.NE{}, SCon{J.digit_char(d), J.digits_k(ds, r)}, stk, SCon{Bool.pick(Char, u, 'E', 'e'), out}, 0, 0, key, (at + 1 : U32), ea),
      F.gc(r, F.NExp{}, r, stk, push(J.digits_k(ds, ""), SCon{J.digit_char(d), SCon{Bool.pick(Char, u, 'E', 'e'), out}}), 0, 0, key, a, ea),
      step_e.NInt(u, SCon{J.digit_char(d), J.digits_k(ds, r)}, stk, out, key, at, ea),
      Equal.trans(F.Out,
        F.gc(SCon{J.digit_char(d), J.digits_k(ds, r)}, F.NE{}, SCon{J.digit_char(d), J.digits_k(ds, r)}, stk, SCon{Bool.pick(Char, u, 'E', 'e'), out}, 0, 0, key, (at + 1 : U32), ea),
        F.gc(J.digits_k(ds, r), F.NExp{}, J.digits_k(ds, r), stk, SCon{J.digit_char(d), SCon{Bool.pick(Char, u, 'E', 'e'), out}}, 0, 0, key, ((at + 1 : U32) + 1 : U32), ea),
        F.gc(r, F.NExp{}, r, stk, push(J.digits_k(ds, ""), SCon{J.digit_char(d), SCon{Bool.pick(Char, u, 'E', 'e'), out}}), 0, 0, key, a, ea),
        dstep_e(d, J.digits_k(ds, r), stk, SCon{Bool.pick(Char, u, 'E', 'e'), out}, key, (at + 1 : U32), ea),
        e3))))

law exp.NInt.Plus.k:
  for +u: Bool
  for +d: J.Digit
  for +ds: List<&2, J.Digit>
  for +r: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  for g: Run_exp(ds, r, stk, SCon{J.digit_char(d), SCon{'+', SCon{Bool.pick(Char, u, 'E', 'e'), out}}}, key, (((at + 1 : U32) + 1 : U32) + 1 : U32), ea)
  V(J.exp_k(J.ESome{u, J.Plus{}, d, ds}, r), F.NInt{}, stk, out, key, at, ea, r, stk, push(J.exp_k(J.ESome{u, J.Plus{}, d, ds}, ""), out))

def exp.NInt.Plus.k(u, d, ds, r, stk, out, key, at, ea, g):
  (+a, e3) = g
  (Q{F.NExp{}, key, a, ea}, (Unit{}, Equal.trans(F.Out,
      F.gc(SCon{Bool.pick(Char, u, 'E', 'e'), SCon{'+', SCon{J.digit_char(d), J.digits_k(ds, r)}}}, F.NInt{}, SCon{Bool.pick(Char, u, 'E', 'e'), SCon{'+', SCon{J.digit_char(d), J.digits_k(ds, r)}}}, stk, out, 0, 0, key, at, ea),
      F.gc(SCon{'+', SCon{J.digit_char(d), J.digits_k(ds, r)}}, F.NE{}, SCon{'+', SCon{J.digit_char(d), J.digits_k(ds, r)}}, stk, SCon{Bool.pick(Char, u, 'E', 'e'), out}, 0, 0, key, (at + 1 : U32), ea),
      F.gc(r, F.NExp{}, r, stk, push(J.digits_k(ds, ""), SCon{J.digit_char(d), SCon{'+', SCon{Bool.pick(Char, u, 'E', 'e'), out}}}), 0, 0, key, a, ea),
      step_e.NInt(u, SCon{'+', SCon{J.digit_char(d), J.digits_k(ds, r)}}, stk, out, key, at, ea),
      Equal.trans(F.Out,
        F.gc(SCon{'+', SCon{J.digit_char(d), J.digits_k(ds, r)}}, F.NE{}, SCon{'+', SCon{J.digit_char(d), J.digits_k(ds, r)}}, stk, SCon{Bool.pick(Char, u, 'E', 'e'), out}, 0, 0, key, (at + 1 : U32), ea),
        F.gc(SCon{J.digit_char(d), J.digits_k(ds, r)}, F.NESign{}, SCon{J.digit_char(d), J.digits_k(ds, r)}, stk, SCon{'+', SCon{Bool.pick(Char, u, 'E', 'e'), out}}, 0, 0, key, ((at + 1 : U32) + 1 : U32), ea),
        F.gc(r, F.NExp{}, r, stk, push(J.digits_k(ds, ""), SCon{J.digit_char(d), SCon{'+', SCon{Bool.pick(Char, u, 'E', 'e'), out}}}), 0, 0, key, a, ea),
        {==},
        Equal.trans(F.Out,
          F.gc(SCon{J.digit_char(d), J.digits_k(ds, r)}, F.NESign{}, SCon{J.digit_char(d), J.digits_k(ds, r)}, stk, SCon{'+', SCon{Bool.pick(Char, u, 'E', 'e'), out}}, 0, 0, key, ((at + 1 : U32) + 1 : U32), ea),
          F.gc(J.digits_k(ds, r), F.NExp{}, J.digits_k(ds, r), stk, SCon{J.digit_char(d), SCon{'+', SCon{Bool.pick(Char, u, 'E', 'e'), out}}}, 0, 0, key, (((at + 1 : U32) + 1 : U32) + 1 : U32), ea),
          F.gc(r, F.NExp{}, r, stk, push(J.digits_k(ds, ""), SCon{J.digit_char(d), SCon{'+', SCon{Bool.pick(Char, u, 'E', 'e'), out}}}), 0, 0, key, a, ea),
          dstep_esign(d, J.digits_k(ds, r), stk, SCon{'+', SCon{Bool.pick(Char, u, 'E', 'e'), out}}, key, ((at + 1 : U32) + 1 : U32), ea),
          e3)))))

law exp.NInt.Minus.k:
  for +u: Bool
  for +d: J.Digit
  for +ds: List<&2, J.Digit>
  for +r: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  for g: Run_exp(ds, r, stk, SCon{J.digit_char(d), SCon{'-', SCon{Bool.pick(Char, u, 'E', 'e'), out}}}, key, (((at + 1 : U32) + 1 : U32) + 1 : U32), ea)
  V(J.exp_k(J.ESome{u, J.Minus{}, d, ds}, r), F.NInt{}, stk, out, key, at, ea, r, stk, push(J.exp_k(J.ESome{u, J.Minus{}, d, ds}, ""), out))

def exp.NInt.Minus.k(u, d, ds, r, stk, out, key, at, ea, g):
  (+a, e3) = g
  (Q{F.NExp{}, key, a, ea}, (Unit{}, Equal.trans(F.Out,
      F.gc(SCon{Bool.pick(Char, u, 'E', 'e'), SCon{'-', SCon{J.digit_char(d), J.digits_k(ds, r)}}}, F.NInt{}, SCon{Bool.pick(Char, u, 'E', 'e'), SCon{'-', SCon{J.digit_char(d), J.digits_k(ds, r)}}}, stk, out, 0, 0, key, at, ea),
      F.gc(SCon{'-', SCon{J.digit_char(d), J.digits_k(ds, r)}}, F.NE{}, SCon{'-', SCon{J.digit_char(d), J.digits_k(ds, r)}}, stk, SCon{Bool.pick(Char, u, 'E', 'e'), out}, 0, 0, key, (at + 1 : U32), ea),
      F.gc(r, F.NExp{}, r, stk, push(J.digits_k(ds, ""), SCon{J.digit_char(d), SCon{'-', SCon{Bool.pick(Char, u, 'E', 'e'), out}}}), 0, 0, key, a, ea),
      step_e.NInt(u, SCon{'-', SCon{J.digit_char(d), J.digits_k(ds, r)}}, stk, out, key, at, ea),
      Equal.trans(F.Out,
        F.gc(SCon{'-', SCon{J.digit_char(d), J.digits_k(ds, r)}}, F.NE{}, SCon{'-', SCon{J.digit_char(d), J.digits_k(ds, r)}}, stk, SCon{Bool.pick(Char, u, 'E', 'e'), out}, 0, 0, key, (at + 1 : U32), ea),
        F.gc(SCon{J.digit_char(d), J.digits_k(ds, r)}, F.NESign{}, SCon{J.digit_char(d), J.digits_k(ds, r)}, stk, SCon{'-', SCon{Bool.pick(Char, u, 'E', 'e'), out}}, 0, 0, key, ((at + 1 : U32) + 1 : U32), ea),
        F.gc(r, F.NExp{}, r, stk, push(J.digits_k(ds, ""), SCon{J.digit_char(d), SCon{'-', SCon{Bool.pick(Char, u, 'E', 'e'), out}}}), 0, 0, key, a, ea),
        {==},
        Equal.trans(F.Out,
          F.gc(SCon{J.digit_char(d), J.digits_k(ds, r)}, F.NESign{}, SCon{J.digit_char(d), J.digits_k(ds, r)}, stk, SCon{'-', SCon{Bool.pick(Char, u, 'E', 'e'), out}}, 0, 0, key, ((at + 1 : U32) + 1 : U32), ea),
          F.gc(J.digits_k(ds, r), F.NExp{}, J.digits_k(ds, r), stk, SCon{J.digit_char(d), SCon{'-', SCon{Bool.pick(Char, u, 'E', 'e'), out}}}, 0, 0, key, (((at + 1 : U32) + 1 : U32) + 1 : U32), ea),
          F.gc(r, F.NExp{}, r, stk, push(J.digits_k(ds, ""), SCon{J.digit_char(d), SCon{'-', SCon{Bool.pick(Char, u, 'E', 'e'), out}}}), 0, 0, key, a, ea),
          dstep_esign(d, J.digits_k(ds, r), stk, SCon{'-', SCon{Bool.pick(Char, u, 'E', 'e'), out}}, key, ((at + 1 : U32) + 1 : U32), ea),
          e3)))))

law exp.NInt:
  for +e: J.Exp
  for +r: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  V(J.exp_k(e, r), F.NInt{}, stk, out, key, at, ea, r, stk, push(J.exp_k(e, ""), out))

def exp.NInt(e, r, stk, out, key, at, ea):
  match e:
    case J.ENone{}:
      (Q{F.NInt{}, key, at, ea}, (Unit{}, {==}))
    case J.ESome{u, sg, d, ds}:
      match sg:
        case J.NoSign{}:
          exp.NInt.NoSign.k(u, d, ds, r, stk, out, key, at, ea, run_exp(ds, r, stk, SCon{J.digit_char(d), SCon{Bool.pick(Char, u, 'E', 'e'), out}}, key, ((at + 1 : U32) + 1 : U32), ea))
        case J.Plus{}:
          exp.NInt.Plus.k(u, d, ds, r, stk, out, key, at, ea, run_exp(ds, r, stk, SCon{J.digit_char(d), SCon{'+', SCon{Bool.pick(Char, u, 'E', 'e'), out}}}, key, (((at + 1 : U32) + 1 : U32) + 1 : U32), ea))
        case J.Minus{}:
          exp.NInt.Minus.k(u, d, ds, r, stk, out, key, at, ea, run_exp(ds, r, stk, SCon{J.digit_char(d), SCon{'-', SCon{Bool.pick(Char, u, 'E', 'e'), out}}}, key, (((at + 1 : U32) + 1 : U32) + 1 : U32), ea))

law exp.NFrac.NoSign.k:
  for +u: Bool
  for +d: J.Digit
  for +ds: List<&2, J.Digit>
  for +r: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  for g: Run_exp(ds, r, stk, SCon{J.digit_char(d), SCon{Bool.pick(Char, u, 'E', 'e'), out}}, key, ((at + 1 : U32) + 1 : U32), ea)
  V(J.exp_k(J.ESome{u, J.NoSign{}, d, ds}, r), F.NFrac{}, stk, out, key, at, ea, r, stk, push(J.exp_k(J.ESome{u, J.NoSign{}, d, ds}, ""), out))

def exp.NFrac.NoSign.k(u, d, ds, r, stk, out, key, at, ea, g):
  (+a, e3) = g
  (Q{F.NExp{}, key, a, ea}, (Unit{}, Equal.trans(F.Out,
      F.gc(SCon{Bool.pick(Char, u, 'E', 'e'), SCon{J.digit_char(d), J.digits_k(ds, r)}}, F.NFrac{}, SCon{Bool.pick(Char, u, 'E', 'e'), SCon{J.digit_char(d), J.digits_k(ds, r)}}, stk, out, 0, 0, key, at, ea),
      F.gc(SCon{J.digit_char(d), J.digits_k(ds, r)}, F.NE{}, SCon{J.digit_char(d), J.digits_k(ds, r)}, stk, SCon{Bool.pick(Char, u, 'E', 'e'), out}, 0, 0, key, (at + 1 : U32), ea),
      F.gc(r, F.NExp{}, r, stk, push(J.digits_k(ds, ""), SCon{J.digit_char(d), SCon{Bool.pick(Char, u, 'E', 'e'), out}}), 0, 0, key, a, ea),
      step_e.NFrac(u, SCon{J.digit_char(d), J.digits_k(ds, r)}, stk, out, key, at, ea),
      Equal.trans(F.Out,
        F.gc(SCon{J.digit_char(d), J.digits_k(ds, r)}, F.NE{}, SCon{J.digit_char(d), J.digits_k(ds, r)}, stk, SCon{Bool.pick(Char, u, 'E', 'e'), out}, 0, 0, key, (at + 1 : U32), ea),
        F.gc(J.digits_k(ds, r), F.NExp{}, J.digits_k(ds, r), stk, SCon{J.digit_char(d), SCon{Bool.pick(Char, u, 'E', 'e'), out}}, 0, 0, key, ((at + 1 : U32) + 1 : U32), ea),
        F.gc(r, F.NExp{}, r, stk, push(J.digits_k(ds, ""), SCon{J.digit_char(d), SCon{Bool.pick(Char, u, 'E', 'e'), out}}), 0, 0, key, a, ea),
        dstep_e(d, J.digits_k(ds, r), stk, SCon{Bool.pick(Char, u, 'E', 'e'), out}, key, (at + 1 : U32), ea),
        e3))))

law exp.NFrac.Plus.k:
  for +u: Bool
  for +d: J.Digit
  for +ds: List<&2, J.Digit>
  for +r: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  for g: Run_exp(ds, r, stk, SCon{J.digit_char(d), SCon{'+', SCon{Bool.pick(Char, u, 'E', 'e'), out}}}, key, (((at + 1 : U32) + 1 : U32) + 1 : U32), ea)
  V(J.exp_k(J.ESome{u, J.Plus{}, d, ds}, r), F.NFrac{}, stk, out, key, at, ea, r, stk, push(J.exp_k(J.ESome{u, J.Plus{}, d, ds}, ""), out))

def exp.NFrac.Plus.k(u, d, ds, r, stk, out, key, at, ea, g):
  (+a, e3) = g
  (Q{F.NExp{}, key, a, ea}, (Unit{}, Equal.trans(F.Out,
      F.gc(SCon{Bool.pick(Char, u, 'E', 'e'), SCon{'+', SCon{J.digit_char(d), J.digits_k(ds, r)}}}, F.NFrac{}, SCon{Bool.pick(Char, u, 'E', 'e'), SCon{'+', SCon{J.digit_char(d), J.digits_k(ds, r)}}}, stk, out, 0, 0, key, at, ea),
      F.gc(SCon{'+', SCon{J.digit_char(d), J.digits_k(ds, r)}}, F.NE{}, SCon{'+', SCon{J.digit_char(d), J.digits_k(ds, r)}}, stk, SCon{Bool.pick(Char, u, 'E', 'e'), out}, 0, 0, key, (at + 1 : U32), ea),
      F.gc(r, F.NExp{}, r, stk, push(J.digits_k(ds, ""), SCon{J.digit_char(d), SCon{'+', SCon{Bool.pick(Char, u, 'E', 'e'), out}}}), 0, 0, key, a, ea),
      step_e.NFrac(u, SCon{'+', SCon{J.digit_char(d), J.digits_k(ds, r)}}, stk, out, key, at, ea),
      Equal.trans(F.Out,
        F.gc(SCon{'+', SCon{J.digit_char(d), J.digits_k(ds, r)}}, F.NE{}, SCon{'+', SCon{J.digit_char(d), J.digits_k(ds, r)}}, stk, SCon{Bool.pick(Char, u, 'E', 'e'), out}, 0, 0, key, (at + 1 : U32), ea),
        F.gc(SCon{J.digit_char(d), J.digits_k(ds, r)}, F.NESign{}, SCon{J.digit_char(d), J.digits_k(ds, r)}, stk, SCon{'+', SCon{Bool.pick(Char, u, 'E', 'e'), out}}, 0, 0, key, ((at + 1 : U32) + 1 : U32), ea),
        F.gc(r, F.NExp{}, r, stk, push(J.digits_k(ds, ""), SCon{J.digit_char(d), SCon{'+', SCon{Bool.pick(Char, u, 'E', 'e'), out}}}), 0, 0, key, a, ea),
        {==},
        Equal.trans(F.Out,
          F.gc(SCon{J.digit_char(d), J.digits_k(ds, r)}, F.NESign{}, SCon{J.digit_char(d), J.digits_k(ds, r)}, stk, SCon{'+', SCon{Bool.pick(Char, u, 'E', 'e'), out}}, 0, 0, key, ((at + 1 : U32) + 1 : U32), ea),
          F.gc(J.digits_k(ds, r), F.NExp{}, J.digits_k(ds, r), stk, SCon{J.digit_char(d), SCon{'+', SCon{Bool.pick(Char, u, 'E', 'e'), out}}}, 0, 0, key, (((at + 1 : U32) + 1 : U32) + 1 : U32), ea),
          F.gc(r, F.NExp{}, r, stk, push(J.digits_k(ds, ""), SCon{J.digit_char(d), SCon{'+', SCon{Bool.pick(Char, u, 'E', 'e'), out}}}), 0, 0, key, a, ea),
          dstep_esign(d, J.digits_k(ds, r), stk, SCon{'+', SCon{Bool.pick(Char, u, 'E', 'e'), out}}, key, ((at + 1 : U32) + 1 : U32), ea),
          e3)))))

law exp.NFrac.Minus.k:
  for +u: Bool
  for +d: J.Digit
  for +ds: List<&2, J.Digit>
  for +r: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  for g: Run_exp(ds, r, stk, SCon{J.digit_char(d), SCon{'-', SCon{Bool.pick(Char, u, 'E', 'e'), out}}}, key, (((at + 1 : U32) + 1 : U32) + 1 : U32), ea)
  V(J.exp_k(J.ESome{u, J.Minus{}, d, ds}, r), F.NFrac{}, stk, out, key, at, ea, r, stk, push(J.exp_k(J.ESome{u, J.Minus{}, d, ds}, ""), out))

def exp.NFrac.Minus.k(u, d, ds, r, stk, out, key, at, ea, g):
  (+a, e3) = g
  (Q{F.NExp{}, key, a, ea}, (Unit{}, Equal.trans(F.Out,
      F.gc(SCon{Bool.pick(Char, u, 'E', 'e'), SCon{'-', SCon{J.digit_char(d), J.digits_k(ds, r)}}}, F.NFrac{}, SCon{Bool.pick(Char, u, 'E', 'e'), SCon{'-', SCon{J.digit_char(d), J.digits_k(ds, r)}}}, stk, out, 0, 0, key, at, ea),
      F.gc(SCon{'-', SCon{J.digit_char(d), J.digits_k(ds, r)}}, F.NE{}, SCon{'-', SCon{J.digit_char(d), J.digits_k(ds, r)}}, stk, SCon{Bool.pick(Char, u, 'E', 'e'), out}, 0, 0, key, (at + 1 : U32), ea),
      F.gc(r, F.NExp{}, r, stk, push(J.digits_k(ds, ""), SCon{J.digit_char(d), SCon{'-', SCon{Bool.pick(Char, u, 'E', 'e'), out}}}), 0, 0, key, a, ea),
      step_e.NFrac(u, SCon{'-', SCon{J.digit_char(d), J.digits_k(ds, r)}}, stk, out, key, at, ea),
      Equal.trans(F.Out,
        F.gc(SCon{'-', SCon{J.digit_char(d), J.digits_k(ds, r)}}, F.NE{}, SCon{'-', SCon{J.digit_char(d), J.digits_k(ds, r)}}, stk, SCon{Bool.pick(Char, u, 'E', 'e'), out}, 0, 0, key, (at + 1 : U32), ea),
        F.gc(SCon{J.digit_char(d), J.digits_k(ds, r)}, F.NESign{}, SCon{J.digit_char(d), J.digits_k(ds, r)}, stk, SCon{'-', SCon{Bool.pick(Char, u, 'E', 'e'), out}}, 0, 0, key, ((at + 1 : U32) + 1 : U32), ea),
        F.gc(r, F.NExp{}, r, stk, push(J.digits_k(ds, ""), SCon{J.digit_char(d), SCon{'-', SCon{Bool.pick(Char, u, 'E', 'e'), out}}}), 0, 0, key, a, ea),
        {==},
        Equal.trans(F.Out,
          F.gc(SCon{J.digit_char(d), J.digits_k(ds, r)}, F.NESign{}, SCon{J.digit_char(d), J.digits_k(ds, r)}, stk, SCon{'-', SCon{Bool.pick(Char, u, 'E', 'e'), out}}, 0, 0, key, ((at + 1 : U32) + 1 : U32), ea),
          F.gc(J.digits_k(ds, r), F.NExp{}, J.digits_k(ds, r), stk, SCon{J.digit_char(d), SCon{'-', SCon{Bool.pick(Char, u, 'E', 'e'), out}}}, 0, 0, key, (((at + 1 : U32) + 1 : U32) + 1 : U32), ea),
          F.gc(r, F.NExp{}, r, stk, push(J.digits_k(ds, ""), SCon{J.digit_char(d), SCon{'-', SCon{Bool.pick(Char, u, 'E', 'e'), out}}}), 0, 0, key, a, ea),
          dstep_esign(d, J.digits_k(ds, r), stk, SCon{'-', SCon{Bool.pick(Char, u, 'E', 'e'), out}}, key, ((at + 1 : U32) + 1 : U32), ea),
          e3)))))

law exp.NFrac:
  for +e: J.Exp
  for +r: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  V(J.exp_k(e, r), F.NFrac{}, stk, out, key, at, ea, r, stk, push(J.exp_k(e, ""), out))

def exp.NFrac(e, r, stk, out, key, at, ea):
  match e:
    case J.ENone{}:
      (Q{F.NFrac{}, key, at, ea}, (Unit{}, {==}))
    case J.ESome{u, sg, d, ds}:
      match sg:
        case J.NoSign{}:
          exp.NFrac.NoSign.k(u, d, ds, r, stk, out, key, at, ea, run_exp(ds, r, stk, SCon{J.digit_char(d), SCon{Bool.pick(Char, u, 'E', 'e'), out}}, key, ((at + 1 : U32) + 1 : U32), ea))
        case J.Plus{}:
          exp.NFrac.Plus.k(u, d, ds, r, stk, out, key, at, ea, run_exp(ds, r, stk, SCon{J.digit_char(d), SCon{'+', SCon{Bool.pick(Char, u, 'E', 'e'), out}}}, key, (((at + 1 : U32) + 1 : U32) + 1 : U32), ea))
        case J.Minus{}:
          exp.NFrac.Minus.k(u, d, ds, r, stk, out, key, at, ea, run_exp(ds, r, stk, SCon{J.digit_char(d), SCon{'-', SCon{Bool.pick(Char, u, 'E', 'e'), out}}}, key, (((at + 1 : U32) + 1 : U32) + 1 : U32), ea))

# the output of fraction then exponent, pushed in turn, is their text
law out_fe:
  for +f: J.Frac
  for +e: J.Exp
  for +o: String
  {push(J.exp_k(e, ""), push(J.frac_k(f, ""), o)) == push(J.frac_k(f, J.exp_k(e, "")), o) : String}

def out_fe(f, e, o):
  Equal.trans(String, push(J.exp_k(e, ""), push(J.frac_k(f, ""), o)), push(J.frac_k(f, "") ++ J.exp_k(e, ""), o), push(J.frac_k(f, J.exp_k(e, "")), o),
    Equal.sym(String, push(J.frac_k(f, "") ++ J.exp_k(e, ""), o), push(J.exp_k(e, ""), push(J.frac_k(f, ""), o)), T.push_app(J.frac_k(f, ""), J.exp_k(e, ""), o)),
    Equal.cong(String, String, z => push(z, o), J.frac_k(f, "") ++ J.exp_k(e, ""), J.frac_k(f, J.exp_k(e, "")),
      Equal.sym(String, J.frac_k(f, J.exp_k(e, "")), J.frac_k(f, "") ++ J.exp_k(e, ""), T.frac(f, "", J.exp_k(e, "")))))

# ... and after the int digits
law out_dfe:
  for +ds: List<&2, J.Digit>
  for +f: J.Frac
  for +e: J.Exp
  for +o: String
  {push(J.exp_k(e, ""), push(J.frac_k(f, ""), push(J.digits_k(ds, ""), o))) == push(J.digits_k(ds, J.frac_k(f, J.exp_k(e, ""))), o) : String}

def out_dfe(ds, f, e, o):
  +fe : String = J.frac_k(f, J.exp_k(e, ""))
  Equal.trans(String, push(J.exp_k(e, ""), push(J.frac_k(f, ""), push(J.digits_k(ds, ""), o))), push(fe, push(J.digits_k(ds, ""), o)), push(J.digits_k(ds, fe), o),
    out_fe(f, e, push(J.digits_k(ds, ""), o)),
    Equal.trans(String, push(fe, push(J.digits_k(ds, ""), o)), push(J.digits_k(ds, "") ++ fe, o), push(J.digits_k(ds, fe), o),
      Equal.sym(String, push(J.digits_k(ds, "") ++ fe, o), push(fe, push(J.digits_k(ds, ""), o)), T.push_app(J.digits_k(ds, ""), fe, o)),
      Equal.cong(String, String, z => push(z, o), J.digits_k(ds, "") ++ fe, J.digits_k(ds, fe),
        Equal.sym(String, J.digits_k(ds, fe), J.digits_k(ds, "") ++ fe, T.digits(ds, "", fe)))))

law tail.NZero.k2:
  for +d: J.Digit
  for +ds: List<&2, J.Digit>
  for +e: J.Exp
  for +r: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  for +a: U32
  for pre: {F.gc(J.frac_k(J.FSome{d, ds}, J.exp_k(e, r)), F.NZero{}, J.frac_k(J.FSome{d, ds}, J.exp_k(e, r)), stk, out, 0, 0, key, at, ea) == F.gc(J.exp_k(e, r), F.NFrac{}, J.exp_k(e, r), stk, push(J.digits_k(ds, ""), SCon{J.digit_char(d), SCon{'.', out}}), 0, 0, key, a, ea) : F.Out}
  for g: V(J.exp_k(e, r), F.NFrac{}, stk, push(J.digits_k(ds, ""), SCon{J.digit_char(d), SCon{'.', out}}), key, a, ea, r, stk, push(J.exp_k(e, ""), push(J.digits_k(ds, ""), SCon{J.digit_char(d), SCon{'.', out}})))
  V(J.frac_k(J.FSome{d, ds}, J.exp_k(e, r)), F.NZero{}, stk, out, key, at, ea, r, stk, push(J.exp_k(e, ""), push(J.frac_k(J.FSome{d, ds}, ""), out)))

def tail.NZero.k2(d, ds, e, r, stk, out, key, at, ea, a, pre, g):
  (+q, pr) = g
  (aft, e4) = pr
  (q, (aft, Equal.trans(F.Out, F.gc(J.frac_k(J.FSome{d, ds}, J.exp_k(e, r)), F.NZero{}, J.frac_k(J.FSome{d, ds}, J.exp_k(e, r)), stk, out, 0, 0, key, at, ea), F.gc(J.exp_k(e, r), F.NFrac{}, J.exp_k(e, r), stk, push(J.digits_k(ds, ""), SCon{J.digit_char(d), SCon{'.', out}}), 0, 0, key, a, ea), after(r, stk, push(J.exp_k(e, ""), push(J.digits_k(ds, ""), SCon{J.digit_char(d), SCon{'.', out}})), q), pre, e4)))

law tail.NZero.k1:
  for +d: J.Digit
  for +ds: List<&2, J.Digit>
  for +e: J.Exp
  for +r: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  for g: Run_frac(ds, J.exp_k(e, r), stk, SCon{J.digit_char(d), SCon{'.', out}}, key, ((at + 1 : U32) + 1 : U32), ea)
  V(J.frac_k(J.FSome{d, ds}, J.exp_k(e, r)), F.NZero{}, stk, out, key, at, ea, r, stk, push(J.exp_k(e, ""), push(J.frac_k(J.FSome{d, ds}, ""), out)))

def tail.NZero.k1(d, ds, e, r, stk, out, key, at, ea, g):
  (+a, e3) = g
  tail.NZero.k2(d, ds, e, r, stk, out, key, at, ea, a,
    Equal.trans(F.Out,
      F.gc(J.frac_k(J.FSome{d, ds}, J.exp_k(e, r)), F.NZero{}, J.frac_k(J.FSome{d, ds}, J.exp_k(e, r)), stk, out, 0, 0, key, at, ea),
      F.gc(SCon{J.digit_char(d), J.digits_k(ds, J.exp_k(e, r))}, F.NDot{}, SCon{J.digit_char(d), J.digits_k(ds, J.exp_k(e, r))}, stk, SCon{'.', out}, 0, 0, key, (at + 1 : U32), ea),
      F.gc(J.exp_k(e, r), F.NFrac{}, J.exp_k(e, r), stk, push(J.digits_k(ds, ""), SCon{J.digit_char(d), SCon{'.', out}}), 0, 0, key, a, ea),
      step_dot.NZero(SCon{J.digit_char(d), J.digits_k(ds, J.exp_k(e, r))}, stk, out, key, at, ea),
      Equal.trans(F.Out,
        F.gc(SCon{J.digit_char(d), J.digits_k(ds, J.exp_k(e, r))}, F.NDot{}, SCon{J.digit_char(d), J.digits_k(ds, J.exp_k(e, r))}, stk, SCon{'.', out}, 0, 0, key, (at + 1 : U32), ea),
        F.gc(J.digits_k(ds, J.exp_k(e, r)), F.NFrac{}, J.digits_k(ds, J.exp_k(e, r)), stk, SCon{J.digit_char(d), SCon{'.', out}}, 0, 0, key, ((at + 1 : U32) + 1 : U32), ea),
        F.gc(J.exp_k(e, r), F.NFrac{}, J.exp_k(e, r), stk, push(J.digits_k(ds, ""), SCon{J.digit_char(d), SCon{'.', out}}), 0, 0, key, a, ea),
        dstep_dot(d, J.digits_k(ds, J.exp_k(e, r)), stk, SCon{'.', out}, key, (at + 1 : U32), ea),
        e3)),
    exp.NFrac(e, r, stk, push(J.digits_k(ds, ""), SCon{J.digit_char(d), SCon{'.', out}}), key, a, ea))

law tail.NZero:
  for +f: J.Frac
  for +e: J.Exp
  for +r: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  V(J.frac_k(f, J.exp_k(e, r)), F.NZero{}, stk, out, key, at, ea, r, stk, push(J.exp_k(e, ""), push(J.frac_k(f, ""), out)))

def tail.NZero(f, e, r, stk, out, key, at, ea):
  match f:
    case J.FNone{}:
      exp.NZero(e, r, stk, out, key, at, ea)
    case J.FSome{d, ds}:
      tail.NZero.k1(d, ds, e, r, stk, out, key, at, ea, run_frac(ds, J.exp_k(e, r), stk, SCon{J.digit_char(d), SCon{'.', out}}, key, ((at + 1 : U32) + 1 : U32), ea))

law tail.NInt.k2:
  for +d: J.Digit
  for +ds: List<&2, J.Digit>
  for +e: J.Exp
  for +r: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  for +a: U32
  for pre: {F.gc(J.frac_k(J.FSome{d, ds}, J.exp_k(e, r)), F.NInt{}, J.frac_k(J.FSome{d, ds}, J.exp_k(e, r)), stk, out, 0, 0, key, at, ea) == F.gc(J.exp_k(e, r), F.NFrac{}, J.exp_k(e, r), stk, push(J.digits_k(ds, ""), SCon{J.digit_char(d), SCon{'.', out}}), 0, 0, key, a, ea) : F.Out}
  for g: V(J.exp_k(e, r), F.NFrac{}, stk, push(J.digits_k(ds, ""), SCon{J.digit_char(d), SCon{'.', out}}), key, a, ea, r, stk, push(J.exp_k(e, ""), push(J.digits_k(ds, ""), SCon{J.digit_char(d), SCon{'.', out}})))
  V(J.frac_k(J.FSome{d, ds}, J.exp_k(e, r)), F.NInt{}, stk, out, key, at, ea, r, stk, push(J.exp_k(e, ""), push(J.frac_k(J.FSome{d, ds}, ""), out)))

def tail.NInt.k2(d, ds, e, r, stk, out, key, at, ea, a, pre, g):
  (+q, pr) = g
  (aft, e4) = pr
  (q, (aft, Equal.trans(F.Out, F.gc(J.frac_k(J.FSome{d, ds}, J.exp_k(e, r)), F.NInt{}, J.frac_k(J.FSome{d, ds}, J.exp_k(e, r)), stk, out, 0, 0, key, at, ea), F.gc(J.exp_k(e, r), F.NFrac{}, J.exp_k(e, r), stk, push(J.digits_k(ds, ""), SCon{J.digit_char(d), SCon{'.', out}}), 0, 0, key, a, ea), after(r, stk, push(J.exp_k(e, ""), push(J.digits_k(ds, ""), SCon{J.digit_char(d), SCon{'.', out}})), q), pre, e4)))

law tail.NInt.k1:
  for +d: J.Digit
  for +ds: List<&2, J.Digit>
  for +e: J.Exp
  for +r: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  for g: Run_frac(ds, J.exp_k(e, r), stk, SCon{J.digit_char(d), SCon{'.', out}}, key, ((at + 1 : U32) + 1 : U32), ea)
  V(J.frac_k(J.FSome{d, ds}, J.exp_k(e, r)), F.NInt{}, stk, out, key, at, ea, r, stk, push(J.exp_k(e, ""), push(J.frac_k(J.FSome{d, ds}, ""), out)))

def tail.NInt.k1(d, ds, e, r, stk, out, key, at, ea, g):
  (+a, e3) = g
  tail.NInt.k2(d, ds, e, r, stk, out, key, at, ea, a,
    Equal.trans(F.Out,
      F.gc(J.frac_k(J.FSome{d, ds}, J.exp_k(e, r)), F.NInt{}, J.frac_k(J.FSome{d, ds}, J.exp_k(e, r)), stk, out, 0, 0, key, at, ea),
      F.gc(SCon{J.digit_char(d), J.digits_k(ds, J.exp_k(e, r))}, F.NDot{}, SCon{J.digit_char(d), J.digits_k(ds, J.exp_k(e, r))}, stk, SCon{'.', out}, 0, 0, key, (at + 1 : U32), ea),
      F.gc(J.exp_k(e, r), F.NFrac{}, J.exp_k(e, r), stk, push(J.digits_k(ds, ""), SCon{J.digit_char(d), SCon{'.', out}}), 0, 0, key, a, ea),
      step_dot.NInt(SCon{J.digit_char(d), J.digits_k(ds, J.exp_k(e, r))}, stk, out, key, at, ea),
      Equal.trans(F.Out,
        F.gc(SCon{J.digit_char(d), J.digits_k(ds, J.exp_k(e, r))}, F.NDot{}, SCon{J.digit_char(d), J.digits_k(ds, J.exp_k(e, r))}, stk, SCon{'.', out}, 0, 0, key, (at + 1 : U32), ea),
        F.gc(J.digits_k(ds, J.exp_k(e, r)), F.NFrac{}, J.digits_k(ds, J.exp_k(e, r)), stk, SCon{J.digit_char(d), SCon{'.', out}}, 0, 0, key, ((at + 1 : U32) + 1 : U32), ea),
        F.gc(J.exp_k(e, r), F.NFrac{}, J.exp_k(e, r), stk, push(J.digits_k(ds, ""), SCon{J.digit_char(d), SCon{'.', out}}), 0, 0, key, a, ea),
        dstep_dot(d, J.digits_k(ds, J.exp_k(e, r)), stk, SCon{'.', out}, key, (at + 1 : U32), ea),
        e3)),
    exp.NFrac(e, r, stk, push(J.digits_k(ds, ""), SCon{J.digit_char(d), SCon{'.', out}}), key, a, ea))

law tail.NInt:
  for +f: J.Frac
  for +e: J.Exp
  for +r: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  V(J.frac_k(f, J.exp_k(e, r)), F.NInt{}, stk, out, key, at, ea, r, stk, push(J.exp_k(e, ""), push(J.frac_k(f, ""), out)))

def tail.NInt(f, e, r, stk, out, key, at, ea):
  match f:
    case J.FNone{}:
      exp.NInt(e, r, stk, out, key, at, ea)
    case J.FSome{d, ds}:
      tail.NInt.k1(d, ds, e, r, stk, out, key, at, ea, run_frac(ds, J.exp_k(e, r), stk, SCon{J.digit_char(d), SCon{'.', out}}, key, ((at + 1 : U32) + 1 : U32), ea))

def NumV(+n: J.Number, +m: F.Mode, +r: String, +stk: List<&2, F.Box>, +out: String, +key: Bool, +at: U32, +ea: U32) -> Type:
  V(J.num_k(n, r), m, stk, out, key, at, ea, r, stk, push(J.num_k(n, ""), out))

law num.mz.k:
  for +m: F.Mode
  for +f: J.Frac
  for +e: J.Exp
  for +r: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  for pre: {F.gc(SCon{'-', SCon{'0', J.frac_k(f, J.exp_k(e, r))}}, m, SCon{'-', SCon{'0', J.frac_k(f, J.exp_k(e, r))}}, stk, out, 0, 0, key, at, ea) == F.gc(J.frac_k(f, J.exp_k(e, r)), F.NZero{}, J.frac_k(f, J.exp_k(e, r)), stk, SCon{'0', SCon{'-', out}}, 0, 0, key, ((at + 1 : U32) + 1 : U32), ea) : F.Out}
  for g: V(J.frac_k(f, J.exp_k(e, r)), F.NZero{}, stk, SCon{'0', SCon{'-', out}}, key, ((at + 1 : U32) + 1 : U32), ea, r, stk, push(J.exp_k(e, ""), push(J.frac_k(f, ""), SCon{'0', SCon{'-', out}})))
  NumV(J.Number{True{}, J.IZero{}, f, e}, m, r, stk, out, key, at, ea)

def num.mz.k(m, f, e, r, stk, out, key, at, ea, pre, g):
  (+q, pr) = g
  (aft, e3) = pr
  (q, (aft, Equal.trans(F.Out, F.gc(SCon{'-', SCon{'0', J.frac_k(f, J.exp_k(e, r))}}, m, SCon{'-', SCon{'0', J.frac_k(f, J.exp_k(e, r))}}, stk, out, 0, 0, key, at, ea), F.gc(J.frac_k(f, J.exp_k(e, r)), F.NZero{}, J.frac_k(f, J.exp_k(e, r)), stk, SCon{'0', SCon{'-', out}}, 0, 0, key, ((at + 1 : U32) + 1 : U32), ea), after(r, stk, push(J.num_k(J.Number{True{}, J.IZero{}, f, e}, ""), out), q), pre, Equal.trans(F.Out, F.gc(J.frac_k(f, J.exp_k(e, r)), F.NZero{}, J.frac_k(f, J.exp_k(e, r)), stk, SCon{'0', SCon{'-', out}}, 0, 0, key, ((at + 1 : U32) + 1 : U32), ea), after(r, stk, push(J.exp_k(e, ""), push(J.frac_k(f, ""), SCon{'0', SCon{'-', out}})), q), after(r, stk, push(J.num_k(J.Number{True{}, J.IZero{}, f, e}, ""), out), q), e3, Equal.cong(String, F.Out, z => after(r, stk, z, q), push(J.exp_k(e, ""), push(J.frac_k(f, ""), SCon{'0', SCon{'-', out}})), push(J.num_k(J.Number{True{}, J.IZero{}, f, e}, ""), out), out_fe(f, e, SCon{'0', SCon{'-', out}}))))))

law num.mz:
  for +m: F.Mode
  for vm: ValM(m)
  for +f: J.Frac
  for +e: J.Exp
  for +r: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  NumV(J.Number{True{}, J.IZero{}, f, e}, m, r, stk, out, key, at, ea)

def num.mz(m, vm, f, e, r, stk, out, key, at, ea):
  num.mz.k(m, f, e, r, stk, out, key, at, ea, Equal.trans(F.Out, F.gc(SCon{'-', SCon{'0', J.frac_k(f, J.exp_k(e, r))}}, m, SCon{'-', SCon{'0', J.frac_k(f, J.exp_k(e, r))}}, stk, out, 0, 0, key, at, ea), F.gc(SCon{'0', J.frac_k(f, J.exp_k(e, r))}, F.NMin{}, SCon{'0', J.frac_k(f, J.exp_k(e, r))}, stk, SCon{'-', out}, 0, 0, key, (at + 1 : U32), ea), F.gc(J.frac_k(f, J.exp_k(e, r)), F.NZero{}, J.frac_k(f, J.exp_k(e, r)), stk, SCon{'0', SCon{'-', out}}, 0, 0, key, ((at + 1 : U32) + 1 : U32), ea), v_minus(m, vm, SCon{'0', J.frac_k(f, J.exp_k(e, r))}, stk, out, key, at, ea), min_zero(J.frac_k(f, J.exp_k(e, r)), stk, SCon{'-', out}, key, (at + 1 : U32), ea)), tail.NZero(f, e, r, stk, SCon{'0', SCon{'-', out}}, key, ((at + 1 : U32) + 1 : U32), ea))

law num.ml.k2:
  for +m: F.Mode
  for +f: J.Frac
  for +e: J.Exp
  for +l: J.Lead
  for +ds: List<&2, J.Digit>
  for +r: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  for +a: U32
  for pre: {F.gc(SCon{'-', SCon{J.lead_char(l), J.digits_k(ds, J.frac_k(f, J.exp_k(e, r)))}}, m, SCon{'-', SCon{J.lead_char(l), J.digits_k(ds, J.frac_k(f, J.exp_k(e, r)))}}, stk, out, 0, 0, key, at, ea) == F.gc(J.frac_k(f, J.exp_k(e, r)), F.NInt{}, J.frac_k(f, J.exp_k(e, r)), stk, push(J.digits_k(ds, ""), SCon{J.lead_char(l), SCon{'-', out}}), 0, 0, key, a, ea) : F.Out}
  for g: V(J.frac_k(f, J.exp_k(e, r)), F.NInt{}, stk, push(J.digits_k(ds, ""), SCon{J.lead_char(l), SCon{'-', out}}), key, a, ea, r, stk, push(J.exp_k(e, ""), push(J.frac_k(f, ""), push(J.digits_k(ds, ""), SCon{J.lead_char(l), SCon{'-', out}}))))
  NumV(J.Number{True{}, J.INon{l, ds}, f, e}, m, r, stk, out, key, at, ea)

def num.ml.k2(m, f, e, l, ds, r, stk, out, key, at, ea, a, pre, g):
  (+q, pr) = g
  (aft, e4) = pr
  (q, (aft, Equal.trans(F.Out, F.gc(SCon{'-', SCon{J.lead_char(l), J.digits_k(ds, J.frac_k(f, J.exp_k(e, r)))}}, m, SCon{'-', SCon{J.lead_char(l), J.digits_k(ds, J.frac_k(f, J.exp_k(e, r)))}}, stk, out, 0, 0, key, at, ea), F.gc(J.frac_k(f, J.exp_k(e, r)), F.NInt{}, J.frac_k(f, J.exp_k(e, r)), stk, push(J.digits_k(ds, ""), SCon{J.lead_char(l), SCon{'-', out}}), 0, 0, key, a, ea), after(r, stk, push(J.num_k(J.Number{True{}, J.INon{l, ds}, f, e}, ""), out), q), pre, Equal.trans(F.Out, F.gc(J.frac_k(f, J.exp_k(e, r)), F.NInt{}, J.frac_k(f, J.exp_k(e, r)), stk, push(J.digits_k(ds, ""), SCon{J.lead_char(l), SCon{'-', out}}), 0, 0, key, a, ea), after(r, stk, push(J.exp_k(e, ""), push(J.frac_k(f, ""), push(J.digits_k(ds, ""), SCon{J.lead_char(l), SCon{'-', out}}))), q), after(r, stk, push(J.num_k(J.Number{True{}, J.INon{l, ds}, f, e}, ""), out), q), e4, Equal.cong(String, F.Out, z => after(r, stk, z, q), push(J.exp_k(e, ""), push(J.frac_k(f, ""), push(J.digits_k(ds, ""), SCon{J.lead_char(l), SCon{'-', out}}))), push(J.num_k(J.Number{True{}, J.INon{l, ds}, f, e}, ""), out), out_dfe(ds, f, e, SCon{J.lead_char(l), SCon{'-', out}}))))))

law num.ml.k1:
  for +m: F.Mode
  for +f: J.Frac
  for +e: J.Exp
  for +l: J.Lead
  for +ds: List<&2, J.Digit>
  for +r: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  for pre: {F.gc(SCon{'-', SCon{J.lead_char(l), J.digits_k(ds, J.frac_k(f, J.exp_k(e, r)))}}, m, SCon{'-', SCon{J.lead_char(l), J.digits_k(ds, J.frac_k(f, J.exp_k(e, r)))}}, stk, out, 0, 0, key, at, ea) == F.gc(J.digits_k(ds, J.frac_k(f, J.exp_k(e, r))), F.NInt{}, J.digits_k(ds, J.frac_k(f, J.exp_k(e, r))), stk, SCon{J.lead_char(l), SCon{'-', out}}, 0, 0, key, ((at + 1 : U32) + 1 : U32), ea) : F.Out}
  for g: Run_int(ds, J.frac_k(f, J.exp_k(e, r)), stk, SCon{J.lead_char(l), SCon{'-', out}}, key, ((at + 1 : U32) + 1 : U32), ea)
  NumV(J.Number{True{}, J.INon{l, ds}, f, e}, m, r, stk, out, key, at, ea)

def num.ml.k1(m, f, e, l, ds, r, stk, out, key, at, ea, pre, g):
  (+a, e3) = g
  num.ml.k2(m, f, e, l, ds, r, stk, out, key, at, ea, a, Equal.trans(F.Out, F.gc(SCon{'-', SCon{J.lead_char(l), J.digits_k(ds, J.frac_k(f, J.exp_k(e, r)))}}, m, SCon{'-', SCon{J.lead_char(l), J.digits_k(ds, J.frac_k(f, J.exp_k(e, r)))}}, stk, out, 0, 0, key, at, ea), F.gc(J.digits_k(ds, J.frac_k(f, J.exp_k(e, r))), F.NInt{}, J.digits_k(ds, J.frac_k(f, J.exp_k(e, r))), stk, SCon{J.lead_char(l), SCon{'-', out}}, 0, 0, key, ((at + 1 : U32) + 1 : U32), ea), F.gc(J.frac_k(f, J.exp_k(e, r)), F.NInt{}, J.frac_k(f, J.exp_k(e, r)), stk, push(J.digits_k(ds, ""), SCon{J.lead_char(l), SCon{'-', out}}), 0, 0, key, a, ea), pre, e3), tail.NInt(f, e, r, stk, push(J.digits_k(ds, ""), SCon{J.lead_char(l), SCon{'-', out}}), key, a, ea))

law num.ml:
  for +m: F.Mode
  for vm: ValM(m)
  for +f: J.Frac
  for +e: J.Exp
  for +l: J.Lead
  for +ds: List<&2, J.Digit>
  for +r: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  NumV(J.Number{True{}, J.INon{l, ds}, f, e}, m, r, stk, out, key, at, ea)

def num.ml(m, vm, f, e, l, ds, r, stk, out, key, at, ea):
  num.ml.k1(m, f, e, l, ds, r, stk, out, key, at, ea, Equal.trans(F.Out, F.gc(SCon{'-', SCon{J.lead_char(l), J.digits_k(ds, J.frac_k(f, J.exp_k(e, r)))}}, m, SCon{'-', SCon{J.lead_char(l), J.digits_k(ds, J.frac_k(f, J.exp_k(e, r)))}}, stk, out, 0, 0, key, at, ea), F.gc(SCon{J.lead_char(l), J.digits_k(ds, J.frac_k(f, J.exp_k(e, r)))}, F.NMin{}, SCon{J.lead_char(l), J.digits_k(ds, J.frac_k(f, J.exp_k(e, r)))}, stk, SCon{'-', out}, 0, 0, key, (at + 1 : U32), ea), F.gc(J.digits_k(ds, J.frac_k(f, J.exp_k(e, r))), F.NInt{}, J.digits_k(ds, J.frac_k(f, J.exp_k(e, r))), stk, SCon{J.lead_char(l), SCon{'-', out}}, 0, 0, key, ((at + 1 : U32) + 1 : U32), ea), v_minus(m, vm, SCon{J.lead_char(l), J.digits_k(ds, J.frac_k(f, J.exp_k(e, r)))}, stk, out, key, at, ea), min_lead(l, J.digits_k(ds, J.frac_k(f, J.exp_k(e, r))), stk, SCon{'-', out}, key, (at + 1 : U32), ea)), run_int(ds, J.frac_k(f, J.exp_k(e, r)), stk, SCon{J.lead_char(l), SCon{'-', out}}, key, ((at + 1 : U32) + 1 : U32), ea))

law num.pz.k:
  for +m: F.Mode
  for +f: J.Frac
  for +e: J.Exp
  for +r: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  for pre: {F.gc(SCon{'0', J.frac_k(f, J.exp_k(e, r))}, m, SCon{'0', J.frac_k(f, J.exp_k(e, r))}, stk, out, 0, 0, key, at, ea) == F.gc(J.frac_k(f, J.exp_k(e, r)), F.NZero{}, J.frac_k(f, J.exp_k(e, r)), stk, SCon{'0', out}, 0, 0, key, (at + 1 : U32), ea) : F.Out}
  for g: V(J.frac_k(f, J.exp_k(e, r)), F.NZero{}, stk, SCon{'0', out}, key, (at + 1 : U32), ea, r, stk, push(J.exp_k(e, ""), push(J.frac_k(f, ""), SCon{'0', out})))
  NumV(J.Number{False{}, J.IZero{}, f, e}, m, r, stk, out, key, at, ea)

def num.pz.k(m, f, e, r, stk, out, key, at, ea, pre, g):
  (+q, pr) = g
  (aft, e3) = pr
  (q, (aft, Equal.trans(F.Out, F.gc(SCon{'0', J.frac_k(f, J.exp_k(e, r))}, m, SCon{'0', J.frac_k(f, J.exp_k(e, r))}, stk, out, 0, 0, key, at, ea), F.gc(J.frac_k(f, J.exp_k(e, r)), F.NZero{}, J.frac_k(f, J.exp_k(e, r)), stk, SCon{'0', out}, 0, 0, key, (at + 1 : U32), ea), after(r, stk, push(J.num_k(J.Number{False{}, J.IZero{}, f, e}, ""), out), q), pre, Equal.trans(F.Out, F.gc(J.frac_k(f, J.exp_k(e, r)), F.NZero{}, J.frac_k(f, J.exp_k(e, r)), stk, SCon{'0', out}, 0, 0, key, (at + 1 : U32), ea), after(r, stk, push(J.exp_k(e, ""), push(J.frac_k(f, ""), SCon{'0', out})), q), after(r, stk, push(J.num_k(J.Number{False{}, J.IZero{}, f, e}, ""), out), q), e3, Equal.cong(String, F.Out, z => after(r, stk, z, q), push(J.exp_k(e, ""), push(J.frac_k(f, ""), SCon{'0', out})), push(J.num_k(J.Number{False{}, J.IZero{}, f, e}, ""), out), out_fe(f, e, SCon{'0', out}))))))

law num.pz:
  for +m: F.Mode
  for vm: ValM(m)
  for +f: J.Frac
  for +e: J.Exp
  for +r: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  NumV(J.Number{False{}, J.IZero{}, f, e}, m, r, stk, out, key, at, ea)

def num.pz(m, vm, f, e, r, stk, out, key, at, ea):
  num.pz.k(m, f, e, r, stk, out, key, at, ea, v_zero(m, vm, J.frac_k(f, J.exp_k(e, r)), stk, out, key, at, ea), tail.NZero(f, e, r, stk, SCon{'0', out}, key, (at + 1 : U32), ea))

law num.pl.k2:
  for +m: F.Mode
  for +f: J.Frac
  for +e: J.Exp
  for +l: J.Lead
  for +ds: List<&2, J.Digit>
  for +r: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  for +a: U32
  for pre: {F.gc(SCon{J.lead_char(l), J.digits_k(ds, J.frac_k(f, J.exp_k(e, r)))}, m, SCon{J.lead_char(l), J.digits_k(ds, J.frac_k(f, J.exp_k(e, r)))}, stk, out, 0, 0, key, at, ea) == F.gc(J.frac_k(f, J.exp_k(e, r)), F.NInt{}, J.frac_k(f, J.exp_k(e, r)), stk, push(J.digits_k(ds, ""), SCon{J.lead_char(l), out}), 0, 0, key, a, ea) : F.Out}
  for g: V(J.frac_k(f, J.exp_k(e, r)), F.NInt{}, stk, push(J.digits_k(ds, ""), SCon{J.lead_char(l), out}), key, a, ea, r, stk, push(J.exp_k(e, ""), push(J.frac_k(f, ""), push(J.digits_k(ds, ""), SCon{J.lead_char(l), out}))))
  NumV(J.Number{False{}, J.INon{l, ds}, f, e}, m, r, stk, out, key, at, ea)

def num.pl.k2(m, f, e, l, ds, r, stk, out, key, at, ea, a, pre, g):
  (+q, pr) = g
  (aft, e4) = pr
  (q, (aft, Equal.trans(F.Out, F.gc(SCon{J.lead_char(l), J.digits_k(ds, J.frac_k(f, J.exp_k(e, r)))}, m, SCon{J.lead_char(l), J.digits_k(ds, J.frac_k(f, J.exp_k(e, r)))}, stk, out, 0, 0, key, at, ea), F.gc(J.frac_k(f, J.exp_k(e, r)), F.NInt{}, J.frac_k(f, J.exp_k(e, r)), stk, push(J.digits_k(ds, ""), SCon{J.lead_char(l), out}), 0, 0, key, a, ea), after(r, stk, push(J.num_k(J.Number{False{}, J.INon{l, ds}, f, e}, ""), out), q), pre, Equal.trans(F.Out, F.gc(J.frac_k(f, J.exp_k(e, r)), F.NInt{}, J.frac_k(f, J.exp_k(e, r)), stk, push(J.digits_k(ds, ""), SCon{J.lead_char(l), out}), 0, 0, key, a, ea), after(r, stk, push(J.exp_k(e, ""), push(J.frac_k(f, ""), push(J.digits_k(ds, ""), SCon{J.lead_char(l), out}))), q), after(r, stk, push(J.num_k(J.Number{False{}, J.INon{l, ds}, f, e}, ""), out), q), e4, Equal.cong(String, F.Out, z => after(r, stk, z, q), push(J.exp_k(e, ""), push(J.frac_k(f, ""), push(J.digits_k(ds, ""), SCon{J.lead_char(l), out}))), push(J.num_k(J.Number{False{}, J.INon{l, ds}, f, e}, ""), out), out_dfe(ds, f, e, SCon{J.lead_char(l), out}))))))

law num.pl.k1:
  for +m: F.Mode
  for +f: J.Frac
  for +e: J.Exp
  for +l: J.Lead
  for +ds: List<&2, J.Digit>
  for +r: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  for pre: {F.gc(SCon{J.lead_char(l), J.digits_k(ds, J.frac_k(f, J.exp_k(e, r)))}, m, SCon{J.lead_char(l), J.digits_k(ds, J.frac_k(f, J.exp_k(e, r)))}, stk, out, 0, 0, key, at, ea) == F.gc(J.digits_k(ds, J.frac_k(f, J.exp_k(e, r))), F.NInt{}, J.digits_k(ds, J.frac_k(f, J.exp_k(e, r))), stk, SCon{J.lead_char(l), out}, 0, 0, key, (at + 1 : U32), ea) : F.Out}
  for g: Run_int(ds, J.frac_k(f, J.exp_k(e, r)), stk, SCon{J.lead_char(l), out}, key, (at + 1 : U32), ea)
  NumV(J.Number{False{}, J.INon{l, ds}, f, e}, m, r, stk, out, key, at, ea)

def num.pl.k1(m, f, e, l, ds, r, stk, out, key, at, ea, pre, g):
  (+a, e3) = g
  num.pl.k2(m, f, e, l, ds, r, stk, out, key, at, ea, a, Equal.trans(F.Out, F.gc(SCon{J.lead_char(l), J.digits_k(ds, J.frac_k(f, J.exp_k(e, r)))}, m, SCon{J.lead_char(l), J.digits_k(ds, J.frac_k(f, J.exp_k(e, r)))}, stk, out, 0, 0, key, at, ea), F.gc(J.digits_k(ds, J.frac_k(f, J.exp_k(e, r))), F.NInt{}, J.digits_k(ds, J.frac_k(f, J.exp_k(e, r))), stk, SCon{J.lead_char(l), out}, 0, 0, key, (at + 1 : U32), ea), F.gc(J.frac_k(f, J.exp_k(e, r)), F.NInt{}, J.frac_k(f, J.exp_k(e, r)), stk, push(J.digits_k(ds, ""), SCon{J.lead_char(l), out}), 0, 0, key, a, ea), pre, e3), tail.NInt(f, e, r, stk, push(J.digits_k(ds, ""), SCon{J.lead_char(l), out}), key, a, ea))

law num.pl:
  for +m: F.Mode
  for vm: ValM(m)
  for +f: J.Frac
  for +e: J.Exp
  for +l: J.Lead
  for +ds: List<&2, J.Digit>
  for +r: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  NumV(J.Number{False{}, J.INon{l, ds}, f, e}, m, r, stk, out, key, at, ea)

def num.pl(m, vm, f, e, l, ds, r, stk, out, key, at, ea):
  num.pl.k1(m, f, e, l, ds, r, stk, out, key, at, ea, v_lead(m, vm, l, J.digits_k(ds, J.frac_k(f, J.exp_k(e, r))), stk, out, key, at, ea), run_int(ds, J.frac_k(f, J.exp_k(e, r)), stk, SCon{J.lead_char(l), out}, key, (at + 1 : U32), ea))

law num:
  for +n: J.Number
  for +m: F.Mode
  for vm: ValM(m)
  for +r: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  NumV(n, m, r, stk, out, key, at, ea)

def num(n, m, vm, r, stk, out, key, at, ea):
  match n:
    case J.Number{True{}, J.IZero{}, f, e}:
      num.mz(m, vm, f, e, r, stk, out, key, at, ea)
    case J.Number{True{}, J.INon{l, ds}, f, e}:
      num.ml(m, vm, f, e, l, ds, r, stk, out, key, at, ea)
    case J.Number{False{}, J.IZero{}, f, e}:
      num.pz(m, vm, f, e, r, stk, out, key, at, ea)
    case J.Number{False{}, J.INon{l, ds}, f, e}:
      num.pl(m, vm, f, e, l, ds, r, stk, out, key, at, ea)

# Values
# ------

law v_null:
  for +m: F.Mode
  for g: ValM(m)
  for +x: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  {F.gc("null" ++ x, m, "null" ++ x, stk, out, 0, 0, key, at, ea) == F.gc(x, F.VAfter{}, x, stk, SCon{'l', SCon{'l', SCon{'u', SCon{'n', out}}}}, 0, 0, key, ((((at + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32), ea) : F.Out}

def v_null(m, g, x, stk, out, key, at, ea):
  match m stk:
    case F.VStart{} Nil{}:
      {==}
    case F.VStart{} Con{F.BArr{}, up}:
      {==}
    case F.VStart{} Con{F.BObj{}, up}:
      {==}
    case F.VTop{} Nil{}:
      {==}
    case F.VTop{} Con{F.BArr{}, up}:
      {==}
    case F.VTop{} Con{F.BObj{}, up}:
      {==}
    case F.VFirst{} Nil{}:
      {==}
    case F.VFirst{} Con{F.BArr{}, up}:
      {==}
    case F.VFirst{} Con{F.BObj{}, up}:
      {==}
    case F.VItem{} Nil{}:
      {==}
    case F.VItem{} Con{F.BArr{}, up}:
      {==}
    case F.VItem{} Con{F.BObj{}, up}:
      {==}
    case F.VObjFirst{} _:
      match g:
    case F.VKey{} _:
      match g:
    case F.VColon{} _:
      match g:
    case F.VObjVal{} Nil{}:
      {==}
    case F.VObjVal{} Con{F.BArr{}, up}:
      {==}
    case F.VObjVal{} Con{F.BObj{}, up}:
      {==}
    case F.VAfter{} _:
      match g:
    case F.SStr{} _:
      match g:
    case F.SEsc{} _:
      match g:
    case F.SU4{} _:
      match g:
    case F.SU3{} _:
      match g:
    case F.SU2{} _:
      match g:
    case F.SU1{} _:
      match g:
    case F.SHi{} _:
      match g:
    case F.SHiU{} _:
      match g:
    case F.NMin{} _:
      match g:
    case F.NZero{} _:
      match g:
    case F.NInt{} _:
      match g:
    case F.NDot{} _:
      match g:
    case F.NFrac{} _:
      match g:
    case F.NE{} _:
      match g:
    case F.NESign{} _:
      match g:
    case F.NExp{} _:
      match g:
    case F.T1{} _:
      match g:
    case F.T2{} _:
      match g:
    case F.T3{} _:
      match g:
    case F.F1{} _:
      match g:
    case F.F2{} _:
      match g:
    case F.F3{} _:
      match g:
    case F.F4{} _:
      match g:
    case F.U1{} _:
      match g:
    case F.U2{} _:
      match g:
    case F.U3{} _:
      match g:
    case F.BCtrl{} _:
      match g:
    case F.BUni{} _:
      match g:
    case F.BLone{} _:
      match g:
    case F.BEsc{} _:
      match g:

law v_true:
  for +m: F.Mode
  for g: ValM(m)
  for +x: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  {F.gc("true" ++ x, m, "true" ++ x, stk, out, 0, 0, key, at, ea) == F.gc(x, F.VAfter{}, x, stk, SCon{'e', SCon{'u', SCon{'r', SCon{'t', out}}}}, 0, 0, key, ((((at + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32), ea) : F.Out}

def v_true(m, g, x, stk, out, key, at, ea):
  match m stk:
    case F.VStart{} Nil{}:
      {==}
    case F.VStart{} Con{F.BArr{}, up}:
      {==}
    case F.VStart{} Con{F.BObj{}, up}:
      {==}
    case F.VTop{} Nil{}:
      {==}
    case F.VTop{} Con{F.BArr{}, up}:
      {==}
    case F.VTop{} Con{F.BObj{}, up}:
      {==}
    case F.VFirst{} Nil{}:
      {==}
    case F.VFirst{} Con{F.BArr{}, up}:
      {==}
    case F.VFirst{} Con{F.BObj{}, up}:
      {==}
    case F.VItem{} Nil{}:
      {==}
    case F.VItem{} Con{F.BArr{}, up}:
      {==}
    case F.VItem{} Con{F.BObj{}, up}:
      {==}
    case F.VObjFirst{} _:
      match g:
    case F.VKey{} _:
      match g:
    case F.VColon{} _:
      match g:
    case F.VObjVal{} Nil{}:
      {==}
    case F.VObjVal{} Con{F.BArr{}, up}:
      {==}
    case F.VObjVal{} Con{F.BObj{}, up}:
      {==}
    case F.VAfter{} _:
      match g:
    case F.SStr{} _:
      match g:
    case F.SEsc{} _:
      match g:
    case F.SU4{} _:
      match g:
    case F.SU3{} _:
      match g:
    case F.SU2{} _:
      match g:
    case F.SU1{} _:
      match g:
    case F.SHi{} _:
      match g:
    case F.SHiU{} _:
      match g:
    case F.NMin{} _:
      match g:
    case F.NZero{} _:
      match g:
    case F.NInt{} _:
      match g:
    case F.NDot{} _:
      match g:
    case F.NFrac{} _:
      match g:
    case F.NE{} _:
      match g:
    case F.NESign{} _:
      match g:
    case F.NExp{} _:
      match g:
    case F.T1{} _:
      match g:
    case F.T2{} _:
      match g:
    case F.T3{} _:
      match g:
    case F.F1{} _:
      match g:
    case F.F2{} _:
      match g:
    case F.F3{} _:
      match g:
    case F.F4{} _:
      match g:
    case F.U1{} _:
      match g:
    case F.U2{} _:
      match g:
    case F.U3{} _:
      match g:
    case F.BCtrl{} _:
      match g:
    case F.BUni{} _:
      match g:
    case F.BLone{} _:
      match g:
    case F.BEsc{} _:
      match g:

law v_false:
  for +m: F.Mode
  for g: ValM(m)
  for +x: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  {F.gc("false" ++ x, m, "false" ++ x, stk, out, 0, 0, key, at, ea) == F.gc(x, F.VAfter{}, x, stk, SCon{'e', SCon{'s', SCon{'l', SCon{'a', SCon{'f', out}}}}}, 0, 0, key, (((((at + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32), ea) : F.Out}

def v_false(m, g, x, stk, out, key, at, ea):
  match m stk:
    case F.VStart{} Nil{}:
      {==}
    case F.VStart{} Con{F.BArr{}, up}:
      {==}
    case F.VStart{} Con{F.BObj{}, up}:
      {==}
    case F.VTop{} Nil{}:
      {==}
    case F.VTop{} Con{F.BArr{}, up}:
      {==}
    case F.VTop{} Con{F.BObj{}, up}:
      {==}
    case F.VFirst{} Nil{}:
      {==}
    case F.VFirst{} Con{F.BArr{}, up}:
      {==}
    case F.VFirst{} Con{F.BObj{}, up}:
      {==}
    case F.VItem{} Nil{}:
      {==}
    case F.VItem{} Con{F.BArr{}, up}:
      {==}
    case F.VItem{} Con{F.BObj{}, up}:
      {==}
    case F.VObjFirst{} _:
      match g:
    case F.VKey{} _:
      match g:
    case F.VColon{} _:
      match g:
    case F.VObjVal{} Nil{}:
      {==}
    case F.VObjVal{} Con{F.BArr{}, up}:
      {==}
    case F.VObjVal{} Con{F.BObj{}, up}:
      {==}
    case F.VAfter{} _:
      match g:
    case F.SStr{} _:
      match g:
    case F.SEsc{} _:
      match g:
    case F.SU4{} _:
      match g:
    case F.SU3{} _:
      match g:
    case F.SU2{} _:
      match g:
    case F.SU1{} _:
      match g:
    case F.SHi{} _:
      match g:
    case F.SHiU{} _:
      match g:
    case F.NMin{} _:
      match g:
    case F.NZero{} _:
      match g:
    case F.NInt{} _:
      match g:
    case F.NDot{} _:
      match g:
    case F.NFrac{} _:
      match g:
    case F.NE{} _:
      match g:
    case F.NESign{} _:
      match g:
    case F.NExp{} _:
      match g:
    case F.T1{} _:
      match g:
    case F.T2{} _:
      match g:
    case F.T3{} _:
      match g:
    case F.F1{} _:
      match g:
    case F.F2{} _:
      match g:
    case F.F3{} _:
      match g:
    case F.F4{} _:
      match g:
    case F.U1{} _:
      match g:
    case F.U2{} _:
      match g:
    case F.U3{} _:
      match g:
    case F.BCtrl{} _:
      match g:
    case F.BUni{} _:
      match g:
    case F.BLone{} _:
      match g:
    case F.BEsc{} _:
      match g:

law v_quote:
  for +m: F.Mode
  for g: ValM(m)
  for +x: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  {F.gc(SCon{'"', x}, m, SCon{'"', x}, stk, out, 0, 0, key, at, ea) == F.gc(x, F.SStr{}, x, stk, SCon{'"', out}, 0, 0, False{}, (at + 1 : U32), ea) : F.Out}

def v_quote(m, g, x, stk, out, key, at, ea):
  match m stk:
    case F.VStart{} Nil{}:
      {==}
    case F.VStart{} Con{F.BArr{}, up}:
      {==}
    case F.VStart{} Con{F.BObj{}, up}:
      {==}
    case F.VTop{} Nil{}:
      {==}
    case F.VTop{} Con{F.BArr{}, up}:
      {==}
    case F.VTop{} Con{F.BObj{}, up}:
      {==}
    case F.VFirst{} Nil{}:
      {==}
    case F.VFirst{} Con{F.BArr{}, up}:
      {==}
    case F.VFirst{} Con{F.BObj{}, up}:
      {==}
    case F.VItem{} Nil{}:
      {==}
    case F.VItem{} Con{F.BArr{}, up}:
      {==}
    case F.VItem{} Con{F.BObj{}, up}:
      {==}
    case F.VObjFirst{} _:
      match g:
    case F.VKey{} _:
      match g:
    case F.VColon{} _:
      match g:
    case F.VObjVal{} Nil{}:
      {==}
    case F.VObjVal{} Con{F.BArr{}, up}:
      {==}
    case F.VObjVal{} Con{F.BObj{}, up}:
      {==}
    case F.VAfter{} _:
      match g:
    case F.SStr{} _:
      match g:
    case F.SEsc{} _:
      match g:
    case F.SU4{} _:
      match g:
    case F.SU3{} _:
      match g:
    case F.SU2{} _:
      match g:
    case F.SU1{} _:
      match g:
    case F.SHi{} _:
      match g:
    case F.SHiU{} _:
      match g:
    case F.NMin{} _:
      match g:
    case F.NZero{} _:
      match g:
    case F.NInt{} _:
      match g:
    case F.NDot{} _:
      match g:
    case F.NFrac{} _:
      match g:
    case F.NE{} _:
      match g:
    case F.NESign{} _:
      match g:
    case F.NExp{} _:
      match g:
    case F.T1{} _:
      match g:
    case F.T2{} _:
      match g:
    case F.T3{} _:
      match g:
    case F.F1{} _:
      match g:
    case F.F2{} _:
      match g:
    case F.F3{} _:
      match g:
    case F.F4{} _:
      match g:
    case F.U1{} _:
      match g:
    case F.U2{} _:
      match g:
    case F.U3{} _:
      match g:
    case F.BCtrl{} _:
      match g:
    case F.BUni{} _:
      match g:
    case F.BLone{} _:
      match g:
    case F.BEsc{} _:
      match g:

law v_arr:
  for +m: F.Mode
  for g: ValM(m)
  for +x: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  {F.gc(SCon{'[', x}, m, SCon{'[', x}, stk, out, 0, 0, key, at, ea) == F.gc(x, F.VFirst{}, x, Con{F.BArr{}, stk}, SCon{'[', out}, 0, 0, key, (at + 1 : U32), ea) : F.Out}

def v_arr(m, g, x, stk, out, key, at, ea):
  match m stk:
    case F.VStart{} Nil{}:
      {==}
    case F.VStart{} Con{F.BArr{}, up}:
      {==}
    case F.VStart{} Con{F.BObj{}, up}:
      {==}
    case F.VTop{} Nil{}:
      {==}
    case F.VTop{} Con{F.BArr{}, up}:
      {==}
    case F.VTop{} Con{F.BObj{}, up}:
      {==}
    case F.VFirst{} Nil{}:
      {==}
    case F.VFirst{} Con{F.BArr{}, up}:
      {==}
    case F.VFirst{} Con{F.BObj{}, up}:
      {==}
    case F.VItem{} Nil{}:
      {==}
    case F.VItem{} Con{F.BArr{}, up}:
      {==}
    case F.VItem{} Con{F.BObj{}, up}:
      {==}
    case F.VObjFirst{} _:
      match g:
    case F.VKey{} _:
      match g:
    case F.VColon{} _:
      match g:
    case F.VObjVal{} Nil{}:
      {==}
    case F.VObjVal{} Con{F.BArr{}, up}:
      {==}
    case F.VObjVal{} Con{F.BObj{}, up}:
      {==}
    case F.VAfter{} _:
      match g:
    case F.SStr{} _:
      match g:
    case F.SEsc{} _:
      match g:
    case F.SU4{} _:
      match g:
    case F.SU3{} _:
      match g:
    case F.SU2{} _:
      match g:
    case F.SU1{} _:
      match g:
    case F.SHi{} _:
      match g:
    case F.SHiU{} _:
      match g:
    case F.NMin{} _:
      match g:
    case F.NZero{} _:
      match g:
    case F.NInt{} _:
      match g:
    case F.NDot{} _:
      match g:
    case F.NFrac{} _:
      match g:
    case F.NE{} _:
      match g:
    case F.NESign{} _:
      match g:
    case F.NExp{} _:
      match g:
    case F.T1{} _:
      match g:
    case F.T2{} _:
      match g:
    case F.T3{} _:
      match g:
    case F.F1{} _:
      match g:
    case F.F2{} _:
      match g:
    case F.F3{} _:
      match g:
    case F.F4{} _:
      match g:
    case F.U1{} _:
      match g:
    case F.U2{} _:
      match g:
    case F.U3{} _:
      match g:
    case F.BCtrl{} _:
      match g:
    case F.BUni{} _:
      match g:
    case F.BLone{} _:
      match g:
    case F.BEsc{} _:
      match g:

law v_obj:
  for +m: F.Mode
  for g: ValM(m)
  for +x: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  {F.gc(SCon{'{', x}, m, SCon{'{', x}, stk, out, 0, 0, key, at, ea) == F.gc(x, F.VObjFirst{}, x, Con{F.BObj{}, stk}, SCon{'{', out}, 0, 0, key, (at + 1 : U32), ea) : F.Out}

def v_obj(m, g, x, stk, out, key, at, ea):
  match m stk:
    case F.VStart{} Nil{}:
      {==}
    case F.VStart{} Con{F.BArr{}, up}:
      {==}
    case F.VStart{} Con{F.BObj{}, up}:
      {==}
    case F.VTop{} Nil{}:
      {==}
    case F.VTop{} Con{F.BArr{}, up}:
      {==}
    case F.VTop{} Con{F.BObj{}, up}:
      {==}
    case F.VFirst{} Nil{}:
      {==}
    case F.VFirst{} Con{F.BArr{}, up}:
      {==}
    case F.VFirst{} Con{F.BObj{}, up}:
      {==}
    case F.VItem{} Nil{}:
      {==}
    case F.VItem{} Con{F.BArr{}, up}:
      {==}
    case F.VItem{} Con{F.BObj{}, up}:
      {==}
    case F.VObjFirst{} _:
      match g:
    case F.VKey{} _:
      match g:
    case F.VColon{} _:
      match g:
    case F.VObjVal{} Nil{}:
      {==}
    case F.VObjVal{} Con{F.BArr{}, up}:
      {==}
    case F.VObjVal{} Con{F.BObj{}, up}:
      {==}
    case F.VAfter{} _:
      match g:
    case F.SStr{} _:
      match g:
    case F.SEsc{} _:
      match g:
    case F.SU4{} _:
      match g:
    case F.SU3{} _:
      match g:
    case F.SU2{} _:
      match g:
    case F.SU1{} _:
      match g:
    case F.SHi{} _:
      match g:
    case F.SHiU{} _:
      match g:
    case F.NMin{} _:
      match g:
    case F.NZero{} _:
      match g:
    case F.NInt{} _:
      match g:
    case F.NDot{} _:
      match g:
    case F.NFrac{} _:
      match g:
    case F.NE{} _:
      match g:
    case F.NESign{} _:
      match g:
    case F.NExp{} _:
      match g:
    case F.T1{} _:
      match g:
    case F.T2{} _:
      match g:
    case F.T3{} _:
      match g:
    case F.F1{} _:
      match g:
    case F.F2{} _:
      match g:
    case F.F3{} _:
      match g:
    case F.F4{} _:
      match g:
    case F.U1{} _:
      match g:
    case F.U2{} _:
      match g:
    case F.U3{} _:
      match g:
    case F.BCtrl{} _:
      match g:
    case F.BUni{} _:
      match g:
    case F.BLone{} _:
      match g:
    case F.BEsc{} _:
      match g:

law v_arr0:
  for +m: F.Mode
  for g: ValM(m)
  for +x: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  {F.gc(SCon{'[', SCon{']', x}}, m, SCon{'[', SCon{']', x}}, stk, out, 0, 0, key, at, ea) == F.gc(x, F.VAfter{}, x, stk, SCon{']', SCon{'[', out}}, 0, 0, key, ((at + 1 : U32) + 1 : U32), ea) : F.Out}

def v_arr0(m, g, x, stk, out, key, at, ea):
  match m stk:
    case F.VStart{} Nil{}:
      {==}
    case F.VStart{} Con{F.BArr{}, up}:
      {==}
    case F.VStart{} Con{F.BObj{}, up}:
      {==}
    case F.VTop{} Nil{}:
      {==}
    case F.VTop{} Con{F.BArr{}, up}:
      {==}
    case F.VTop{} Con{F.BObj{}, up}:
      {==}
    case F.VFirst{} Nil{}:
      {==}
    case F.VFirst{} Con{F.BArr{}, up}:
      {==}
    case F.VFirst{} Con{F.BObj{}, up}:
      {==}
    case F.VItem{} Nil{}:
      {==}
    case F.VItem{} Con{F.BArr{}, up}:
      {==}
    case F.VItem{} Con{F.BObj{}, up}:
      {==}
    case F.VObjFirst{} _:
      match g:
    case F.VKey{} _:
      match g:
    case F.VColon{} _:
      match g:
    case F.VObjVal{} Nil{}:
      {==}
    case F.VObjVal{} Con{F.BArr{}, up}:
      {==}
    case F.VObjVal{} Con{F.BObj{}, up}:
      {==}
    case F.VAfter{} _:
      match g:
    case F.SStr{} _:
      match g:
    case F.SEsc{} _:
      match g:
    case F.SU4{} _:
      match g:
    case F.SU3{} _:
      match g:
    case F.SU2{} _:
      match g:
    case F.SU1{} _:
      match g:
    case F.SHi{} _:
      match g:
    case F.SHiU{} _:
      match g:
    case F.NMin{} _:
      match g:
    case F.NZero{} _:
      match g:
    case F.NInt{} _:
      match g:
    case F.NDot{} _:
      match g:
    case F.NFrac{} _:
      match g:
    case F.NE{} _:
      match g:
    case F.NESign{} _:
      match g:
    case F.NExp{} _:
      match g:
    case F.T1{} _:
      match g:
    case F.T2{} _:
      match g:
    case F.T3{} _:
      match g:
    case F.F1{} _:
      match g:
    case F.F2{} _:
      match g:
    case F.F3{} _:
      match g:
    case F.F4{} _:
      match g:
    case F.U1{} _:
      match g:
    case F.U2{} _:
      match g:
    case F.U3{} _:
      match g:
    case F.BCtrl{} _:
      match g:
    case F.BUni{} _:
      match g:
    case F.BLone{} _:
      match g:
    case F.BEsc{} _:
      match g:

law v_obj0:
  for +m: F.Mode
  for g: ValM(m)
  for +x: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  {F.gc(SCon{'{', SCon{'}', x}}, m, SCon{'{', SCon{'}', x}}, stk, out, 0, 0, key, at, ea) == F.gc(x, F.VAfter{}, x, stk, SCon{'}', SCon{'{', out}}, 0, 0, key, ((at + 1 : U32) + 1 : U32), ea) : F.Out}

def v_obj0(m, g, x, stk, out, key, at, ea):
  match m stk:
    case F.VStart{} Nil{}:
      {==}
    case F.VStart{} Con{F.BArr{}, up}:
      {==}
    case F.VStart{} Con{F.BObj{}, up}:
      {==}
    case F.VTop{} Nil{}:
      {==}
    case F.VTop{} Con{F.BArr{}, up}:
      {==}
    case F.VTop{} Con{F.BObj{}, up}:
      {==}
    case F.VFirst{} Nil{}:
      {==}
    case F.VFirst{} Con{F.BArr{}, up}:
      {==}
    case F.VFirst{} Con{F.BObj{}, up}:
      {==}
    case F.VItem{} Nil{}:
      {==}
    case F.VItem{} Con{F.BArr{}, up}:
      {==}
    case F.VItem{} Con{F.BObj{}, up}:
      {==}
    case F.VObjFirst{} _:
      match g:
    case F.VKey{} _:
      match g:
    case F.VColon{} _:
      match g:
    case F.VObjVal{} Nil{}:
      {==}
    case F.VObjVal{} Con{F.BArr{}, up}:
      {==}
    case F.VObjVal{} Con{F.BObj{}, up}:
      {==}
    case F.VAfter{} _:
      match g:
    case F.SStr{} _:
      match g:
    case F.SEsc{} _:
      match g:
    case F.SU4{} _:
      match g:
    case F.SU3{} _:
      match g:
    case F.SU2{} _:
      match g:
    case F.SU1{} _:
      match g:
    case F.SHi{} _:
      match g:
    case F.SHiU{} _:
      match g:
    case F.NMin{} _:
      match g:
    case F.NZero{} _:
      match g:
    case F.NInt{} _:
      match g:
    case F.NDot{} _:
      match g:
    case F.NFrac{} _:
      match g:
    case F.NE{} _:
      match g:
    case F.NESign{} _:
      match g:
    case F.NExp{} _:
      match g:
    case F.T1{} _:
      match g:
    case F.T2{} _:
      match g:
    case F.T3{} _:
      match g:
    case F.F1{} _:
      match g:
    case F.F2{} _:
      match g:
    case F.F3{} _:
      match g:
    case F.F4{} _:
      match g:
    case F.U1{} _:
      match g:
    case F.U2{} _:
      match g:
    case F.U3{} _:
      match g:
    case F.BCtrl{} _:
      match g:
    case F.BUni{} _:
      match g:
    case F.BLone{} _:
      match g:
    case F.BEsc{} _:
      match g:

law a_close:
  for +m: F.Mode
  for g: Aft(m)
  for +x: String
  for +up: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  {F.gc(SCon{']', x}, m, SCon{']', x}, Con{F.BArr{}, up}, out, 0, 0, key, at, ea) == F.gc(x, F.VAfter{}, x, up, SCon{']', out}, 0, 0, key, (at + 1 : U32), ea) : F.Out}

def a_close(m, g, x, up, out, key, at, ea):
  match m:
    case F.VStart{}:
      match g:
    case F.VTop{}:
      match g:
    case F.VFirst{}:
      match g:
    case F.VItem{}:
      match g:
    case F.VObjFirst{}:
      match g:
    case F.VKey{}:
      match g:
    case F.VColon{}:
      match g:
    case F.VObjVal{}:
      match g:
    case F.VAfter{}:
      {==}
    case F.SStr{}:
      match g:
    case F.SEsc{}:
      match g:
    case F.SU4{}:
      match g:
    case F.SU3{}:
      match g:
    case F.SU2{}:
      match g:
    case F.SU1{}:
      match g:
    case F.SHi{}:
      match g:
    case F.SHiU{}:
      match g:
    case F.NMin{}:
      match g:
    case F.NZero{}:
      {==}
    case F.NInt{}:
      {==}
    case F.NDot{}:
      match g:
    case F.NFrac{}:
      {==}
    case F.NE{}:
      match g:
    case F.NESign{}:
      match g:
    case F.NExp{}:
      {==}
    case F.T1{}:
      match g:
    case F.T2{}:
      match g:
    case F.T3{}:
      match g:
    case F.F1{}:
      match g:
    case F.F2{}:
      match g:
    case F.F3{}:
      match g:
    case F.F4{}:
      match g:
    case F.U1{}:
      match g:
    case F.U2{}:
      match g:
    case F.U3{}:
      match g:
    case F.BCtrl{}:
      match g:
    case F.BUni{}:
      match g:
    case F.BLone{}:
      match g:
    case F.BEsc{}:
      match g:

law o_close:
  for +m: F.Mode
  for g: Aft(m)
  for +x: String
  for +up: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  {F.gc(SCon{'}', x}, m, SCon{'}', x}, Con{F.BObj{}, up}, out, 0, 0, key, at, ea) == F.gc(x, F.VAfter{}, x, up, SCon{'}', out}, 0, 0, key, (at + 1 : U32), ea) : F.Out}

def o_close(m, g, x, up, out, key, at, ea):
  match m:
    case F.VStart{}:
      match g:
    case F.VTop{}:
      match g:
    case F.VFirst{}:
      match g:
    case F.VItem{}:
      match g:
    case F.VObjFirst{}:
      match g:
    case F.VKey{}:
      match g:
    case F.VColon{}:
      match g:
    case F.VObjVal{}:
      match g:
    case F.VAfter{}:
      {==}
    case F.SStr{}:
      match g:
    case F.SEsc{}:
      match g:
    case F.SU4{}:
      match g:
    case F.SU3{}:
      match g:
    case F.SU2{}:
      match g:
    case F.SU1{}:
      match g:
    case F.SHi{}:
      match g:
    case F.SHiU{}:
      match g:
    case F.NMin{}:
      match g:
    case F.NZero{}:
      {==}
    case F.NInt{}:
      {==}
    case F.NDot{}:
      match g:
    case F.NFrac{}:
      {==}
    case F.NE{}:
      match g:
    case F.NESign{}:
      match g:
    case F.NExp{}:
      {==}
    case F.T1{}:
      match g:
    case F.T2{}:
      match g:
    case F.T3{}:
      match g:
    case F.F1{}:
      match g:
    case F.F2{}:
      match g:
    case F.F3{}:
      match g:
    case F.F4{}:
      match g:
    case F.U1{}:
      match g:
    case F.U2{}:
      match g:
    case F.U3{}:
      match g:
    case F.BCtrl{}:
      match g:
    case F.BUni{}:
      match g:
    case F.BLone{}:
      match g:
    case F.BEsc{}:
      match g:

law a_comma:
  for +m: F.Mode
  for g: Aft(m)
  for +x: String
  for +up: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  {F.gc(SCon{',', x}, m, SCon{',', x}, Con{F.BArr{}, up}, out, 0, 0, key, at, ea) == F.gc(x, F.VItem{}, x, Con{F.BArr{}, up}, SCon{',', out}, 0, 0, key, (at + 1 : U32), ea) : F.Out}

def a_comma(m, g, x, up, out, key, at, ea):
  match m:
    case F.VStart{}:
      match g:
    case F.VTop{}:
      match g:
    case F.VFirst{}:
      match g:
    case F.VItem{}:
      match g:
    case F.VObjFirst{}:
      match g:
    case F.VKey{}:
      match g:
    case F.VColon{}:
      match g:
    case F.VObjVal{}:
      match g:
    case F.VAfter{}:
      {==}
    case F.SStr{}:
      match g:
    case F.SEsc{}:
      match g:
    case F.SU4{}:
      match g:
    case F.SU3{}:
      match g:
    case F.SU2{}:
      match g:
    case F.SU1{}:
      match g:
    case F.SHi{}:
      match g:
    case F.SHiU{}:
      match g:
    case F.NMin{}:
      match g:
    case F.NZero{}:
      {==}
    case F.NInt{}:
      {==}
    case F.NDot{}:
      match g:
    case F.NFrac{}:
      {==}
    case F.NE{}:
      match g:
    case F.NESign{}:
      match g:
    case F.NExp{}:
      {==}
    case F.T1{}:
      match g:
    case F.T2{}:
      match g:
    case F.T3{}:
      match g:
    case F.F1{}:
      match g:
    case F.F2{}:
      match g:
    case F.F3{}:
      match g:
    case F.F4{}:
      match g:
    case F.U1{}:
      match g:
    case F.U2{}:
      match g:
    case F.U3{}:
      match g:
    case F.BCtrl{}:
      match g:
    case F.BUni{}:
      match g:
    case F.BLone{}:
      match g:
    case F.BEsc{}:
      match g:

law o_comma:
  for +m: F.Mode
  for g: Aft(m)
  for +x: String
  for +up: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  {F.gc(SCon{',', x}, m, SCon{',', x}, Con{F.BObj{}, up}, out, 0, 0, key, at, ea) == F.gc(x, F.VKey{}, x, Con{F.BObj{}, up}, SCon{',', out}, 0, 0, key, (at + 1 : U32), ea) : F.Out}

def o_comma(m, g, x, up, out, key, at, ea):
  match m:
    case F.VStart{}:
      match g:
    case F.VTop{}:
      match g:
    case F.VFirst{}:
      match g:
    case F.VItem{}:
      match g:
    case F.VObjFirst{}:
      match g:
    case F.VKey{}:
      match g:
    case F.VColon{}:
      match g:
    case F.VObjVal{}:
      match g:
    case F.VAfter{}:
      {==}
    case F.SStr{}:
      match g:
    case F.SEsc{}:
      match g:
    case F.SU4{}:
      match g:
    case F.SU3{}:
      match g:
    case F.SU2{}:
      match g:
    case F.SU1{}:
      match g:
    case F.SHi{}:
      match g:
    case F.SHiU{}:
      match g:
    case F.NMin{}:
      match g:
    case F.NZero{}:
      {==}
    case F.NInt{}:
      {==}
    case F.NDot{}:
      match g:
    case F.NFrac{}:
      {==}
    case F.NE{}:
      match g:
    case F.NESign{}:
      match g:
    case F.NExp{}:
      {==}
    case F.T1{}:
      match g:
    case F.T2{}:
      match g:
    case F.T3{}:
      match g:
    case F.F1{}:
      match g:
    case F.F2{}:
      match g:
    case F.F3{}:
      match g:
    case F.F4{}:
      match g:
    case F.U1{}:
      match g:
    case F.U2{}:
      match g:
    case F.U3{}:
      match g:
    case F.BCtrl{}:
      match g:
    case F.BUni{}:
      match g:
    case F.BLone{}:
      match g:
    case F.BEsc{}:
      match g:

def Ctx(+more: Bool, +j: J.Json, +m: F.Mode, +stk: List<&2, F.Box>) -> Type:
  match more:
    case False{}:
      ValM(m)
    case True{}:
      match j:
        case J.JArr{_}:
          match stk:
            case Con{F.BArr{}, _}:
              Aft(m)
            case _:
              Empty
        case J.JObj{_}:
          match stk:
            case Con{F.BObj{}, _}:
              Aft(m)
            case _:
              Empty
        case _:
          Empty

def popd(+more: Bool, +stk: List<&2, F.Box>) -> List<&2, F.Box>:
  match more:
    case False{}:
      stk
    case True{}:
      match stk:
        case Con{_, up}:
          up
        case Nil{}:
          []

def Goal(+j: J.Json, +more: Bool, +m: F.Mode, +stk: List<&2, F.Box>, +r: String, +out: String, +key: Bool, +at: U32, +ea: U32) -> Type:
  V(S.text(j, more, r), m, stk, out, key, at, ea, r, popd(more, stk), push(S.text(j, more, ""), out))

# a value, then more text y: its output then y's is its text before y
law out_seq:
  for +h: J.Json
  for +y: String
  for +o: String
  {push(y, push(S.text(h, False{}, ""), o)) == push(S.text(h, False{}, y), o) : String}

def out_seq(h, y, o):
  Equal.trans(String, push(y, push(S.text(h, False{}, ""), o)), push(S.text(h, False{}, "") ++ y, o), push(S.text(h, False{}, y), o),
    Equal.sym(String, push(S.text(h, False{}, "") ++ y, o), push(y, push(S.text(h, False{}, ""), o)), T.push_app(S.text(h, False{}, ""), y, o)),
    Equal.cong(String, String, z => push(z, o), S.text(h, False{}, "") ++ y, S.text(h, False{}, y),
      Equal.sym(String, S.text(h, False{}, y), S.text(h, False{}, "") ++ y, T.text(h, False{}, "", y))))

# a key's output, then the value's, is the key's text before the value
law out_key:
  for +k: String
  for +tv: String
  for +o: String
  {push(tv, SCon{':', push(S.esc(k, "\""), o)}) == push(S.esc(k, SCon{'"', SCon{':', tv}}), o) : String}

def out_key(k, tv, o):
  Equal.trans(String, push(tv, SCon{':', push(S.esc(k, "\""), o)}), push(S.esc(k, "\"") ++ SCon{':', tv}, o), push(S.esc(k, SCon{'"', SCon{':', tv}}), o),
    Equal.sym(String, push(S.esc(k, "\"") ++ SCon{':', tv}, o), push(SCon{':', tv}, push(S.esc(k, "\""), o)), T.push_app(S.esc(k, "\""), SCon{':', tv}, o)),
    Equal.cong(String, String, z => push(z, o), S.esc(k, "\"") ++ SCon{':', tv}, S.esc(k, SCon{'"', SCon{':', tv}}),
      Equal.sym(String, S.esc(k, SCon{'"', SCon{':', tv}}), S.esc(k, "\"") ++ SCon{':', tv}, T.esc(k, "\"", SCon{':', tv}))))

# a string value
law str_v.k:
  for +s: String
  for +m: F.Mode
  for +r: String
  for +stk: List<&2, F.Box>
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  for s1: {F.gc(SCon{'"', S.esc(s, SCon{'"', r})}, m, SCon{'"', S.esc(s, SCon{'"', r})}, stk, out, 0, 0, key, at, ea) == F.gc(S.esc(s, SCon{'"', r}), F.SStr{}, S.esc(s, SCon{'"', r}), stk, SCon{'"', out}, 0, 0, False{}, (at + 1 : U32), ea) : F.Out}
  for g: FS.SB(s, r, stk, SCon{'"', out}, False{}, (at + 1 : U32), ea)
  Goal(J.JStr{s}, False{}, m, stk, r, out, key, at, ea)

def str_v.k(s, m, r, stk, out, key, at, ea, s1, g):
  (+p, e2) = g
  (Q{F.VAfter{}, False{}, FS.p_at(p), FS.p_ea(p)}, (Unit{}, Equal.trans(F.Out, F.gc(SCon{'"', S.esc(s, SCon{'"', r})}, m, SCon{'"', S.esc(s, SCon{'"', r})}, stk, out, 0, 0, key, at, ea), F.gc(S.esc(s, SCon{'"', r}), F.SStr{}, S.esc(s, SCon{'"', r}), stk, SCon{'"', out}, 0, 0, False{}, (at + 1 : U32), ea),
    F.gc(r, F.VAfter{}, r, stk, push(S.esc(s, "\""), SCon{'"', out}), 0, 0, False{}, FS.p_at(p), FS.p_ea(p)), s1, e2)))

law arr.f.k3:
  for +h: J.Json
  for +t: List<&2, J.Json>
  for +stk: List<&2, F.Box>
  for +m: F.Mode
  for +r: String
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  for pre: {F.gc(SCon{'[', S.text(h, False{}, S.text(J.JArr{t}, True{}, r))}, m, SCon{'[', S.text(h, False{}, S.text(J.JArr{t}, True{}, r))}, stk, out, 0, 0, key, at, ea) == F.gc(S.text(h, False{}, S.text(J.JArr{t}, True{}, r)), F.VFirst{}, S.text(h, False{}, S.text(J.JArr{t}, True{}, r)), Con{F.BArr{}, stk}, SCon{'[', out}, 0, 0, key, (at + 1 : U32), ea) : F.Out}
  for +m1: F.Mode
  for +k1: Bool
  for +a1: U32
  for +e1: U32
  for eq1: {F.gc(S.text(h, False{}, S.text(J.JArr{t}, True{}, r)), F.VFirst{}, S.text(h, False{}, S.text(J.JArr{t}, True{}, r)), Con{F.BArr{}, stk}, SCon{'[', out}, 0, 0, key, (at + 1 : U32), ea) == after(S.text(J.JArr{t}, True{}, r), Con{F.BArr{}, stk}, push(S.text(h, False{}, ""), SCon{'[', out}), Q{m1, k1, a1, e1}) : F.Out}
  for g2: Goal(J.JArr{t}, True{}, m1, Con{F.BArr{}, stk}, r, push(S.text(h, False{}, ""), SCon{'[', out}), k1, a1, e1)
  Goal(J.JArr{Con{h, t}}, False{}, m, stk, r, out, key, at, ea)

def arr.f.k3(h, t, stk, m, r, out, key, at, ea, pre, m1, k1, a1, e1, eq1, g2):
  (+q2, pr2) = g2
  (aft2, eq2) = pr2
  (q2, (aft2, Equal.trans(F.Out,
        F.gc(SCon{'[', S.text(h, False{}, S.text(J.JArr{t}, True{}, r))}, m, SCon{'[', S.text(h, False{}, S.text(J.JArr{t}, True{}, r))}, stk, out, 0, 0, key, at, ea),
        F.gc(S.text(h, False{}, S.text(J.JArr{t}, True{}, r)), F.VFirst{}, S.text(h, False{}, S.text(J.JArr{t}, True{}, r)), Con{F.BArr{}, stk}, SCon{'[', out}, 0, 0, key, (at + 1 : U32), ea),
        after(r, stk, push(S.text(J.JArr{Con{h, t}}, False{}, ""), out), q2),
        pre,
        Equal.trans(F.Out,
          F.gc(S.text(h, False{}, S.text(J.JArr{t}, True{}, r)), F.VFirst{}, S.text(h, False{}, S.text(J.JArr{t}, True{}, r)), Con{F.BArr{}, stk}, SCon{'[', out}, 0, 0, key, (at + 1 : U32), ea),
          after(S.text(J.JArr{t}, True{}, r), Con{F.BArr{}, stk}, push(S.text(h, False{}, ""), SCon{'[', out}), Q{m1, k1, a1, e1}),
          after(r, stk, push(S.text(J.JArr{Con{h, t}}, False{}, ""), out), q2),
          eq1,
          Equal.trans(F.Out,
            after(S.text(J.JArr{t}, True{}, r), Con{F.BArr{}, stk}, push(S.text(h, False{}, ""), SCon{'[', out}), Q{m1, k1, a1, e1}),
            after(r, stk, push(S.text(J.JArr{t}, True{}, ""), push(S.text(h, False{}, ""), SCon{'[', out})), q2),
            after(r, stk, push(S.text(J.JArr{Con{h, t}}, False{}, ""), out), q2),
            eq2,
            Equal.cong(String, F.Out, z => after(r, stk, z, q2), push(S.text(J.JArr{t}, True{}, ""), push(S.text(h, False{}, ""), SCon{'[', out})), push(S.text(J.JArr{Con{h, t}}, False{}, ""), out), out_seq(h, S.text(J.JArr{t}, True{}, ""), SCon{'[', out})))))))

law arr.f.k2:
  for +h: J.Json
  for +t: List<&2, J.Json>
  for +stk: List<&2, F.Box>
  for +m: F.Mode
  for +r: String
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  for pre: {F.gc(SCon{'[', S.text(h, False{}, S.text(J.JArr{t}, True{}, r))}, m, SCon{'[', S.text(h, False{}, S.text(J.JArr{t}, True{}, r))}, stk, out, 0, 0, key, at, ea) == F.gc(S.text(h, False{}, S.text(J.JArr{t}, True{}, r)), F.VFirst{}, S.text(h, False{}, S.text(J.JArr{t}, True{}, r)), Con{F.BArr{}, stk}, SCon{'[', out}, 0, 0, key, (at + 1 : U32), ea) : F.Out}
  for +q1: Q
  for aft1: AftQ(q1)
  for eq1: {F.gc(S.text(h, False{}, S.text(J.JArr{t}, True{}, r)), F.VFirst{}, S.text(h, False{}, S.text(J.JArr{t}, True{}, r)), Con{F.BArr{}, stk}, SCon{'[', out}, 0, 0, key, (at + 1 : U32), ea) == after(S.text(J.JArr{t}, True{}, r), Con{F.BArr{}, stk}, push(S.text(h, False{}, ""), SCon{'[', out}), q1) : F.Out}
  for ih2: @m2: F.Mode -> @k2: Bool -> @a2: U32 -> @e2: U32 -> @aft: Aft(m2) -> Goal(J.JArr{t}, True{}, m2, Con{F.BArr{}, stk}, r, push(S.text(h, False{}, ""), SCon{'[', out}), k2, a2, e2)
  Goal(J.JArr{Con{h, t}}, False{}, m, stk, r, out, key, at, ea)

def arr.f.k2(h, t, stk, m, r, out, key, at, ea, pre, q1, aft1, eq1, ih2):
  match q1:
    case Q{m1, k1, a1, e1}:
      arr.f.k3(h, t, stk, m, r, out, key, at, ea, pre, m1, k1, a1, e1, eq1, ih2(m1, k1, a1, e1, aft1))

law arr.f.k1:
  for +h: J.Json
  for +t: List<&2, J.Json>
  for +stk: List<&2, F.Box>
  for +m: F.Mode
  for +r: String
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  for pre: {F.gc(SCon{'[', S.text(h, False{}, S.text(J.JArr{t}, True{}, r))}, m, SCon{'[', S.text(h, False{}, S.text(J.JArr{t}, True{}, r))}, stk, out, 0, 0, key, at, ea) == F.gc(S.text(h, False{}, S.text(J.JArr{t}, True{}, r)), F.VFirst{}, S.text(h, False{}, S.text(J.JArr{t}, True{}, r)), Con{F.BArr{}, stk}, SCon{'[', out}, 0, 0, key, (at + 1 : U32), ea) : F.Out}
  for g1: Goal(h, False{}, F.VFirst{}, Con{F.BArr{}, stk}, S.text(J.JArr{t}, True{}, r), SCon{'[', out}, key, (at + 1 : U32), ea)
  for ih2: @m2: F.Mode -> @k2: Bool -> @a2: U32 -> @e2: U32 -> @aft: Aft(m2) -> Goal(J.JArr{t}, True{}, m2, Con{F.BArr{}, stk}, r, push(S.text(h, False{}, ""), SCon{'[', out}), k2, a2, e2)
  Goal(J.JArr{Con{h, t}}, False{}, m, stk, r, out, key, at, ea)

def arr.f.k1(h, t, stk, m, r, out, key, at, ea, pre, g1, ih2):
  (+q1, pr1) = g1
  (aft1, eq1) = pr1
  arr.f.k2(h, t, stk, m, r, out, key, at, ea, pre, q1, aft1, eq1, ih2)

law arr.t.k3:
  for +h: J.Json
  for +t: List<&2, J.Json>
  for +up: List<&2, F.Box>
  for +m: F.Mode
  for +r: String
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  for pre: {F.gc(SCon{',', S.text(h, False{}, S.text(J.JArr{t}, True{}, r))}, m, SCon{',', S.text(h, False{}, S.text(J.JArr{t}, True{}, r))}, Con{F.BArr{}, up}, out, 0, 0, key, at, ea) == F.gc(S.text(h, False{}, S.text(J.JArr{t}, True{}, r)), F.VItem{}, S.text(h, False{}, S.text(J.JArr{t}, True{}, r)), Con{F.BArr{}, up}, SCon{',', out}, 0, 0, key, (at + 1 : U32), ea) : F.Out}
  for +m1: F.Mode
  for +k1: Bool
  for +a1: U32
  for +e1: U32
  for eq1: {F.gc(S.text(h, False{}, S.text(J.JArr{t}, True{}, r)), F.VItem{}, S.text(h, False{}, S.text(J.JArr{t}, True{}, r)), Con{F.BArr{}, up}, SCon{',', out}, 0, 0, key, (at + 1 : U32), ea) == after(S.text(J.JArr{t}, True{}, r), Con{F.BArr{}, up}, push(S.text(h, False{}, ""), SCon{',', out}), Q{m1, k1, a1, e1}) : F.Out}
  for g2: Goal(J.JArr{t}, True{}, m1, Con{F.BArr{}, up}, r, push(S.text(h, False{}, ""), SCon{',', out}), k1, a1, e1)
  Goal(J.JArr{Con{h, t}}, True{}, m, Con{F.BArr{}, up}, r, out, key, at, ea)

def arr.t.k3(h, t, up, m, r, out, key, at, ea, pre, m1, k1, a1, e1, eq1, g2):
  (+q2, pr2) = g2
  (aft2, eq2) = pr2
  (q2, (aft2, Equal.trans(F.Out,
        F.gc(SCon{',', S.text(h, False{}, S.text(J.JArr{t}, True{}, r))}, m, SCon{',', S.text(h, False{}, S.text(J.JArr{t}, True{}, r))}, Con{F.BArr{}, up}, out, 0, 0, key, at, ea),
        F.gc(S.text(h, False{}, S.text(J.JArr{t}, True{}, r)), F.VItem{}, S.text(h, False{}, S.text(J.JArr{t}, True{}, r)), Con{F.BArr{}, up}, SCon{',', out}, 0, 0, key, (at + 1 : U32), ea),
        after(r, up, push(S.text(J.JArr{Con{h, t}}, True{}, ""), out), q2),
        pre,
        Equal.trans(F.Out,
          F.gc(S.text(h, False{}, S.text(J.JArr{t}, True{}, r)), F.VItem{}, S.text(h, False{}, S.text(J.JArr{t}, True{}, r)), Con{F.BArr{}, up}, SCon{',', out}, 0, 0, key, (at + 1 : U32), ea),
          after(S.text(J.JArr{t}, True{}, r), Con{F.BArr{}, up}, push(S.text(h, False{}, ""), SCon{',', out}), Q{m1, k1, a1, e1}),
          after(r, up, push(S.text(J.JArr{Con{h, t}}, True{}, ""), out), q2),
          eq1,
          Equal.trans(F.Out,
            after(S.text(J.JArr{t}, True{}, r), Con{F.BArr{}, up}, push(S.text(h, False{}, ""), SCon{',', out}), Q{m1, k1, a1, e1}),
            after(r, up, push(S.text(J.JArr{t}, True{}, ""), push(S.text(h, False{}, ""), SCon{',', out})), q2),
            after(r, up, push(S.text(J.JArr{Con{h, t}}, True{}, ""), out), q2),
            eq2,
            Equal.cong(String, F.Out, z => after(r, up, z, q2), push(S.text(J.JArr{t}, True{}, ""), push(S.text(h, False{}, ""), SCon{',', out})), push(S.text(J.JArr{Con{h, t}}, True{}, ""), out), out_seq(h, S.text(J.JArr{t}, True{}, ""), SCon{',', out})))))))

law arr.t.k2:
  for +h: J.Json
  for +t: List<&2, J.Json>
  for +up: List<&2, F.Box>
  for +m: F.Mode
  for +r: String
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  for pre: {F.gc(SCon{',', S.text(h, False{}, S.text(J.JArr{t}, True{}, r))}, m, SCon{',', S.text(h, False{}, S.text(J.JArr{t}, True{}, r))}, Con{F.BArr{}, up}, out, 0, 0, key, at, ea) == F.gc(S.text(h, False{}, S.text(J.JArr{t}, True{}, r)), F.VItem{}, S.text(h, False{}, S.text(J.JArr{t}, True{}, r)), Con{F.BArr{}, up}, SCon{',', out}, 0, 0, key, (at + 1 : U32), ea) : F.Out}
  for +q1: Q
  for aft1: AftQ(q1)
  for eq1: {F.gc(S.text(h, False{}, S.text(J.JArr{t}, True{}, r)), F.VItem{}, S.text(h, False{}, S.text(J.JArr{t}, True{}, r)), Con{F.BArr{}, up}, SCon{',', out}, 0, 0, key, (at + 1 : U32), ea) == after(S.text(J.JArr{t}, True{}, r), Con{F.BArr{}, up}, push(S.text(h, False{}, ""), SCon{',', out}), q1) : F.Out}
  for ih2: @m2: F.Mode -> @k2: Bool -> @a2: U32 -> @e2: U32 -> @aft: Aft(m2) -> Goal(J.JArr{t}, True{}, m2, Con{F.BArr{}, up}, r, push(S.text(h, False{}, ""), SCon{',', out}), k2, a2, e2)
  Goal(J.JArr{Con{h, t}}, True{}, m, Con{F.BArr{}, up}, r, out, key, at, ea)

def arr.t.k2(h, t, up, m, r, out, key, at, ea, pre, q1, aft1, eq1, ih2):
  match q1:
    case Q{m1, k1, a1, e1}:
      arr.t.k3(h, t, up, m, r, out, key, at, ea, pre, m1, k1, a1, e1, eq1, ih2(m1, k1, a1, e1, aft1))

law arr.t.k1:
  for +h: J.Json
  for +t: List<&2, J.Json>
  for +up: List<&2, F.Box>
  for +m: F.Mode
  for +r: String
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  for pre: {F.gc(SCon{',', S.text(h, False{}, S.text(J.JArr{t}, True{}, r))}, m, SCon{',', S.text(h, False{}, S.text(J.JArr{t}, True{}, r))}, Con{F.BArr{}, up}, out, 0, 0, key, at, ea) == F.gc(S.text(h, False{}, S.text(J.JArr{t}, True{}, r)), F.VItem{}, S.text(h, False{}, S.text(J.JArr{t}, True{}, r)), Con{F.BArr{}, up}, SCon{',', out}, 0, 0, key, (at + 1 : U32), ea) : F.Out}
  for g1: Goal(h, False{}, F.VItem{}, Con{F.BArr{}, up}, S.text(J.JArr{t}, True{}, r), SCon{',', out}, key, (at + 1 : U32), ea)
  for ih2: @m2: F.Mode -> @k2: Bool -> @a2: U32 -> @e2: U32 -> @aft: Aft(m2) -> Goal(J.JArr{t}, True{}, m2, Con{F.BArr{}, up}, r, push(S.text(h, False{}, ""), SCon{',', out}), k2, a2, e2)
  Goal(J.JArr{Con{h, t}}, True{}, m, Con{F.BArr{}, up}, r, out, key, at, ea)

def arr.t.k1(h, t, up, m, r, out, key, at, ea, pre, g1, ih2):
  (+q1, pr1) = g1
  (aft1, eq1) = pr1
  arr.t.k2(h, t, up, m, r, out, key, at, ea, pre, q1, aft1, eq1, ih2)

law obj.f.k5:
  for +k: String
  for +v: J.Json
  for +t: List<&2, J.Field>
  for +stk: List<&2, F.Box>
  for +m: F.Mode
  for +r: String
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  for +pa: U32
  for +pe: U32
  for pre: {F.gc(SCon{'{', SCon{'"', S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}})}}, m, SCon{'{', SCon{'"', S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}})}}, stk, out, 0, 0, key, at, ea) == F.gc(S.text(v, False{}, S.text(J.JObj{t}, True{}, r)), F.VObjVal{}, S.text(v, False{}, S.text(J.JObj{t}, True{}, r)), Con{F.BObj{}, stk}, SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{'{', out}})}, 0, 0, True{}, (pa + 1 : U32), pe) : F.Out}
  for +m1: F.Mode
  for +k1: Bool
  for +a1: U32
  for +e1: U32
  for eq1: {F.gc(S.text(v, False{}, S.text(J.JObj{t}, True{}, r)), F.VObjVal{}, S.text(v, False{}, S.text(J.JObj{t}, True{}, r)), Con{F.BObj{}, stk}, SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{'{', out}})}, 0, 0, True{}, (pa + 1 : U32), pe) == after(S.text(J.JObj{t}, True{}, r), Con{F.BObj{}, stk}, push(S.text(v, False{}, ""), SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{'{', out}})}), Q{m1, k1, a1, e1}) : F.Out}
  for g2: Goal(J.JObj{t}, True{}, m1, Con{F.BObj{}, stk}, r, push(S.text(v, False{}, ""), SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{'{', out}})}), k1, a1, e1)
  Goal(J.JObj{Con{J.Field{k, v}, t}}, False{}, m, stk, r, out, key, at, ea)

def obj.f.k5(k, v, t, stk, m, r, out, key, at, ea, pa, pe, pre, m1, k1, a1, e1, eq1, g2):
  (+q2, pr2) = g2
  (aft2, eq2) = pr2
  (q2, (aft2, Equal.trans(F.Out,
        F.gc(SCon{'{', SCon{'"', S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}})}}, m, SCon{'{', SCon{'"', S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}})}}, stk, out, 0, 0, key, at, ea),
        F.gc(S.text(v, False{}, S.text(J.JObj{t}, True{}, r)), F.VObjVal{}, S.text(v, False{}, S.text(J.JObj{t}, True{}, r)), Con{F.BObj{}, stk}, SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{'{', out}})}, 0, 0, True{}, (pa + 1 : U32), pe),
        after(r, stk, push(S.text(J.JObj{Con{J.Field{k, v}, t}}, False{}, ""), out), q2),
        pre,
        Equal.trans(F.Out,
          F.gc(S.text(v, False{}, S.text(J.JObj{t}, True{}, r)), F.VObjVal{}, S.text(v, False{}, S.text(J.JObj{t}, True{}, r)), Con{F.BObj{}, stk}, SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{'{', out}})}, 0, 0, True{}, (pa + 1 : U32), pe),
          after(S.text(J.JObj{t}, True{}, r), Con{F.BObj{}, stk}, push(S.text(v, False{}, ""), SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{'{', out}})}), Q{m1, k1, a1, e1}),
          after(r, stk, push(S.text(J.JObj{Con{J.Field{k, v}, t}}, False{}, ""), out), q2),
          eq1,
          Equal.trans(F.Out,
            after(S.text(J.JObj{t}, True{}, r), Con{F.BObj{}, stk}, push(S.text(v, False{}, ""), SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{'{', out}})}), Q{m1, k1, a1, e1}),
            after(r, stk, push(S.text(J.JObj{t}, True{}, ""), push(S.text(v, False{}, ""), SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{'{', out}})})), q2),
            after(r, stk, push(S.text(J.JObj{Con{J.Field{k, v}, t}}, False{}, ""), out), q2),
            eq2,
            Equal.trans(F.Out,
              after(r, stk, push(S.text(J.JObj{t}, True{}, ""), push(S.text(v, False{}, ""), SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{'{', out}})})), q2),
              after(r, stk, push(S.text(v, False{}, S.text(J.JObj{t}, True{}, "")), SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{'{', out}})}), q2),
              after(r, stk, push(S.text(J.JObj{Con{J.Field{k, v}, t}}, False{}, ""), out), q2),
              Equal.cong(String, F.Out, z => after(r, stk, z, q2), push(S.text(J.JObj{t}, True{}, ""), push(S.text(v, False{}, ""), SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{'{', out}})})), push(S.text(v, False{}, S.text(J.JObj{t}, True{}, "")), SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{'{', out}})}), out_seq(v, S.text(J.JObj{t}, True{}, ""), SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{'{', out}})})),
              Equal.cong(String, F.Out, z => after(r, stk, z, q2), push(S.text(v, False{}, S.text(J.JObj{t}, True{}, "")), SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{'{', out}})}), push(S.text(J.JObj{Con{J.Field{k, v}, t}}, False{}, ""), out), out_key(k, S.text(v, False{}, S.text(J.JObj{t}, True{}, "")), SCon{'"', SCon{'{', out}}))))))))

law obj.f.k4:
  for +k: String
  for +v: J.Json
  for +t: List<&2, J.Field>
  for +stk: List<&2, F.Box>
  for +m: F.Mode
  for +r: String
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  for +pa: U32
  for +pe: U32
  for pre: {F.gc(SCon{'{', SCon{'"', S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}})}}, m, SCon{'{', SCon{'"', S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}})}}, stk, out, 0, 0, key, at, ea) == F.gc(S.text(v, False{}, S.text(J.JObj{t}, True{}, r)), F.VObjVal{}, S.text(v, False{}, S.text(J.JObj{t}, True{}, r)), Con{F.BObj{}, stk}, SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{'{', out}})}, 0, 0, True{}, (pa + 1 : U32), pe) : F.Out}
  for +q1: Q
  for aft1: AftQ(q1)
  for eq1: {F.gc(S.text(v, False{}, S.text(J.JObj{t}, True{}, r)), F.VObjVal{}, S.text(v, False{}, S.text(J.JObj{t}, True{}, r)), Con{F.BObj{}, stk}, SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{'{', out}})}, 0, 0, True{}, (pa + 1 : U32), pe) == after(S.text(J.JObj{t}, True{}, r), Con{F.BObj{}, stk}, push(S.text(v, False{}, ""), SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{'{', out}})}), q1) : F.Out}
  for ih2: @m2: F.Mode -> @k2: Bool -> @a2: U32 -> @e2: U32 -> @aft: Aft(m2) -> Goal(J.JObj{t}, True{}, m2, Con{F.BObj{}, stk}, r, push(S.text(v, False{}, ""), SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{'{', out}})}), k2, a2, e2)
  Goal(J.JObj{Con{J.Field{k, v}, t}}, False{}, m, stk, r, out, key, at, ea)

def obj.f.k4(k, v, t, stk, m, r, out, key, at, ea, pa, pe, pre, q1, aft1, eq1, ih2):
  match q1:
    case Q{m1, k1, a1, e1}:
      obj.f.k5(k, v, t, stk, m, r, out, key, at, ea, pa, pe, pre, m1, k1, a1, e1, eq1, ih2(m1, k1, a1, e1, aft1))

law obj.f.k3:
  for +k: String
  for +v: J.Json
  for +t: List<&2, J.Field>
  for +stk: List<&2, F.Box>
  for +m: F.Mode
  for +r: String
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  for +pa: U32
  for +pe: U32
  for pre: {F.gc(SCon{'{', SCon{'"', S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}})}}, m, SCon{'{', SCon{'"', S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}})}}, stk, out, 0, 0, key, at, ea) == F.gc(S.text(v, False{}, S.text(J.JObj{t}, True{}, r)), F.VObjVal{}, S.text(v, False{}, S.text(J.JObj{t}, True{}, r)), Con{F.BObj{}, stk}, SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{'{', out}})}, 0, 0, True{}, (pa + 1 : U32), pe) : F.Out}
  for g1: Goal(v, False{}, F.VObjVal{}, Con{F.BObj{}, stk}, S.text(J.JObj{t}, True{}, r), SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{'{', out}})}, True{}, (pa + 1 : U32), pe)
  for ih2: @m2: F.Mode -> @k2: Bool -> @a2: U32 -> @e2: U32 -> @aft: Aft(m2) -> Goal(J.JObj{t}, True{}, m2, Con{F.BObj{}, stk}, r, push(S.text(v, False{}, ""), SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{'{', out}})}), k2, a2, e2)
  Goal(J.JObj{Con{J.Field{k, v}, t}}, False{}, m, stk, r, out, key, at, ea)

def obj.f.k3(k, v, t, stk, m, r, out, key, at, ea, pa, pe, pre, g1, ih2):
  (+q1, pr1) = g1
  (aft1, eq1) = pr1
  obj.f.k4(k, v, t, stk, m, r, out, key, at, ea, pa, pe, pre, q1, aft1, eq1, ih2)

law obj.f.k2:
  for +k: String
  for +v: J.Json
  for +t: List<&2, J.Field>
  for +stk: List<&2, F.Box>
  for +m: F.Mode
  for +r: String
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  for pre: {F.gc(SCon{'{', SCon{'"', S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}})}}, m, SCon{'{', SCon{'"', S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}})}}, stk, out, 0, 0, key, at, ea) == F.gc(S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}}), F.SStr{}, S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}}), Con{F.BObj{}, stk}, SCon{'"', SCon{'{', out}}, 0, 0, True{}, ((at + 1 : U32) + 1 : U32), ea) : F.Out}
  for +pa: U32
  for +pe: U32
  for eqk: {F.gc(S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}}), F.SStr{}, S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}}), Con{F.BObj{}, stk}, SCon{'"', SCon{'{', out}}, 0, 0, True{}, ((at + 1 : U32) + 1 : U32), ea) == F.gc(SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}, F.VColon{}, SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}, Con{F.BObj{}, stk}, push(S.esc(k, "\""), SCon{'"', SCon{'{', out}}), 0, 0, True{}, pa, pe) : F.Out}
  for ih1: @pa2: U32 -> @pe2: U32 -> Goal(v, False{}, F.VObjVal{}, Con{F.BObj{}, stk}, S.text(J.JObj{t}, True{}, r), SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{'{', out}})}, True{}, (pa2 + 1 : U32), pe2)
  for ih2: @m2: F.Mode -> @k2: Bool -> @a2: U32 -> @e2: U32 -> @aft: Aft(m2) -> Goal(J.JObj{t}, True{}, m2, Con{F.BObj{}, stk}, r, push(S.text(v, False{}, ""), SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{'{', out}})}), k2, a2, e2)
  Goal(J.JObj{Con{J.Field{k, v}, t}}, False{}, m, stk, r, out, key, at, ea)

def obj.f.k2(k, v, t, stk, m, r, out, key, at, ea, pre, pa, pe, eqk, ih1, ih2):
  obj.f.k3(k, v, t, stk, m, r, out, key, at, ea, pa, pe, Equal.trans(F.Out,
      F.gc(SCon{'{', SCon{'"', S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}})}}, m, SCon{'{', SCon{'"', S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}})}}, stk, out, 0, 0, key, at, ea),
      F.gc(S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}}), F.SStr{}, S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}}), Con{F.BObj{}, stk}, SCon{'"', SCon{'{', out}}, 0, 0, True{}, ((at + 1 : U32) + 1 : U32), ea),
      F.gc(S.text(v, False{}, S.text(J.JObj{t}, True{}, r)), F.VObjVal{}, S.text(v, False{}, S.text(J.JObj{t}, True{}, r)), Con{F.BObj{}, stk}, SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{'{', out}})}, 0, 0, True{}, (pa + 1 : U32), pe),
      pre,
      Equal.trans(F.Out,
        F.gc(S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}}), F.SStr{}, S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}}), Con{F.BObj{}, stk}, SCon{'"', SCon{'{', out}}, 0, 0, True{}, ((at + 1 : U32) + 1 : U32), ea),
        F.gc(SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}, F.VColon{}, SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}, Con{F.BObj{}, stk}, push(S.esc(k, "\""), SCon{'"', SCon{'{', out}}), 0, 0, True{}, pa, pe),
        F.gc(S.text(v, False{}, S.text(J.JObj{t}, True{}, r)), F.VObjVal{}, S.text(v, False{}, S.text(J.JObj{t}, True{}, r)), Con{F.BObj{}, stk}, SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{'{', out}})}, 0, 0, True{}, (pa + 1 : U32), pe),
        eqk,
        {==})),
    ih1(pa, pe), ih2)

law obj.f.k1:
  for +k: String
  for +v: J.Json
  for +t: List<&2, J.Field>
  for +stk: List<&2, F.Box>
  for +m: F.Mode
  for +r: String
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  for pre: {F.gc(SCon{'{', SCon{'"', S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}})}}, m, SCon{'{', SCon{'"', S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}})}}, stk, out, 0, 0, key, at, ea) == F.gc(S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}}), F.SStr{}, S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}}), Con{F.BObj{}, stk}, SCon{'"', SCon{'{', out}}, 0, 0, True{}, ((at + 1 : U32) + 1 : U32), ea) : F.Out}
  for gk: FS.SB(k, SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}, Con{F.BObj{}, stk}, SCon{'"', SCon{'{', out}}, True{}, ((at + 1 : U32) + 1 : U32), ea)
  for ih1: @pa2: U32 -> @pe2: U32 -> Goal(v, False{}, F.VObjVal{}, Con{F.BObj{}, stk}, S.text(J.JObj{t}, True{}, r), SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{'{', out}})}, True{}, (pa2 + 1 : U32), pe2)
  for ih2: @m2: F.Mode -> @k2: Bool -> @a2: U32 -> @e2: U32 -> @aft: Aft(m2) -> Goal(J.JObj{t}, True{}, m2, Con{F.BObj{}, stk}, r, push(S.text(v, False{}, ""), SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{'{', out}})}), k2, a2, e2)
  Goal(J.JObj{Con{J.Field{k, v}, t}}, False{}, m, stk, r, out, key, at, ea)

def obj.f.k1(k, v, t, stk, m, r, out, key, at, ea, pre, gk, ih1, ih2):
  (+p, eqk) = gk
  obj.f.k2(k, v, t, stk, m, r, out, key, at, ea, pre, FS.p_at(p), FS.p_ea(p), eqk, ih1, ih2)

law obj.t.k5:
  for +k: String
  for +v: J.Json
  for +t: List<&2, J.Field>
  for +up: List<&2, F.Box>
  for +m: F.Mode
  for +r: String
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  for +pa: U32
  for +pe: U32
  for pre: {F.gc(SCon{',', SCon{'"', S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}})}}, m, SCon{',', SCon{'"', S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}})}}, Con{F.BObj{}, up}, out, 0, 0, key, at, ea) == F.gc(S.text(v, False{}, S.text(J.JObj{t}, True{}, r)), F.VObjVal{}, S.text(v, False{}, S.text(J.JObj{t}, True{}, r)), Con{F.BObj{}, up}, SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{',', out}})}, 0, 0, True{}, (pa + 1 : U32), pe) : F.Out}
  for +m1: F.Mode
  for +k1: Bool
  for +a1: U32
  for +e1: U32
  for eq1: {F.gc(S.text(v, False{}, S.text(J.JObj{t}, True{}, r)), F.VObjVal{}, S.text(v, False{}, S.text(J.JObj{t}, True{}, r)), Con{F.BObj{}, up}, SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{',', out}})}, 0, 0, True{}, (pa + 1 : U32), pe) == after(S.text(J.JObj{t}, True{}, r), Con{F.BObj{}, up}, push(S.text(v, False{}, ""), SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{',', out}})}), Q{m1, k1, a1, e1}) : F.Out}
  for g2: Goal(J.JObj{t}, True{}, m1, Con{F.BObj{}, up}, r, push(S.text(v, False{}, ""), SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{',', out}})}), k1, a1, e1)
  Goal(J.JObj{Con{J.Field{k, v}, t}}, True{}, m, Con{F.BObj{}, up}, r, out, key, at, ea)

def obj.t.k5(k, v, t, up, m, r, out, key, at, ea, pa, pe, pre, m1, k1, a1, e1, eq1, g2):
  (+q2, pr2) = g2
  (aft2, eq2) = pr2
  (q2, (aft2, Equal.trans(F.Out,
        F.gc(SCon{',', SCon{'"', S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}})}}, m, SCon{',', SCon{'"', S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}})}}, Con{F.BObj{}, up}, out, 0, 0, key, at, ea),
        F.gc(S.text(v, False{}, S.text(J.JObj{t}, True{}, r)), F.VObjVal{}, S.text(v, False{}, S.text(J.JObj{t}, True{}, r)), Con{F.BObj{}, up}, SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{',', out}})}, 0, 0, True{}, (pa + 1 : U32), pe),
        after(r, up, push(S.text(J.JObj{Con{J.Field{k, v}, t}}, True{}, ""), out), q2),
        pre,
        Equal.trans(F.Out,
          F.gc(S.text(v, False{}, S.text(J.JObj{t}, True{}, r)), F.VObjVal{}, S.text(v, False{}, S.text(J.JObj{t}, True{}, r)), Con{F.BObj{}, up}, SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{',', out}})}, 0, 0, True{}, (pa + 1 : U32), pe),
          after(S.text(J.JObj{t}, True{}, r), Con{F.BObj{}, up}, push(S.text(v, False{}, ""), SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{',', out}})}), Q{m1, k1, a1, e1}),
          after(r, up, push(S.text(J.JObj{Con{J.Field{k, v}, t}}, True{}, ""), out), q2),
          eq1,
          Equal.trans(F.Out,
            after(S.text(J.JObj{t}, True{}, r), Con{F.BObj{}, up}, push(S.text(v, False{}, ""), SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{',', out}})}), Q{m1, k1, a1, e1}),
            after(r, up, push(S.text(J.JObj{t}, True{}, ""), push(S.text(v, False{}, ""), SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{',', out}})})), q2),
            after(r, up, push(S.text(J.JObj{Con{J.Field{k, v}, t}}, True{}, ""), out), q2),
            eq2,
            Equal.trans(F.Out,
              after(r, up, push(S.text(J.JObj{t}, True{}, ""), push(S.text(v, False{}, ""), SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{',', out}})})), q2),
              after(r, up, push(S.text(v, False{}, S.text(J.JObj{t}, True{}, "")), SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{',', out}})}), q2),
              after(r, up, push(S.text(J.JObj{Con{J.Field{k, v}, t}}, True{}, ""), out), q2),
              Equal.cong(String, F.Out, z => after(r, up, z, q2), push(S.text(J.JObj{t}, True{}, ""), push(S.text(v, False{}, ""), SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{',', out}})})), push(S.text(v, False{}, S.text(J.JObj{t}, True{}, "")), SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{',', out}})}), out_seq(v, S.text(J.JObj{t}, True{}, ""), SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{',', out}})})),
              Equal.cong(String, F.Out, z => after(r, up, z, q2), push(S.text(v, False{}, S.text(J.JObj{t}, True{}, "")), SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{',', out}})}), push(S.text(J.JObj{Con{J.Field{k, v}, t}}, True{}, ""), out), out_key(k, S.text(v, False{}, S.text(J.JObj{t}, True{}, "")), SCon{'"', SCon{',', out}}))))))))

law obj.t.k4:
  for +k: String
  for +v: J.Json
  for +t: List<&2, J.Field>
  for +up: List<&2, F.Box>
  for +m: F.Mode
  for +r: String
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  for +pa: U32
  for +pe: U32
  for pre: {F.gc(SCon{',', SCon{'"', S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}})}}, m, SCon{',', SCon{'"', S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}})}}, Con{F.BObj{}, up}, out, 0, 0, key, at, ea) == F.gc(S.text(v, False{}, S.text(J.JObj{t}, True{}, r)), F.VObjVal{}, S.text(v, False{}, S.text(J.JObj{t}, True{}, r)), Con{F.BObj{}, up}, SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{',', out}})}, 0, 0, True{}, (pa + 1 : U32), pe) : F.Out}
  for +q1: Q
  for aft1: AftQ(q1)
  for eq1: {F.gc(S.text(v, False{}, S.text(J.JObj{t}, True{}, r)), F.VObjVal{}, S.text(v, False{}, S.text(J.JObj{t}, True{}, r)), Con{F.BObj{}, up}, SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{',', out}})}, 0, 0, True{}, (pa + 1 : U32), pe) == after(S.text(J.JObj{t}, True{}, r), Con{F.BObj{}, up}, push(S.text(v, False{}, ""), SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{',', out}})}), q1) : F.Out}
  for ih2: @m2: F.Mode -> @k2: Bool -> @a2: U32 -> @e2: U32 -> @aft: Aft(m2) -> Goal(J.JObj{t}, True{}, m2, Con{F.BObj{}, up}, r, push(S.text(v, False{}, ""), SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{',', out}})}), k2, a2, e2)
  Goal(J.JObj{Con{J.Field{k, v}, t}}, True{}, m, Con{F.BObj{}, up}, r, out, key, at, ea)

def obj.t.k4(k, v, t, up, m, r, out, key, at, ea, pa, pe, pre, q1, aft1, eq1, ih2):
  match q1:
    case Q{m1, k1, a1, e1}:
      obj.t.k5(k, v, t, up, m, r, out, key, at, ea, pa, pe, pre, m1, k1, a1, e1, eq1, ih2(m1, k1, a1, e1, aft1))

law obj.t.k3:
  for +k: String
  for +v: J.Json
  for +t: List<&2, J.Field>
  for +up: List<&2, F.Box>
  for +m: F.Mode
  for +r: String
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  for +pa: U32
  for +pe: U32
  for pre: {F.gc(SCon{',', SCon{'"', S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}})}}, m, SCon{',', SCon{'"', S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}})}}, Con{F.BObj{}, up}, out, 0, 0, key, at, ea) == F.gc(S.text(v, False{}, S.text(J.JObj{t}, True{}, r)), F.VObjVal{}, S.text(v, False{}, S.text(J.JObj{t}, True{}, r)), Con{F.BObj{}, up}, SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{',', out}})}, 0, 0, True{}, (pa + 1 : U32), pe) : F.Out}
  for g1: Goal(v, False{}, F.VObjVal{}, Con{F.BObj{}, up}, S.text(J.JObj{t}, True{}, r), SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{',', out}})}, True{}, (pa + 1 : U32), pe)
  for ih2: @m2: F.Mode -> @k2: Bool -> @a2: U32 -> @e2: U32 -> @aft: Aft(m2) -> Goal(J.JObj{t}, True{}, m2, Con{F.BObj{}, up}, r, push(S.text(v, False{}, ""), SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{',', out}})}), k2, a2, e2)
  Goal(J.JObj{Con{J.Field{k, v}, t}}, True{}, m, Con{F.BObj{}, up}, r, out, key, at, ea)

def obj.t.k3(k, v, t, up, m, r, out, key, at, ea, pa, pe, pre, g1, ih2):
  (+q1, pr1) = g1
  (aft1, eq1) = pr1
  obj.t.k4(k, v, t, up, m, r, out, key, at, ea, pa, pe, pre, q1, aft1, eq1, ih2)

law obj.t.k2:
  for +k: String
  for +v: J.Json
  for +t: List<&2, J.Field>
  for +up: List<&2, F.Box>
  for +m: F.Mode
  for +r: String
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  for pre: {F.gc(SCon{',', SCon{'"', S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}})}}, m, SCon{',', SCon{'"', S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}})}}, Con{F.BObj{}, up}, out, 0, 0, key, at, ea) == F.gc(S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}}), F.SStr{}, S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}}), Con{F.BObj{}, up}, SCon{'"', SCon{',', out}}, 0, 0, True{}, ((at + 1 : U32) + 1 : U32), ea) : F.Out}
  for +pa: U32
  for +pe: U32
  for eqk: {F.gc(S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}}), F.SStr{}, S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}}), Con{F.BObj{}, up}, SCon{'"', SCon{',', out}}, 0, 0, True{}, ((at + 1 : U32) + 1 : U32), ea) == F.gc(SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}, F.VColon{}, SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}, Con{F.BObj{}, up}, push(S.esc(k, "\""), SCon{'"', SCon{',', out}}), 0, 0, True{}, pa, pe) : F.Out}
  for ih1: @pa2: U32 -> @pe2: U32 -> Goal(v, False{}, F.VObjVal{}, Con{F.BObj{}, up}, S.text(J.JObj{t}, True{}, r), SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{',', out}})}, True{}, (pa2 + 1 : U32), pe2)
  for ih2: @m2: F.Mode -> @k2: Bool -> @a2: U32 -> @e2: U32 -> @aft: Aft(m2) -> Goal(J.JObj{t}, True{}, m2, Con{F.BObj{}, up}, r, push(S.text(v, False{}, ""), SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{',', out}})}), k2, a2, e2)
  Goal(J.JObj{Con{J.Field{k, v}, t}}, True{}, m, Con{F.BObj{}, up}, r, out, key, at, ea)

def obj.t.k2(k, v, t, up, m, r, out, key, at, ea, pre, pa, pe, eqk, ih1, ih2):
  obj.t.k3(k, v, t, up, m, r, out, key, at, ea, pa, pe, Equal.trans(F.Out,
      F.gc(SCon{',', SCon{'"', S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}})}}, m, SCon{',', SCon{'"', S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}})}}, Con{F.BObj{}, up}, out, 0, 0, key, at, ea),
      F.gc(S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}}), F.SStr{}, S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}}), Con{F.BObj{}, up}, SCon{'"', SCon{',', out}}, 0, 0, True{}, ((at + 1 : U32) + 1 : U32), ea),
      F.gc(S.text(v, False{}, S.text(J.JObj{t}, True{}, r)), F.VObjVal{}, S.text(v, False{}, S.text(J.JObj{t}, True{}, r)), Con{F.BObj{}, up}, SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{',', out}})}, 0, 0, True{}, (pa + 1 : U32), pe),
      pre,
      Equal.trans(F.Out,
        F.gc(S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}}), F.SStr{}, S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}}), Con{F.BObj{}, up}, SCon{'"', SCon{',', out}}, 0, 0, True{}, ((at + 1 : U32) + 1 : U32), ea),
        F.gc(SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}, F.VColon{}, SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}, Con{F.BObj{}, up}, push(S.esc(k, "\""), SCon{'"', SCon{',', out}}), 0, 0, True{}, pa, pe),
        F.gc(S.text(v, False{}, S.text(J.JObj{t}, True{}, r)), F.VObjVal{}, S.text(v, False{}, S.text(J.JObj{t}, True{}, r)), Con{F.BObj{}, up}, SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{',', out}})}, 0, 0, True{}, (pa + 1 : U32), pe),
        eqk,
        {==})),
    ih1(pa, pe), ih2)

law obj.t.k1:
  for +k: String
  for +v: J.Json
  for +t: List<&2, J.Field>
  for +up: List<&2, F.Box>
  for +m: F.Mode
  for +r: String
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  for pre: {F.gc(SCon{',', SCon{'"', S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}})}}, m, SCon{',', SCon{'"', S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}})}}, Con{F.BObj{}, up}, out, 0, 0, key, at, ea) == F.gc(S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}}), F.SStr{}, S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}}), Con{F.BObj{}, up}, SCon{'"', SCon{',', out}}, 0, 0, True{}, ((at + 1 : U32) + 1 : U32), ea) : F.Out}
  for gk: FS.SB(k, SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}, Con{F.BObj{}, up}, SCon{'"', SCon{',', out}}, True{}, ((at + 1 : U32) + 1 : U32), ea)
  for ih1: @pa2: U32 -> @pe2: U32 -> Goal(v, False{}, F.VObjVal{}, Con{F.BObj{}, up}, S.text(J.JObj{t}, True{}, r), SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{',', out}})}, True{}, (pa2 + 1 : U32), pe2)
  for ih2: @m2: F.Mode -> @k2: Bool -> @a2: U32 -> @e2: U32 -> @aft: Aft(m2) -> Goal(J.JObj{t}, True{}, m2, Con{F.BObj{}, up}, r, push(S.text(v, False{}, ""), SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{',', out}})}), k2, a2, e2)
  Goal(J.JObj{Con{J.Field{k, v}, t}}, True{}, m, Con{F.BObj{}, up}, r, out, key, at, ea)

def obj.t.k1(k, v, t, up, m, r, out, key, at, ea, pre, gk, ih1, ih2):
  (+p, eqk) = gk
  obj.t.k2(k, v, t, up, m, r, out, key, at, ea, pre, FS.p_at(p), FS.p_ea(p), eqk, ih1, ih2)

# the main lemma: from where the text of j may start, the loop reads it
# and lands, with the same text pushed, where what follows may come
law run:
  for +j: J.Json
  for +more: Bool
  for +m: F.Mode
  for +stk: List<&2, F.Box>
  for +r: String
  for +out: String
  for +key: Bool
  for +at: U32
  for +ea: U32
  for ctx: Ctx(more, j, m, stk)
  Goal(j, more, m, stk, r, out, key, at, ea)

def run(j, more, m, stk, r, out, key, at, ea, ctx):
  match j:
    case J.JNull{}:
      match more:
        case False{}:
          (Q{F.VAfter{}, key, ((((at + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32), ea}, (Unit{}, v_null(m, ctx, r, stk, out, key, at, ea)))
        case True{}:
          match ctx:
    case J.JBool{True{}}:
      match more:
        case False{}:
          (Q{F.VAfter{}, key, ((((at + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32), ea}, (Unit{}, v_true(m, ctx, r, stk, out, key, at, ea)))
        case True{}:
          match ctx:
    case J.JBool{False{}}:
      match more:
        case False{}:
          (Q{F.VAfter{}, key, (((((at + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32) + 1 : U32), ea}, (Unit{}, v_false(m, ctx, r, stk, out, key, at, ea)))
        case True{}:
          match ctx:
    case J.JNum{n}:
      match more:
        case False{}:
          num(n, m, ctx, r, stk, out, key, at, ea)
        case True{}:
          match ctx:
    case J.JStr{s}:
      match more:
        case False{}:
          str_v.k(s, m, r, stk, out, key, at, ea, v_quote(m, ctx, S.esc(s, SCon{'"', r}), stk, out, key, at, ea),
            FS.sb(s, r, stk, SCon{'"', out}, False{}, (at + 1 : U32), ea))
        case True{}:
          match ctx:
    case J.JArr{Nil{}}:
      match more:
        case False{}:
          (Q{F.VAfter{}, key, ((at + 1 : U32) + 1 : U32), ea}, (Unit{}, v_arr0(m, ctx, r, stk, out, key, at, ea)))
        case True{}:
          match stk:
            case Con{F.BArr{}, up}:
              (Q{F.VAfter{}, key, (at + 1 : U32), ea}, (Unit{}, a_close(m, ctx, r, up, out, key, at, ea)))
            case Con{F.BObj{}, _}:
              match ctx:
            case Nil{}:
              match ctx:
    case J.JArr{Con{h, t}}:
      match more:
        case False{}:
          arr.f.k1(h, t, stk, m, r, out, key, at, ea, v_arr(m, ctx, S.text(h, False{}, S.text(J.JArr{t}, True{}, r)), stk, out, key, at, ea),
            run(h, False{}, F.VFirst{}, Con{F.BArr{}, stk}, S.text(J.JArr{t}, True{}, r), SCon{'[', out}, key, (at + 1 : U32), ea, Unit{}),
            +m2 => +k2 => +a2 => +e2 => aft => run(J.JArr{t}, True{}, m2, Con{F.BArr{}, stk}, r, push(S.text(h, False{}, ""), SCon{'[', out}), k2, a2, e2, aft))
        case True{}:
          match stk:
            case Con{F.BArr{}, up}:
              arr.t.k1(h, t, up, m, r, out, key, at, ea, a_comma(m, ctx, S.text(h, False{}, S.text(J.JArr{t}, True{}, r)), up, out, key, at, ea),
            run(h, False{}, F.VItem{}, Con{F.BArr{}, up}, S.text(J.JArr{t}, True{}, r), SCon{',', out}, key, (at + 1 : U32), ea, Unit{}),
            +m2 => +k2 => +a2 => +e2 => aft => run(J.JArr{t}, True{}, m2, Con{F.BArr{}, up}, r, push(S.text(h, False{}, ""), SCon{',', out}), k2, a2, e2, aft))
            case Con{F.BObj{}, _}:
              match ctx:
            case Nil{}:
              match ctx:
    case J.JObj{Nil{}}:
      match more:
        case False{}:
          (Q{F.VAfter{}, key, ((at + 1 : U32) + 1 : U32), ea}, (Unit{}, v_obj0(m, ctx, r, stk, out, key, at, ea)))
        case True{}:
          match stk:
            case Con{F.BObj{}, up}:
              (Q{F.VAfter{}, key, (at + 1 : U32), ea}, (Unit{}, o_close(m, ctx, r, up, out, key, at, ea)))
            case Con{F.BArr{}, _}:
              match ctx:
            case Nil{}:
              match ctx:
    case J.JObj{Con{J.Field{k, v}, t}}:
      match more:
        case False{}:
          obj.f.k1(k, v, t, stk, m, r, out, key, at, ea, Equal.trans(F.Out,
        F.gc(SCon{'{', SCon{'"', S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}})}}, m, SCon{'{', SCon{'"', S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}})}}, stk, out, 0, 0, key, at, ea),
        F.gc(SCon{'"', S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}})}, F.VObjFirst{}, SCon{'"', S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}})}, Con{F.BObj{}, stk}, SCon{'{', out}, 0, 0, key, (at + 1 : U32), ea),
        F.gc(S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}}), F.SStr{}, S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}}), Con{F.BObj{}, stk}, SCon{'"', SCon{'{', out}}, 0, 0, True{}, ((at + 1 : U32) + 1 : U32), ea),
        v_obj(m, ctx, SCon{'"', S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}})}, stk, out, key, at, ea),
        {==}),
            FS.sb(k, SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}, Con{F.BObj{}, stk}, SCon{'"', SCon{'{', out}}, True{}, ((at + 1 : U32) + 1 : U32), ea),
            +pa2 => +pe2 => run(v, False{}, F.VObjVal{}, Con{F.BObj{}, stk}, S.text(J.JObj{t}, True{}, r), SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{'{', out}})}, True{}, (pa2 + 1 : U32), pe2, Unit{}),
            +m2 => +k2 => +a2 => +e2 => aft => run(J.JObj{t}, True{}, m2, Con{F.BObj{}, stk}, r, push(S.text(v, False{}, ""), SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{'{', out}})}), k2, a2, e2, aft))
        case True{}:
          match stk:
            case Con{F.BObj{}, up}:
              obj.t.k1(k, v, t, up, m, r, out, key, at, ea, Equal.trans(F.Out,
        F.gc(SCon{',', SCon{'"', S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}})}}, m, SCon{',', SCon{'"', S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}})}}, Con{F.BObj{}, up}, out, 0, 0, key, at, ea),
        F.gc(SCon{'"', S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}})}, F.VKey{}, SCon{'"', S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}})}, Con{F.BObj{}, up}, SCon{',', out}, 0, 0, key, (at + 1 : U32), ea),
        F.gc(S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}}), F.SStr{}, S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}}), Con{F.BObj{}, up}, SCon{'"', SCon{',', out}}, 0, 0, True{}, ((at + 1 : U32) + 1 : U32), ea),
        o_comma(m, ctx, SCon{'"', S.esc(k, SCon{'"', SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}})}, up, out, key, at, ea),
        {==}),
            FS.sb(k, SCon{':', S.text(v, False{}, S.text(J.JObj{t}, True{}, r))}, Con{F.BObj{}, up}, SCon{'"', SCon{',', out}}, True{}, ((at + 1 : U32) + 1 : U32), ea),
            +pa2 => +pe2 => run(v, False{}, F.VObjVal{}, Con{F.BObj{}, up}, S.text(J.JObj{t}, True{}, r), SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{',', out}})}, True{}, (pa2 + 1 : U32), pe2, Unit{}),
            +m2 => +k2 => +a2 => +e2 => aft => run(J.JObj{t}, True{}, m2, Con{F.BObj{}, up}, r, push(S.text(v, False{}, ""), SCon{':', push(S.esc(k, "\""), SCon{'"', SCon{',', out}})}), k2, a2, e2, aft))
            case Con{F.BArr{}, _}:
              match ctx:
            case Nil{}:
              match ctx:

# at the end of the input, the loop after a value answers its output
law finish.m:
  for +m: F.Mode
  for +k: Bool
  for +a: U32
  for +e: U32
  for +out: String
  for aft: Aft(m)
  {after("", [], out, Q{m, k, a, e}) == F.Ok{String.reverse(out)} : F.Out}

def finish.m(m, k, a, e, out, aft):
  match m:
    case F.VStart{}:
      match aft:
    case F.VTop{}:
      match aft:
    case F.VFirst{}:
      match aft:
    case F.VItem{}:
      match aft:
    case F.VObjFirst{}:
      match aft:
    case F.VKey{}:
      match aft:
    case F.VColon{}:
      match aft:
    case F.VObjVal{}:
      match aft:
    case F.VAfter{}:
      {==}
    case F.SStr{}:
      match aft:
    case F.SEsc{}:
      match aft:
    case F.SU4{}:
      match aft:
    case F.SU3{}:
      match aft:
    case F.SU2{}:
      match aft:
    case F.SU1{}:
      match aft:
    case F.SHi{}:
      match aft:
    case F.SHiU{}:
      match aft:
    case F.NMin{}:
      match aft:
    case F.NZero{}:
      {==}
    case F.NInt{}:
      {==}
    case F.NDot{}:
      match aft:
    case F.NFrac{}:
      {==}
    case F.NE{}:
      match aft:
    case F.NESign{}:
      match aft:
    case F.NExp{}:
      {==}
    case F.T1{}:
      match aft:
    case F.T2{}:
      match aft:
    case F.T3{}:
      match aft:
    case F.F1{}:
      match aft:
    case F.F2{}:
      match aft:
    case F.F3{}:
      match aft:
    case F.F4{}:
      match aft:
    case F.U1{}:
      match aft:
    case F.U2{}:
      match aft:
    case F.U3{}:
      match aft:
    case F.BCtrl{}:
      match aft:
    case F.BUni{}:
      match aft:
    case F.BLone{}:
      match aft:
    case F.BEsc{}:
      match aft:

law finish:
  for +out: String
  for +q: Q
  for aft: AftQ(q)
  {after("", [], out, q) == F.Ok{String.reverse(out)} : F.Out}

def finish(out, q, aft):
  match q:
    case Q{m, k, a, e}:
      finish.m(m, k, a, e, out, aft)

law rev_rev:
  for +a: String
  {String.reverse(push(a, "")) == a : String}

def rev_rev(a):
  Equal.trans(String, String.reverse(push(a, "")), a ++ "", a, P.rr(a, "", ""), T.app_nil(a))

law round_trip.go:
  for +t: String
  for g: V(t, F.VStart{}, [], "", False{}, 0, 0, "", [], push(t, ""))
  {F.gc(t, F.VStart{}, t, [], "", 0, 0, False{}, 0, 0) == F.Ok{t} : F.Out}

def round_trip.go(t, g):
  (+q, pr) = g
  (aft, eq) = pr
  Equal.trans(F.Out, F.gc(t, F.VStart{}, t, [], "", 0, 0, False{}, 0, 0), after("", [], push(t, ""), q), F.Ok{t},
    eq,
    Equal.trans(F.Out, after("", [], push(t, ""), q), F.Ok{String.reverse(push(t, ""))}, F.Ok{t},
      finish(push(t, ""), q, aft),
      Equal.cong(String, F.Out, z => F.Ok{z}, String.reverse(push(t, "")), t, rev_rev(t))))

# the fast loop reads what the printer writes back to the same text
law fast_round_trip:
  for +j: J.Json
  {F.reformat(J.stringify(j)) == F.Ok{J.stringify(j)} : F.Out}

def fast_round_trip(j):
  +t : String = S.text(j, False{}, "")
  %Equal.sym(String, J.stringify(j), t, P.print(j)) : {F.reformat(_) == F.Ok{_} : F.Out}
  round_trip.go(t, run(j, False{}, F.VStart{}, [], "", "", False{}, 0, 0, Unit{}))
