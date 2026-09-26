import Base
import ../bjson.bend as J
import ../fast.bend as F
import ./spec.bend as S
import ./fast_text.bend as T
import ./fast.bend as FS

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
