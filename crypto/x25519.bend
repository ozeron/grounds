import Base
import ./bytes.bend as B
import ./field25519.bend as F

# RFC 7748 X25519. The field implementation uses fixed-size arithmetic and
# the ladder swaps coordinates by XOR mask. Generated-code timing is unproven.

def clamp_scalar(bytes: List<&2, U32>, +i: U32) -> List<&2, U32>:
  match bytes:
    case Nil{}:
      []
    case Con{+byte, tail}:
      first = U32.and(byte, 248)
      last = U32.or(U32.and(byte, 127), 64)
      value = Bool.pick(U32, U32.is_eq(i, 0), first,
        Bool.pick(U32, U32.is_eq(i, 31), last, byte))
      Con{value, clamp_scalar(tail, U32.inc(i))}

def scalar_bit(position: Nat, offset: Nat, bytes: List<&2, U32>) -> U32:
  match position bytes:
    case 0n Con{byte, _}:
      U32.and(U32.shrn(byte, offset), 1)
    case 1n+p Con{_, tail}:
      scalar_bit(p, offset, tail)
    case _ _:
      0

type Swap is Type:
  Swap{a: Array<U32>, b: Array<U32>, out_a: Array<U32>, out_b: Array<U32>}

def swap_step.b(+i: U32, +mask: U32, a: Array<U32>, +av: U32,
                out_a: Array<U32>, out_b: Array<U32>, r: Array<U32> & U32) -> Swap:
  (b, +bv) = r
  +difference = U32.and(mask, U32.xor(av, bv))
  Swap{a, b, Array.set(U32, out_a, i, U32.xor(av, difference)),
    Array.set(U32, out_b, i, U32.xor(bv, difference))}

def swap_step.a(+i: U32, mask: U32, b: Array<U32>,
                out_a: Array<U32>, out_b: Array<U32>, r: Array<U32> & U32) -> Swap:
  (a, av) = r
  swap_step.b(i, mask, a, av, out_a, out_b, Array.get(U32, b, i))

def swap_digits(left: Nat, +i: U32, +mask: U32, state: Swap) -> Array<U32> & Array<U32>:
  match left state:
    case 0n Swap{_, _, out_a, out_b}:
      (out_a, out_b)
    case 1n+p Swap{a, b, out_a, out_b}:
      swap_digits(p, U32.inc(i), mask,
        swap_step.a(i, mask, b, out_a, out_b, Array.get(U32, a, i)))

def cswap(bit: U32, a: Array<U32>, b: Array<U32>) -> Array<U32> & Array<U32>:
  swap_digits(32n, 0, U32.sub(0, bit), Swap{a, b, F.zero(), F.zero()})

type Ladder is Type:
  Ladder{x1: Array<U32>, x2: Array<U32>, z2: Array<U32>, x3: Array<U32>, z3: Array<U32>, swap: U32}

def swapped.z(x1: Array<U32>, x2: Array<U32>, x3: Array<U32>, bit: U32,
              r: Array<U32> & Array<U32>) -> Ladder:
  (z2, z3) = r
  Ladder{x1, x2, z2, x3, z3, bit}

def swapped.x(x1: Array<U32>, z2: Array<U32>, z3: Array<U32>, bit: U32, control: U32,
              r: Array<U32> & Array<U32>) -> Ladder:
  (x2, x3) = r
  swapped.z(x1, x2, x3, bit, cswap(control, z2, z3))

def swapped(+bit: U32, state: Ladder) -> Ladder:
  match state:
    case Ladder{x1, x2, z2, x3, z3, old}:
      +control = U32.xor(old, bit)
      swapped.x(x1, z2, z3, bit, control, cswap(control, x2, x3))

type Sums is Type:
  Sums{sum: Array<U32>, difference: Array<U32>}

def add_sub.cloned(ar: Array<U32> & Array<U32>, br: Array<U32> & Array<U32>) -> Sums:
  (a1, a2) = ar
  (b1, b2) = br
  Sums{F.add(a1, b1), F.sub(a2, b2)}

def add_sub(a: Array<U32>, b: Array<U32>) -> Sums:
  add_sub.cloned(Array.clone(U32, a), Array.clone(U32, b))

def step.finish(x1: Array<U32>, x1_for_z3: Array<U32>,
                aa_for_x2: Array<U32>, aa_for_z2: Array<U32>,
                bb_for_x2: Array<U32>, e_for_z2: Array<U32>, e_for_a24: Array<U32>,
                da_plus: Array<U32>, da_minus: Array<U32>,
                cb_plus: Array<U32>, cb_minus: Array<U32>, bit: U32) -> Ladder:
  x3 = F.square(F.add(da_plus, cb_plus))
  z3 = F.mul(x1_for_z3, F.square(F.sub(da_minus, cb_minus)))
  x2 = F.mul(aa_for_x2, bb_for_x2)
  z2 = F.mul(e_for_z2, F.add(aa_for_z2, F.mul(F.a24(), e_for_a24)))
  Ladder{x1, x2, z2, x3, z3, bit}

def step.split(x1: Array<U32>, x1_for_z3: Array<U32>,
               aa_copy: Array<U32> & Array<U32>, bb_for_x2: Array<U32>,
               e_copy: Array<U32> & Array<U32>,
               da_copy: Array<U32> & Array<U32>, cb_copy: Array<U32> & Array<U32>, bit: U32) -> Ladder:
  (aa_for_x2, aa_for_z2) = aa_copy
  (e_for_z2, e_for_a24) = e_copy
  (da_plus, da_minus) = da_copy
  (cb_plus, cb_minus) = cb_copy
  step.finish(x1, x1_for_z3, aa_for_x2, aa_for_z2, bb_for_x2,
    e_for_z2, e_for_a24, da_plus, da_minus, cb_plus, cb_minus, bit)

def step.aa(x1: Array<U32>, x1_for_z3: Array<U32>,
            aa_copy: Array<U32> & Array<U32>, bb_copy: Array<U32> & Array<U32>,
            da: Array<U32>, cb: Array<U32>, bit: U32) -> Ladder:
  (aa_for_e, aa_other) = aa_copy
  (bb_for_e, bb_for_x2) = bb_copy
  e = F.sub(aa_for_e, bb_for_e)
  step.split(x1, x1_for_z3, Array.clone(U32, aa_other), bb_for_x2,
    Array.clone(U32, e), Array.clone(U32, da), Array.clone(U32, cb), bit)

def step.ab(x1: Array<U32>, x1_for_z3: Array<U32>,
            ar: Array<U32> & Array<U32>, br: Array<U32> & Array<U32>,
            c: Array<U32>, d: Array<U32>, bit: U32) -> Ladder:
  (a_for_aa, a_for_da) = ar
  (b_for_bb, b_for_cb) = br
  aa = F.square(a_for_aa)
  bb = F.square(b_for_bb)
  da = F.mul(d, a_for_da)
  cb = F.mul(c, b_for_cb)
  step.aa(x1, x1_for_z3, Array.clone(U32, aa), Array.clone(U32, bb), da, cb, bit)

def step.sums(x1_copy: Array<U32> & Array<U32>, ab: Sums, cd: Sums, bit: U32) -> Ladder:
  (x1, x1_for_z3) = x1_copy
  match ab cd:
    case Sums{a, b} Sums{c, d}:
      step.ab(x1, x1_for_z3, Array.clone(U32, a), Array.clone(U32, b), c, d, bit)

def step(state: Ladder) -> Ladder:
  match state:
    case Ladder{x1, x2, z2, x3, z3, bit}:
      step.sums(Array.clone(U32, x1), add_sub(x2, z2), add_sub(x3, z3), bit)

def ladder(left: Nat, +scalar: List<&2, U32>, state: Ladder) -> Ladder:
  match left state:
    case 0n Ladder{x1, x2, z2, x3, z3, swap}:
      swapped(0, Ladder{x1, x2, z2, x3, z3, swap})
    case 1n+ +p Ladder{x1, x2, z2, x3, z3, swap}:
      +bit = scalar_bit(Nat.div(p, 8n), Nat.mod(p, 8n), scalar)
      ladder(p, scalar, step(swapped(bit, Ladder{x1, x2, z2, x3, z3, swap})))

# p-2 = 2^255-21 has all bits 0..254 set except bits 2 and 4.
def pow_bit(include: Bool, square: Array<U32>, base: Array<U32>) -> Array<U32>:
  match include:
    case False{}:
      square
    case True{}:
      F.mul(square, base)

type Power is Type:
  Power{base: Array<U32>, acc: Array<U32>}

def invert.step(include: Bool, square: Array<U32>, r: Array<U32> & Array<U32>) -> Power:
  (base, for_mul) = r
  Power{base, pow_bit(include, square, for_mul)}

def invert(left: Nat, state: Power) -> Array<U32>:
  match left state:
    case 0n Power{_, acc}:
      acc
    case 1n+ +p Power{base, acc}:
      include = Bool.not(Bool.or(Nat.is_eq(p, 2n), Nat.is_eq(p, 4n)))
      invert(p, invert.step(include, F.square(acc), Array.clone(U32, base)))

def finish(state: Ladder) -> List<&2, U32>:
  match state:
    case Ladder{_, x2, z2, _, _, _}:
      F.encode(F.mul(x2, invert(255n, Power{z2, F.one()})))

def initial(r: Array<U32> & Array<U32>) -> Ladder:
  (x1, x3) = r
  Ladder{x1, F.one(), F.zero(), x3, F.one(), 0}

def scalar_mult.raw(scalar: List<&2, U32>, u: List<&2, U32>) -> List<&2, U32>:
  k = clamp_scalar(scalar, 0)
  finish(ladder(255n, k, initial(Array.clone(U32, F.decode(u)))))

def scalar_mult.checked(ok: Bool, scalar: List<&2, U32>, u: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match ok:
    case False{}:
      None{}
    case True{}:
      Some{scalar_mult.raw(scalar, u)}

def scalar_mult(+scalar: List<&2, U32>, +u: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  ok = Bool.and(Bool.and(Nat.is_eq(B.length(scalar), 32n), B.valid(scalar)),
    Bool.and(Nat.is_eq(B.length(u), 32n), B.valid(u)))
  scalar_mult.checked(ok, scalar, u)

def base_point() -> List<&2, U32>:
  Con{9, List.replicate(U32, 31n, 0)}

def public_key(scalar: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  scalar_mult(scalar, base_point())

def any_nonzero(bytes: List<&2, U32>, +acc: U32) -> U32:
  match bytes:
    case Nil{}:
      acc
    case Con{byte, tail}:
      any_nonzero(tail, U32.or(acc, byte))

def shared.nonzero(ok: Bool, bytes: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  match ok:
    case False{}:
      None{}
    case True{}:
      Some{bytes}

def shared.checked(result: Maybe<&2, List<&2, U32>>) -> Maybe<&2, List<&2, U32>>:
  match result:
    case None{}:
      None{}
    case Some{+bytes}:
      shared.nonzero(U32.is_ne(any_nonzero(bytes, 0), 0), bytes)

def shared(scalar: List<&2, U32>, peer_public: List<&2, U32>) -> Maybe<&2, List<&2, U32>>:
  shared.checked(scalar_mult(scalar, peer_public))
