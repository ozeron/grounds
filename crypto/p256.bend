import Base
import ./field256.bend as F
import ./bytes.bend as B

# P-256, SP 800-186 section 3.2.1.3. Internal ordinary projective x=X/Z,
# y=Y/Z with canonical Montgomery byte limbs (R=2^256). Only validated
# curve points or the infinity representative (0:R:0) enter group operations.
# Complete RCB add-2015-rcb-3 includes doubling/inverses/infinity without a
# coordinate-dependent exceptional-case branch. Source-level fixed schedules
# do not establish optimized native/JIT timing or physical secret erasure.

type Point is Type:
  Point{x: Array<U32>, y: Array<U32>, z: Array<U32>}

def to_mont(value: Array<U32>) -> Array<U32>:
  F.mont(F.Field{}, value, F.r2(F.Field{}))

def from_mont(value: Array<U32>) -> Array<U32>:
  F.mont(F.Field{}, value, F.one())

def mont_one() -> Array<U32>:
  to_mont(F.one())

def infinity() -> Point:
  Point{F.zero(), mont_one(), F.zero()}

def curve_b() -> Array<U32>:
  to_mont(F.decode(F.Field{}, [75, 96, 210, 39, 62, 60, 206, 59, 246, 176, 83, 204, 176, 6, 29, 101, 188, 134, 152, 118, 85, 189, 235, 179, 231, 147, 58, 170, 216, 53, 198, 90]))

def generator() -> Point:
  Point{to_mont(F.decode(F.Field{}, [150, 194, 152, 216, 69, 57, 161, 244, 160, 51, 235, 45, 129, 125, 3, 119, 242, 64, 164, 99, 229, 230, 188, 248, 71, 66, 44, 225, 242, 209, 23, 107])),
        to_mont(F.decode(F.Field{}, [245, 81, 191, 55, 104, 64, 182, 203, 206, 94, 49, 107, 87, 51, 206, 43, 22, 158, 15, 124, 74, 235, 231, 142, 155, 127, 26, 254, 226, 66, 227, 79])), mont_one()}

def clone.coordinates(xr: Array<U32> & Array<U32>, yr: Array<U32> & Array<U32>,
                      zr: Array<U32> & Array<U32>) -> Point & Point:
  (x1, x2) = xr
  (y1, y2) = yr
  (z1, z2) = zr
  (Point{x1, y1, z1}, Point{x2, y2, z2})

def clone(point: Point) -> Point & Point:
  match point:
    case Point{x, y, z}:
      clone.coordinates(Array.clone(U32, x), Array.clone(U32, y), Array.clone(U32, z))

# Port of the published EFD straight-line formula; each arithmetic value
# remains canonical and in Montgomery representation throughout.
def add.stage_37(pair: Array<U32> & Array<U32>, keep_33: Array<U32>, keep_35: Array<U32>, keep_36: Array<U32>, keep_37: Array<U32>, t1_5: Array<U32>, y3_9: Array<U32>) -> Point:
  (keep_38, use_38) = pair
  x3_8 = F.mont(F.Field{}, use_38, keep_36)
  x3_9 = F.sub(F.Field{}, x3_8, t1_5)
  z3_4 = F.mont(F.Field{}, keep_33, keep_37)
  t1_6 = F.mont(F.Field{}, keep_38, keep_35)
  z3_5 = F.add(F.Field{}, z3_4, t1_6)
  Point{x3_9, y3_9, z3_5}

def add.stage_36(pair: Array<U32> & Array<U32>, keep_33: Array<U32>, keep_35: Array<U32>, keep_36: Array<U32>, t1_5: Array<U32>, t2_3: Array<U32>, t3_3: Array<U32>, use_36: Array<U32>) -> Point:
  (keep_37, use_37) = pair
  y3_8 = F.mont(F.Field{}, use_36, use_37)
  y3_9 = F.add(F.Field{}, y3_8, t2_3)
  add.stage_37(Array.clone(U32, t3_3), keep_33, keep_35, keep_36, keep_37, t1_5, y3_9)

def add.stage_35(pair: Array<U32> & Array<U32>, keep_33: Array<U32>, keep_35: Array<U32>, t1_5: Array<U32>, t2_3: Array<U32>, t3_3: Array<U32>, z3_3: Array<U32>) -> Point:
  (keep_36, use_36) = pair
  add.stage_36(Array.clone(U32, z3_3), keep_33, keep_35, keep_36, t1_5, t2_3, t3_3, use_36)

def add.stage_34(pair: Array<U32> & Array<U32>, keep_33: Array<U32>, keep_34: Array<U32>, t1_5: Array<U32>, t3_3: Array<U32>, x3_7: Array<U32>, z3_3: Array<U32>) -> Point:
  (keep_35, use_35) = pair
  t2_3 = F.mont(F.Field{}, use_35, keep_34)
  add.stage_35(Array.clone(U32, x3_7), keep_33, keep_35, t1_5, t2_3, t3_3, z3_3)

def add.stage_33(pair: Array<U32> & Array<U32>, keep_33: Array<U32>, t0_3: Array<U32>, t3_3: Array<U32>, use_33: Array<U32>, x3_7: Array<U32>, z3_3: Array<U32>) -> Point:
  (keep_34, use_34) = pair
  t1_5 = F.mont(F.Field{}, use_33, use_34)
  add.stage_34(Array.clone(U32, t0_3), keep_33, keep_34, t1_5, t3_3, x3_7, z3_3)

def add.stage_32(pair: Array<U32> & Array<U32>, t0_3: Array<U32>, t3_3: Array<U32>, x3_7: Array<U32>, y3_7: Array<U32>, z3_3: Array<U32>) -> Point:
  (keep_33, use_33) = pair
  add.stage_33(Array.clone(U32, y3_7), keep_33, t0_3, t3_3, use_33, x3_7, z3_3)

def add.stage_31(pair: Array<U32> & Array<U32>, keep_27: Array<U32>, t3_3: Array<U32>, t4_5: Array<U32>, use_31: Array<U32>, x3_7: Array<U32>, y3_7: Array<U32>, z3_3: Array<U32>) -> Point:
  (keep_32, use_32) = pair
  t1_4 = F.add(F.Field{}, use_31, use_32)
  t0_2 = F.add(F.Field{}, t1_4, keep_32)
  t0_3 = F.sub(F.Field{}, t0_2, keep_27)
  add.stage_32(Array.clone(U32, t4_5), t0_3, t3_3, x3_7, y3_7, z3_3)

def add.stage_30(pair: Array<U32> & Array<U32>, keep_27: Array<U32>, t3_3: Array<U32>, t4_5: Array<U32>, x3_7: Array<U32>, y3_7: Array<U32>, z3_3: Array<U32>) -> Point:
  (keep_31, use_31) = pair
  add.stage_31(Array.clone(U32, keep_31), keep_27, t3_3, t4_5, use_31, x3_7, y3_7, z3_3)

def add.stage_29(pair: Array<U32> & Array<U32>, keep_27: Array<U32>, keep_28: Array<U32>, t3_3: Array<U32>, t4_5: Array<U32>, use_29: Array<U32>, x3_7: Array<U32>, z3_3: Array<U32>) -> Point:
  (keep_30, use_30) = pair
  t1_3 = F.add(F.Field{}, use_29, use_30)
  y3_7 = F.add(F.Field{}, t1_3, keep_30)
  add.stage_30(Array.clone(U32, keep_28), keep_27, t3_3, t4_5, x3_7, y3_7, z3_3)

def add.stage_28(pair: Array<U32> & Array<U32>, keep_27: Array<U32>, keep_28: Array<U32>, t3_3: Array<U32>, t4_5: Array<U32>, x3_7: Array<U32>, z3_3: Array<U32>) -> Point:
  (keep_29, use_29) = pair
  add.stage_29(Array.clone(U32, keep_29), keep_27, keep_28, t3_3, t4_5, use_29, x3_7, z3_3)

def add.stage_27(pair: Array<U32> & Array<U32>, keep_27: Array<U32>, t3_3: Array<U32>, t4_5: Array<U32>, x3_7: Array<U32>, y3_5: Array<U32>, z3_3: Array<U32>) -> Point:
  (keep_28, use_28) = pair
  y3_6 = F.sub(F.Field{}, y3_5, use_28)
  add.stage_28(Array.clone(U32, y3_6), keep_27, keep_28, t3_3, t4_5, x3_7, z3_3)

def add.stage_26(pair: Array<U32> & Array<U32>, keep_17: Array<U32>, t3_3: Array<U32>, t4_5: Array<U32>, x3_7: Array<U32>, y3_4: Array<U32>, z3_3: Array<U32>) -> Point:
  (keep_27, use_27) = pair
  y3_5 = F.sub(F.Field{}, y3_4, use_27)
  add.stage_27(Array.clone(U32, keep_17), keep_27, t3_3, t4_5, x3_7, y3_5, z3_3)

def add.stage_25(pair: Array<U32> & Array<U32>, keep_17: Array<U32>, t3_3: Array<U32>, t4_5: Array<U32>, use_25: Array<U32>, x3_7: Array<U32>, y3_4: Array<U32>, z3_3: Array<U32>) -> Point:
  (keep_26, use_26) = pair
  t1_2 = F.add(F.Field{}, use_25, use_26)
  t2_2 = F.add(F.Field{}, t1_2, keep_26)
  add.stage_26(Array.clone(U32, t2_2), keep_17, t3_3, t4_5, x3_7, y3_4, z3_3)

def add.stage_24(pair: Array<U32> & Array<U32>, keep_17: Array<U32>, t3_3: Array<U32>, t4_5: Array<U32>, x3_7: Array<U32>, y3_4: Array<U32>, z3_3: Array<U32>) -> Point:
  (keep_25, use_25) = pair
  add.stage_25(Array.clone(U32, keep_25), keep_17, t3_3, t4_5, use_25, x3_7, y3_4, z3_3)

def add.stage_23(pair: Array<U32> & Array<U32>, keep_17: Array<U32>, keep_19: Array<U32>, keep_20: Array<U32>, keep_23: Array<U32>, t3_3: Array<U32>, t4_5: Array<U32>, use_23: Array<U32>) -> Point:
  (keep_24, use_24) = pair
  z3_3 = F.sub(F.Field{}, use_23, use_24)
  x3_7 = F.add(F.Field{}, keep_23, keep_24)
  y3_4 = F.mont(F.Field{}, curve_b(), keep_20)
  add.stage_24(Array.clone(U32, keep_19), keep_17, t3_3, t4_5, x3_7, y3_4, z3_3)

def add.stage_22(pair: Array<U32> & Array<U32>, keep_17: Array<U32>, keep_19: Array<U32>, keep_20: Array<U32>, t3_3: Array<U32>, t4_5: Array<U32>, x3_6: Array<U32>) -> Point:
  (keep_23, use_23) = pair
  add.stage_23(Array.clone(U32, x3_6), keep_17, keep_19, keep_20, keep_23, t3_3, t4_5, use_23)

def add.stage_21(pair: Array<U32> & Array<U32>, keep_15: Array<U32>, keep_17: Array<U32>, keep_19: Array<U32>, keep_20: Array<U32>, t3_3: Array<U32>, t4_5: Array<U32>, use_21: Array<U32>) -> Point:
  (keep_22, use_22) = pair
  z3_2 = F.add(F.Field{}, use_21, use_22)
  x3_6 = F.add(F.Field{}, keep_22, z3_2)
  add.stage_22(Array.clone(U32, keep_15), keep_17, keep_19, keep_20, t3_3, t4_5, x3_6)

def add.stage_20(pair: Array<U32> & Array<U32>, keep_15: Array<U32>, keep_17: Array<U32>, keep_19: Array<U32>, keep_20: Array<U32>, t3_3: Array<U32>, t4_5: Array<U32>) -> Point:
  (keep_21, use_21) = pair
  add.stage_21(Array.clone(U32, keep_21), keep_15, keep_17, keep_19, keep_20, t3_3, t4_5, use_21)

def add.stage_19(pair: Array<U32> & Array<U32>, keep_15: Array<U32>, keep_17: Array<U32>, keep_19: Array<U32>, t3_3: Array<U32>, t4_5: Array<U32>, z3_1: Array<U32>) -> Point:
  (keep_20, use_20) = pair
  x3_5 = F.sub(F.Field{}, use_20, z3_1)
  add.stage_20(Array.clone(U32, x3_5), keep_15, keep_17, keep_19, keep_20, t3_3, t4_5)

def add.stage_18(pair: Array<U32> & Array<U32>, keep_15: Array<U32>, keep_17: Array<U32>, t3_3: Array<U32>, t4_5: Array<U32>, y3_3: Array<U32>) -> Point:
  (keep_19, use_19) = pair
  z3_1 = F.mont(F.Field{}, curve_b(), use_19)
  add.stage_19(Array.clone(U32, y3_3), keep_15, keep_17, keep_19, t3_3, t4_5, z3_1)

def add.stage_17(pair: Array<U32> & Array<U32>, keep_15: Array<U32>, keep_17: Array<U32>, t3_3: Array<U32>, t4_5: Array<U32>, use_17: Array<U32>, x3_4: Array<U32>) -> Point:
  (keep_18, use_18) = pair
  y3_2 = F.add(F.Field{}, use_17, use_18)
  y3_3 = F.sub(F.Field{}, x3_4, y3_2)
  add.stage_18(Array.clone(U32, keep_18), keep_15, keep_17, t3_3, t4_5, y3_3)

def add.stage_16(pair: Array<U32> & Array<U32>, keep_15: Array<U32>, keep_16: Array<U32>, t3_3: Array<U32>, t4_5: Array<U32>, x3_4: Array<U32>) -> Point:
  (keep_17, use_17) = pair
  add.stage_17(Array.clone(U32, keep_16), keep_15, keep_17, t3_3, t4_5, use_17, x3_4)

def add.stage_15(pair: Array<U32> & Array<U32>, keep_11: Array<U32>, keep_13: Array<U32>, keep_14: Array<U32>, keep_15: Array<U32>, keep_7: Array<U32>, keep_9: Array<U32>, t3_3: Array<U32>, t4_4: Array<U32>, use_15: Array<U32>) -> Point:
  (keep_16, use_16) = pair
  x3_2 = F.add(F.Field{}, use_15, use_16)
  t4_5 = F.sub(F.Field{}, t4_4, x3_2)
  x3_3 = F.add(F.Field{}, keep_7, keep_13)
  y3_1 = F.add(F.Field{}, keep_9, keep_14)
  x3_4 = F.mont(F.Field{}, x3_3, y3_1)
  add.stage_16(Array.clone(U32, keep_11), keep_15, keep_16, t3_3, t4_5, x3_4)

def add.stage_14(pair: Array<U32> & Array<U32>, keep_11: Array<U32>, keep_13: Array<U32>, keep_14: Array<U32>, keep_7: Array<U32>, keep_9: Array<U32>, t2_1: Array<U32>, t3_3: Array<U32>, t4_4: Array<U32>) -> Point:
  (keep_15, use_15) = pair
  add.stage_15(Array.clone(U32, t2_1), keep_11, keep_13, keep_14, keep_15, keep_7, keep_9, t3_3, t4_4, use_15)

def add.stage_13(pair: Array<U32> & Array<U32>, keep_10: Array<U32>, keep_11: Array<U32>, keep_12: Array<U32>, keep_13: Array<U32>, keep_7: Array<U32>, keep_9: Array<U32>, t2_1: Array<U32>, t3_3: Array<U32>, t4_3: Array<U32>) -> Point:
  (keep_14, use_14) = pair
  x3_1 = F.add(F.Field{}, keep_10, use_14)
  t4_4 = F.mont(F.Field{}, t4_3, x3_1)
  add.stage_14(Array.clone(U32, keep_12), keep_11, keep_13, keep_14, keep_7, keep_9, t2_1, t3_3, t4_4)

def add.stage_12(pair: Array<U32> & Array<U32>, keep_10: Array<U32>, keep_11: Array<U32>, keep_12: Array<U32>, keep_6: Array<U32>, keep_7: Array<U32>, keep_8: Array<U32>, keep_9: Array<U32>, t2_1: Array<U32>, t3_3: Array<U32>) -> Point:
  (keep_13, use_13) = pair
  t4_3 = F.add(F.Field{}, keep_8, use_13)
  add.stage_13(Array.clone(U32, keep_6), keep_10, keep_11, keep_12, keep_13, keep_7, keep_9, t2_1, t3_3, t4_3)

def add.stage_11(pair: Array<U32> & Array<U32>, keep_10: Array<U32>, keep_11: Array<U32>, keep_5: Array<U32>, keep_6: Array<U32>, keep_7: Array<U32>, keep_8: Array<U32>, keep_9: Array<U32>, t2_1: Array<U32>, t3_2: Array<U32>, use_11: Array<U32>) -> Point:
  (keep_12, use_12) = pair
  t4_2 = F.add(F.Field{}, use_11, use_12)
  t3_3 = F.sub(F.Field{}, t3_2, t4_2)
  add.stage_12(Array.clone(U32, keep_5), keep_10, keep_11, keep_12, keep_6, keep_7, keep_8, keep_9, t2_1, t3_3)

def add.stage_10(pair: Array<U32> & Array<U32>, keep_10: Array<U32>, keep_5: Array<U32>, keep_6: Array<U32>, keep_7: Array<U32>, keep_8: Array<U32>, keep_9: Array<U32>, t1_1: Array<U32>, t2_1: Array<U32>, t3_2: Array<U32>) -> Point:
  (keep_11, use_11) = pair
  add.stage_11(Array.clone(U32, t1_1), keep_10, keep_11, keep_5, keep_6, keep_7, keep_8, keep_9, t2_1, t3_2, use_11)

def add.stage_9(pair: Array<U32> & Array<U32>, keep_5: Array<U32>, keep_6: Array<U32>, keep_7: Array<U32>, keep_8: Array<U32>, keep_9: Array<U32>, t0_1: Array<U32>, t1_1: Array<U32>, t2_1: Array<U32>, t3_1: Array<U32>, use_9: Array<U32>) -> Point:
  (keep_10, use_10) = pair
  t4_1 = F.add(F.Field{}, use_9, use_10)
  t3_2 = F.mont(F.Field{}, t3_1, t4_1)
  add.stage_10(Array.clone(U32, t0_1), keep_10, keep_5, keep_6, keep_7, keep_8, keep_9, t1_1, t2_1, t3_2)

def add.stage_8(pair: Array<U32> & Array<U32>, keep_4: Array<U32>, keep_5: Array<U32>, keep_6: Array<U32>, keep_7: Array<U32>, keep_8: Array<U32>, t0_1: Array<U32>, t1_1: Array<U32>, t2_1: Array<U32>, t3_1: Array<U32>) -> Point:
  (keep_9, use_9) = pair
  add.stage_9(Array.clone(U32, keep_4), keep_5, keep_6, keep_7, keep_8, keep_9, t0_1, t1_1, t2_1, t3_1, use_9)

def add.stage_7(pair: Array<U32> & Array<U32>, keep_2: Array<U32>, keep_4: Array<U32>, keep_5: Array<U32>, keep_6: Array<U32>, keep_7: Array<U32>, t0_1: Array<U32>, t1_1: Array<U32>, t2_1: Array<U32>, use_7: Array<U32>) -> Point:
  (keep_8, use_8) = pair
  t3_1 = F.add(F.Field{}, use_7, use_8)
  add.stage_8(Array.clone(U32, keep_2), keep_4, keep_5, keep_6, keep_7, keep_8, t0_1, t1_1, t2_1, t3_1)

def add.stage_6(pair: Array<U32> & Array<U32>, keep_2: Array<U32>, keep_3: Array<U32>, keep_4: Array<U32>, keep_5: Array<U32>, keep_6: Array<U32>, t0_1: Array<U32>, t1_1: Array<U32>, t2_1: Array<U32>) -> Point:
  (keep_7, use_7) = pair
  add.stage_7(Array.clone(U32, keep_3), keep_2, keep_4, keep_5, keep_6, keep_7, t0_1, t1_1, t2_1, use_7)

def add.stage_5(pair: Array<U32> & Array<U32>, keep_1: Array<U32>, keep_2: Array<U32>, keep_3: Array<U32>, keep_4: Array<U32>, keep_5: Array<U32>, t0_1: Array<U32>, t1_1: Array<U32>, use_5: Array<U32>) -> Point:
  (keep_6, use_6) = pair
  t2_1 = F.mont(F.Field{}, use_5, use_6)
  add.stage_6(Array.clone(U32, keep_1), keep_2, keep_3, keep_4, keep_5, keep_6, t0_1, t1_1, t2_1)

def add.stage_4(pair: Array<U32> & Array<U32>, keep_1: Array<U32>, keep_2: Array<U32>, keep_3: Array<U32>, keep_4: Array<U32>, t0_1: Array<U32>, t1_1: Array<U32>, z2: Array<U32>) -> Point:
  (keep_5, use_5) = pair
  add.stage_5(Array.clone(U32, z2), keep_1, keep_2, keep_3, keep_4, keep_5, t0_1, t1_1, use_5)

def add.stage_3(pair: Array<U32> & Array<U32>, keep_1: Array<U32>, keep_2: Array<U32>, keep_3: Array<U32>, t0_1: Array<U32>, use_3: Array<U32>, z1: Array<U32>, z2: Array<U32>) -> Point:
  (keep_4, use_4) = pair
  t1_1 = F.mont(F.Field{}, use_3, use_4)
  add.stage_4(Array.clone(U32, z1), keep_1, keep_2, keep_3, keep_4, t0_1, t1_1, z2)

def add.stage_2(pair: Array<U32> & Array<U32>, keep_1: Array<U32>, keep_2: Array<U32>, t0_1: Array<U32>, y2: Array<U32>, z1: Array<U32>, z2: Array<U32>) -> Point:
  (keep_3, use_3) = pair
  add.stage_3(Array.clone(U32, y2), keep_1, keep_2, keep_3, t0_1, use_3, z1, z2)

def add.stage_1(pair: Array<U32> & Array<U32>, keep_1: Array<U32>, use_1: Array<U32>, y1: Array<U32>, y2: Array<U32>, z1: Array<U32>, z2: Array<U32>) -> Point:
  (keep_2, use_2) = pair
  t0_1 = F.mont(F.Field{}, use_1, use_2)
  add.stage_2(Array.clone(U32, y1), keep_1, keep_2, t0_1, y2, z1, z2)

def add.stage_0(pair: Array<U32> & Array<U32>, x2: Array<U32>, y1: Array<U32>, y2: Array<U32>, z1: Array<U32>, z2: Array<U32>) -> Point:
  (keep_1, use_1) = pair
  add.stage_1(Array.clone(U32, x2), keep_1, use_1, y1, y2, z1, z2)

def add(first: Point, second: Point) -> Point:
  match first second:
    case Point{x1, y1, z1} Point{x2, y2, z2}:
      add.stage_0(Array.clone(U32, x1), x2, y1, y2, z1, z2)

def select(+mask: U32, first: Point, second: Point) -> Point:
  match first second:
    case Point{x1, y1, z1} Point{x2, y2, z2}:
      Point{F.select_bytes(32n, 0, mask, F.Select{x1, x2, F.zero()}),
            F.select_bytes(32n, 0, mask, F.Select{y1, y2, F.zero()}),
            F.select_bytes(32n, 0, mask, F.Select{z1, z2, F.zero()})}

def double.cloned(pair: Point & Point) -> Point:
  (first, second) = pair
  add(first, second)

def double(point: Point) -> Point:
  double.cloned(clone(point))

def scalar_bit(position: Nat, offset: Nat, bytes: List<&2, U32>) -> U32:
  match position bytes:
    case 0n Con{byte, _}:
      U32.and(U32.shrn(byte, offset), 1)
    case 1n+p Con{_, tail}:
      scalar_bit(p, offset, tail)
    case _ _:
      0

type Multiplication is Type:
  Multiplication{base: Point, acc: Point}

def multiply.selected(+bit: U32, base: Point, pair: Point & Point, factor: Point) -> Multiplication:
  (doubled, for_add) = pair
  Multiplication{base, select(U32.mul(255, bit), doubled, add(for_add, factor))}

def multiply.base(bit: U32, acc: Point, pair: Point & Point) -> Multiplication:
  (base, factor) = pair
  multiply.selected(bit, base, clone(double(acc)), factor)

# Raw internal scalar profile: exactly 32 valid little-endian bytes.
# Every 256-bit input uses 256 doublings, 256 additions, 256 masked selections.
def multiply.go(left: Nat, +scalar: List<&2, U32>, state: Multiplication) -> Point:
  match left state:
    case 0n Multiplication{_, acc}:
      acc
    case 1n+ +p Multiplication{base, acc}:
      multiply.go(p, scalar, multiply.base(scalar_bit(Nat.div(p, 8n), Nat.mod(p, 8n), scalar), acc, clone(base)))

def multiply(scalar: List<&2, U32>, point: Point) -> Point:
  multiply.go(256n, scalar, Multiplication{point, infinity()})

# SEC1 uncompressed encoding only: 04 || x_BE32 || y_BE32. Infinity has
# no accepted wire encoding. Normalization explicitly rejects zero Z.
def encode.coordinates(x: Array<U32>, y: Array<U32>, pair: Array<U32> & Array<U32>) -> Maybe<&1, List<&2, U32>>:
  (for_x, for_y) = pair
  x_bytes = List.reverse(&2, U32, F.encode(from_mont(F.mont(F.Field{}, x, for_x))))
  y_bytes = List.reverse(&2, U32, F.encode(from_mont(F.mont(F.Field{}, y, for_y))))
  Some{Con{4, B.append(x_bytes, y_bytes)}}

def encode.inverted(x: Array<U32>, y: Array<U32>, inverse: Maybe<&1, Array<U32>>) -> Maybe<&1, List<&2, U32>>:
  match inverse:
    case None{}:
      None{}
    case Some{inverse}:
      encode.coordinates(x, y, Array.clone(U32, to_mont(inverse)))

def encode(point: Point) -> Maybe<&1, List<&2, U32>>:
  match point:
    case Point{x, y, z}:
      encode.inverted(x, y, F.invert(F.Field{}, from_mont(z)))

def difference.zero(pair: Array<U32> & U32) -> Bool:
  (_, value) = pair
  U32.is_eq(value, 0)

def equal(first: Array<U32>, second: Array<U32>) -> Bool:
  difference.zero(F.zero.go(32n, 0, F.ZeroScan{F.sub(F.Field{}, first, second), 0}))

def curve.checked(valid: Bool, x: Array<U32>, y: Array<U32>) -> Maybe<&1, Point>:
  match valid:
    case False{}:
      None{}
    case True{}:
      Some{Point{x, y, mont_one()}}

def curve.products(x: Array<U32>, y: Array<U32>, for_product: Array<U32>, triple_first: Array<U32>,
                   square_pair: Array<U32> & Array<U32>, triple_pair: Array<U32> & Array<U32>,
                   y_pair: Array<U32> & Array<U32>) -> Maybe<&1, Point>:
  (square_first, square_second) = square_pair
  (triple_second, triple_third) = triple_pair
  (y_first, y_second) = y_pair
  cube = F.mont(F.Field{}, F.mont(F.Field{}, square_first, square_second), for_product)
  triple = F.add(F.Field{}, triple_first, F.add(F.Field{}, triple_second, triple_third))
  rhs = F.add(F.Field{}, F.sub(F.Field{}, cube, triple), curve_b())
  lhs = F.mont(F.Field{}, y_first, y_second)
  curve.checked(equal(lhs, rhs), x, y)

def curve.square(x: Array<U32>, y: Array<U32>, square_pair: Array<U32> & Array<U32>,
                 triple_pair: Array<U32> & Array<U32>, y_pair: Array<U32> & Array<U32>) -> Maybe<&1, Point>:
  (for_square, for_product) = square_pair
  (triple_first, triple_tail) = triple_pair
  curve.products(x, y, for_product, triple_first, Array.clone(U32, for_square), Array.clone(U32, triple_tail), y_pair)

def curve.equation(x: Array<U32>, y: Array<U32>, x_pair: Array<U32> & Array<U32>,
                   y_pair: Array<U32> & Array<U32>) -> Maybe<&1, Point>:
  (for_cube, for_triple) = x_pair
  curve.square(x, y, Array.clone(U32, for_cube), Array.clone(U32, for_triple), y_pair)

def curve.cloned(x_pair: Array<U32> & Array<U32>, y_pair: Array<U32> & Array<U32>) -> Maybe<&1, Point>:
  (x, for_equation_x) = x_pair
  (y, for_equation_y) = y_pair
  curve.equation(x, y, Array.clone(U32, for_equation_x), Array.clone(U32, for_equation_y))

def decode.canonical(x: Maybe<&1, Array<U32>>, y: Maybe<&1, Array<U32>>) -> Maybe<&1, Point>:
  match x y:
    case Some{x} Some{y}:
      curve.cloned(Array.clone(U32, to_mont(x)), Array.clone(U32, to_mont(y)))
    case _ _:
      None{}

# The public 32-byte prefix is collected in reverse to form little-endian x.
def split_x(left: Nat, bytes: List<&2, U32>, reversed: List<&2, U32>) -> List<&2, U32> & List<&2, U32>:
  match left bytes:
    case 0n bytes:
      (reversed, bytes)
    case 1n+p Con{byte, tail}:
      split_x(p, tail, Con{byte, reversed})
    case _ _:
      ([], [])

def decode.split(pair: List<&2, U32> & List<&2, U32>) -> Maybe<&1, Point>:
  (x, y) = pair
  decode.canonical(F.decode_canonical(F.Field{}, x),
    F.decode_canonical(F.Field{}, List.reverse(&2, U32, y)))

def decode.profile(valid: Bool, bytes: List<&2, U32>) -> Maybe<&1, Point>:
  match valid bytes:
    case True{} Con{4, coordinates}:
      decode.split(split_x(32n, coordinates, []))
    case _ _:
      None{}

# P-256 cofactor is one: canonical non-infinity on-curve points are in the
# prime-order subgroup. Invalid/alias/off-curve coordinates are rejected.
def decode(+bytes: List<&2, U32>) -> Maybe<&1, Point>:
  decode.profile(Bool.and(Nat.is_eq(B.length(bytes), 65n), B.valid(bytes)), bytes)

def private.nonzero(valid: Bool, value: Array<U32>) -> Maybe<&1, List<&2, U32>>:
  match valid:
    case False{}:
      None{}
    case True{}:
      Some{F.encode(value)}

def private.scanned(pair: Array<U32> & U32) -> Maybe<&1, List<&2, U32>>:
  (value, difference) = pair
  private.nonzero(U32.is_ne(difference, 0), value)

def private.canonical(value: Maybe<&1, Array<U32>>) -> Maybe<&1, List<&2, U32>>:
  match value:
    case None{}:
      None{}
    case Some{value}:
      private.scanned(F.zero.go(32n, 0, F.ZeroScan{value, 0}))

# Private scalars are exactly 32 big-endian bytes with 1 <= d < n.
def private_scalar(bytes: List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  private.canonical(F.decode_canonical(F.Scalar{}, List.reverse(&2, U32, bytes)))

def public_key.scalar(scalar: Maybe<&1, List<&2, U32>>) -> Maybe<&1, List<&2, U32>>:
  match scalar:
    case None{}:
      None{}
    case Some{scalar}:
      encode(multiply(scalar, generator()))

def public_key(private: List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  public_key.scalar(private_scalar(private))

# ECDH returns exactly the affine x coordinate, 32 big-endian bytes.
def shared.x(pair: List<&2, U32> & List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  (x, _) = pair
  Some{List.reverse(&2, U32, x)}

def shared.encoded(value: Maybe<&1, List<&2, U32>>) -> Maybe<&1, List<&2, U32>>:
  match value:
    case Some{Con{4, coordinates}}:
      shared.x(split_x(32n, coordinates, []))
    case _:
      None{}

def shared.validated(scalar: Maybe<&1, List<&2, U32>>, peer: Maybe<&1, Point>) -> Maybe<&1, List<&2, U32>>:
  match scalar peer:
    case Some{scalar} Some{point}:
      shared.encoded(encode(multiply(scalar, point)))
    case _ _:
      None{}

def shared(private: List<&2, U32>, peer: List<&2, U32>) -> Maybe<&1, List<&2, U32>>:
  shared.validated(private_scalar(private), decode(peer))
