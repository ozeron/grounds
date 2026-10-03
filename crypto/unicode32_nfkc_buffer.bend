import Base

# Packed scalar/CCC values and stable segment/class ordering keys.
# Initial storage is small; doubling never narrows the valid Name input bound.
type Buffer is Type:
  Buffer{values: Array<U32>, length: U32, capacity: U32, exponent: Nat, segment: U32, last: U32, ordered: Bool}

def new() -> Buffer:
  Buffer{Array.new(U32, 1n, 0), 0, 2, 1n, 0, 0, True{}}

def write(+point: U32, buffer: Buffer) -> Buffer:
  match buffer:
    case Buffer{values, +length, capacity, exponent, +segment, +last, ordered}:
      +current = U32.add(segment, Bool.pick(U32, U32.is_eq(U32.and(point, 255), 0), 1, 0))
      +key = U32.or(U32.shln(current, 8n), U32.and(point, 255))
      Buffer{Array.set(U32, values, length, point),
        U32.inc(length), capacity, exponent, current, key, Bool.and(ordered, U32.is_le(last, key))}

def put.checked(full: Bool, point: U32, buffer: Buffer) -> Buffer:
  match full buffer:
    case False{} buffer: write(point, buffer)
    case True{} Buffer{values, length, +capacity, +exponent, segment, last, ordered}:
      write(point, Buffer{ANode{values, Array.new(U32, exponent, 0)},
        length, U32.mul(capacity, 2), Nat.add(exponent, 1n), segment, last, ordered})

def put(point: U32, buffer: Buffer) -> Buffer:
  match buffer:
    case Buffer{values, +length, +capacity, exponent, segment, last, ordered}:
      put.checked(U32.is_eq(length, capacity), point, Buffer{values, length, capacity, exponent, segment, last, ordered})
