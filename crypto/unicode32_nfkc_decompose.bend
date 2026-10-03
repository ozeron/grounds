import Base
import ./unicode32_nfkc_tables.bend as T
import ./unicode32_nfkc_data.bend as D
import ./unicode32_nfkc_buffer.bend as B
import ./unicode32_lookup.bend as L

# Fully expanded compatibility mappings; Hangul decomposes algorithmically.
def collect.next(buffer: B.Buffer, result: Array<U32> & U32, next: Array<U32> -> B.Buffer -> Array<U32> & B.Buffer) -> Array<U32> & B.Buffer:
  (array, point) = result
  next(array, B.put(point, buffer))

def collect(left: Nat, +offset: U32, array: Array<U32>, buffer: B.Buffer) -> Array<U32> & B.Buffer:
  match left:
    case 0n: (array, buffer)
    case 1n+p: collect.next(buffer, Array.get(U32, array, offset), a => b => collect(p, U32.inc(offset), a, b))

def collected(index: Array<U32>, classes: Array<U32>, composition: Array<U32>, result: Array<U32> & B.Buffer) -> T.Tables & B.Buffer:
  (values, buffer) = result
  (T.Tables{index, values, classes, composition}, buffer)

def identity(index: Array<U32>, values: Array<U32>, composition: Array<U32>, +code: U32, buffer: B.Buffer, result: Array<U32> & Maybe<U32>) -> T.Tables & B.Buffer:
  (classes, class) = result
  match class:
    case None{}: (T.Tables{index, values, classes, composition}, B.put(U32.shln(code, 8n), buffer))
    case Some{class}: (T.Tables{index, values, classes, composition}, B.put(U32.or(U32.shln(code, 8n), class), buffer))

def found(+code: U32, values: Array<U32>, classes: Array<U32>, composition: Array<U32>, buffer: B.Buffer, result: Array<U32> & Maybe<U32>) -> T.Tables & B.Buffer:
  (index, mapping) = result
  match mapping:
    case None{}: identity(index, values, composition, code, buffer, L.find(D.classes.rows(), code, classes))
    case Some{+descriptor}:
      collected(index, classes, composition, collect(U32.to_nat(U32.and(descriptor, 31)), U32.div(descriptor, 32), values, buffer))

def hangul.tail(+trailing: U32, buffer: B.Buffer) -> B.Buffer:
  match trailing:
    case 0: buffer
    case _: B.put(U32.shln(U32.add(4519, trailing), 8n), buffer)

def hangul(+code: U32, buffer: B.Buffer) -> B.Buffer:
  +s = U32.sub(code, 44032)
  leading = U32.add(4352, U32.div(s, 588))
  vowel = U32.add(4449, U32.mod(U32.div(s, 28), 21))
  hangul.tail(U32.mod(s, 28), B.put(U32.shln(vowel, 8n), B.put(U32.shln(leading, 8n), buffer)))

def scalar.checked(is_hangul: Bool, state: T.Tables, +code: U32, buffer: B.Buffer) -> T.Tables & B.Buffer:
  match is_hangul state:
    case True{} state: (state, hangul(code, buffer))
    case False{} T.Tables{index, values, classes, composition}:
      found(code, values, classes, composition, buffer, L.find(D.decomposition.rows(), code, index))

def scalar(state: T.Tables, +code: U32, buffer: B.Buffer) -> T.Tables & B.Buffer:
  scalar.checked(Bool.and(U32.is_ge(code, 44032), U32.is_le(code, 55203)), state, code, buffer)

def run.next(result: T.Tables & B.Buffer, next: T.Tables -> B.Buffer -> T.Tables & B.Buffer) -> T.Tables & B.Buffer:
  (state, buffer) = result
  next(state, buffer)

def run(codes: List<&2, U32>, state: T.Tables, buffer: B.Buffer) -> T.Tables & B.Buffer:
  match codes:
    case Nil{}: (state, buffer)
    case Con{code, rest}: run.next(scalar(state, code, buffer), s => b => run(rest, s, b))
