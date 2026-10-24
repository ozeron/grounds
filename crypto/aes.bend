import Base
import ./aes128.bend as A128
import ./aes256.bend as A256
import ./bytes.bend as B

# Prepared AES key. The key width is public metadata, independent of bytes.
type Prepared is Type:
  Prepared{keys: Array<U32>, wide: Bool}

def expand.width(wide: Bool, key: List<&2,U32>) -> Prepared:
  match wide:
    case True{}: Prepared{A256.expand.raw(key),True{}}
    case False{}: Prepared{A128.expand.raw(key),False{}}

def expand.raw(+key: List<&2,U32>) -> Prepared:
  expand.width(Nat.is_eq(B.length(key),32n),key)

def block.got(wide: Bool, pair: Array<U32> & List<&2,U32>) -> Prepared & List<&2,U32>:
  (keys,bytes) = pair
  (Prepared{keys,wide},bytes)

def block(owner: Prepared, input: List<&2,U32>) -> Prepared & List<&2,U32>:
  match owner:
    case Prepared{keys,True{}}: block.got(True{},A256.block(keys,input))
    case Prepared{keys,False{}}: block.got(False{},A128.block(keys,input))
